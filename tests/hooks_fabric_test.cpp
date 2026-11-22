#include "blackbird/coding.hpp"
#include "blackbird/hooks.hpp"
#include "blackbird/hooks_view.hpp"
#include "blackbird/json.hpp"
#include "blackbird/terminal.hpp"
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace blackbird;

namespace {

void require(bool condition, const char *why) {
  if (!condition)
    throw std::runtime_error(why);
}

template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}

void append_utf8(std::string &out, char32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xc0U | (cp >> 6U));
    out += static_cast<char>(0x80U | (cp & 0x3fU));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xe0U | (cp >> 12U));
    out += static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU));
    out += static_cast<char>(0x80U | (cp & 0x3fU));
  } else {
    out += static_cast<char>(0xf0U | (cp >> 18U));
    out += static_cast<char>(0x80U | ((cp >> 12U) & 0x3fU));
    out += static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU));
    out += static_cast<char>(0x80U | (cp & 0x3fU));
  }
}

std::string render_text(const ChatGrid &grid) {
  std::string out;
  for (std::size_t row = 0; row < grid.height; ++row) {
    for (std::size_t col = 0; col < grid.width; ++col) {
      const auto &cell = grid.cells[row * grid.width + col];
      if (cell.width == 0)
        continue;
      append_utf8(out, cell.scalar);
      if (cell.length != 0)
        out.append(grid.tails, cell.tail, cell.length);
    }
    out += '\n';
  }
  return out;
}

class QuietProvider final : public CodingProvider {
public:
  Value respond(const Value &,
                const std::function<void(std::string_view)> &capture) override {
    auto out = Value::object({{"output", Value{Value::Array{}}}});
    capture(unwrap(dump_json(out)));
    return out;
  }
};

void test_hook_registry_validation_and_explain() {
  Value cfg = Value::object(
      {{"hooks", Value{Value::Array{
                     Value::object({{"name", Value{"late_obs"}},
                                    {"event", Value{"turn_start"}},
                                    {"kind", Value{"observer"}},
                                    {"order", Value{Number{20}}},
                                    {"source", Value{"return 'late'"}}}),
                     Value::object(
                         {{"name", Value{"early_guard"}},
                          {"event", Value{"before_tool"}},
                          {"kind", Value{"admission"}},
                          {"order", Value{Number{-5}}},
                          {"match", Value::object({{"tool", Value{"write_file"}}})},
                          {"source", Value{"return {allow=false, reason='blocked'}"}}}),
                     Value::object({{"name", Value{"off_hook"}},
                                    {"event", Value{"turn_start"}},
                                    {"kind", Value{"observer"}},
                                    {"enabled", Value{false}},
                                    {"order", Value{Number{1}}},
                                    {"source", Value{"return 'off'"}}})}}}});

  HookRegistry reg{cfg, "rev-1"};
  require(reg.definitions().size() == 3, "three hooks registered");
  require(reg.definitions()[0].name == "early_guard" &&
              reg.definitions()[1].name == "off_hook" &&
              reg.definitions()[2].name == "late_obs",
          "hooks sorted deterministically by order");

  const auto explain_tool = reg.explain(
      {.event = HookEvent::before_tool, .tool = "write_file", .prompt = {}});
  require(explain_tool.size() == 3, "explain covers every hook");
  require(explain_tool[0].name == "early_guard" && explain_tool[0].matched &&
              explain_tool[0].reason == "matched",
          "early_guard matches write_file");
  require(explain_tool[1].name == "off_hook" && !explain_tool[1].matched &&
              explain_tool[1].reason == "disabled",
          "disabled hook reports disabled");
  require(explain_tool[2].name == "late_obs" && !explain_tool[2].matched &&
              explain_tool[2].reason == "event mismatch",
          "wrong-event hook reports event mismatch");

  // Admission kind on turn_start must be rejected.
  bool rejected_kind = false;
  try {
    const Value bad = Value::object(
        {{"hooks",
          Value{Value::Array{Value::object({{"name", Value{"bad"}},
                                            {"event", Value{"turn_start"}},
                                            {"kind", Value{"admission"}},
                                            {"source", Value{"return true"}}})}}}});
    (void)HookRegistry{bad, "bad"};
  } catch (const Error &e) {
    rejected_kind = e.code == ErrorCode::invalid_range;
  }
  require(rejected_kind, "admission hook on non-before_tool event rejected");
}

void test_engine_hooks_lifecycle_and_execution() {
  char pattern[] = "/tmp/blackbird-hooks-XXXXXX";
  const auto *path = ::mkdtemp(pattern);
  require(path != nullptr, "mkdtemp failed");
  struct Cleanup {
    std::filesystem::path dir;
    ~Cleanup() {
      std::error_code ignored;
      std::filesystem::remove_all(dir, ignored);
    }
  } cleanup{path};

  const auto guarded_file = std::filesystem::path{path} / "should-not-exist.txt";
  const auto allowed_file = std::filesystem::path{path} / "allowed.txt";

  {
    auto root =
        unwrap(RetainedState::create(std::make_unique<NativeJournalDirectory>(
                                         unwrap(NativeJournalDirectory::open(path))),
                                     "audit",
                                     {make_id<EnvironmentId>(1),
                                      make_id<AuditStreamId>(2),
                                      3,
                                      {1024 * 1024, 4 * 1024 * 1024},
                                      std::nullopt},
                                     {64 * 1024 * 1024, 20000}));
    AuditLog log{*root};
    ContextStore context{log};
    QuietProvider provider;
    CodingEngine engine{log, context, provider, "test-model"};

    // Reject invalid Lua hook syntax without altering effective registry.
    engine.turn({"", R"(
      local bad = blackbird.call('program_config', {
        proposal = {
          modules = blackbird.array({}),
          model = '',
          effort = '',
          hooks = blackbird.array({
            { name = 'broken', event = 'turn_start', kind = 'observer', source = 'if then end' }
          })
        }
      })
      assert(not bad.staged, 'invalid Lua hook syntax must not stage')
    )"});
    require(engine.hooks()->definitions().empty(),
            "rejected syntax leaves hook registry empty");

    // Stage four hooks: turn_start context_transform, before_tool admission guard,
    // after_tool observer, and a deliberately failing observer (must not abort turn).
    const Value proposal = Value::object(
        {{"modules", Value{Value::Array{}}},
         {"model", Value{""}},
         {"effort", Value{""}},
         {"hooks",
          Value{Value::Array{
              Value::object(
                  {{"name", Value{"inject_note"}},
                   {"event", Value{"turn_start"}},
                   {"kind", Value{"context_transform"}},
                   {"order", Value{Number{1}}},
                   {"match", Value::object({{"prompt_prefix", Value{"Deploy"}}})},
                   {"description", Value{"Inject safety checklist on Deploy turns"}},
                   {"source", Value{R"(
                      return {
                        append = blackbird.array({
                          { role = 'developer', content = 'HOOK_NOTE:' .. event.prompt }
                        }),
                        note = 'injected checklist'
                      }
                    )"}}}),
              Value::object(
                  {{"name", Value{"block_write"}},
                   {"event", Value{"before_tool"}},
                   {"kind", Value{"admission"}},
                   {"order", Value{Number{2}}},
                   {"match", Value::object({{"tool", Value{"write_file"}}})},
                   {"description", Value{"Block writes to protected path"}},
                   {"source",
                    Value{"if event.arguments and event.arguments.path == '" +
                          guarded_file.string() +
                          "' then return {allow=false, reason='protected path'} end\n"
                          "return {allow=true, note='write permitted'}"}}}),
              Value::object({{"name", Value{"fail_gracefully"}},
                             {"event", Value{"after_tool"}},
                             {"kind", Value{"observer"}},
                             {"order", Value{Number{3}}},
                             {"source", Value{"error('observer boom')"}}}),
              Value::object(
                  {{"name", Value{"compact_watch"}},
                   {"event", Value{"context_compact"}},
                   {"kind", Value{"observer"}},
                   {"order", Value{Number{4}}},
                   {"source",
                    Value{"return 'saw compact ' .. tostring(event.op)"}}})}}}});

    // Stage mid-turn: active hooks must stay empty until turn boundary!
    engine.turn(
        {"", "local r = blackbird.call('program_config', blackbird.json.decode([==[" +
                 unwrap(dump_json(Value::object({{"proposal", proposal}}))) +
                 "]==]))\n"
                 "assert(r.staged)\n"
                 "assert(#blackbird.hooks().hooks == 0, 'not active mid-turn')\n"
                 "assert(blackbird.hooks().pending_revision ~= nil)\n"});
    require(engine.hooks()->definitions().size() == 4,
            "hooks activated cleanly at turn boundary");
    require(!engine.pending_hooks(), "pending hooks cleared after activation");

    // Turn 2: Deploy prompt triggers turn_start context_transform, blocked write_file
    // is refused BEFORE touching disk, allowed write_file succeeds, and failing
    // after_tool observer is isolated without aborting the turn.
    engine.turn({"Deploy release",
                 "local denied = blackbird.call('write_file', {path='" +
                     guarded_file.string() +
                     "', content='nope'})\n"
                     "assert(denied.error == 'hook_refused', 'expected hook_refused')\n"
                     "assert(denied.hook == 'block_write')\n"
                     "assert(denied.reason == 'protected path')\n"
                     "local ok = blackbird.call('write_file', {path='" +
                     allowed_file.string() +
                     "', content='hello'})\n"
                     "assert(not ok.error, 'allowed write succeeds')\n"
                     "return {denied = denied, ok = ok}"});

    require(!std::filesystem::exists(guarded_file),
            "admission refusal prevented guarded file creation");
    require(std::filesystem::exists(allowed_file),
            "allowed write_file executed normally");

    // Verify turn_start context_transform injected note block into ContextStore.
    bool saw_hook_note = false;
    for (const auto &block : context.blocks()) {
      if (block.kind == BlockKind::note && block.label == "hook:inject_note") {
        saw_hook_note = true;
        break;
      }
    }
    require(saw_hook_note, "turn_start context_transform appended note block");

    // Verify dispatch history captured matched_ok, matched_denied, and matched_failed.
    bool saw_ok = false, saw_denied = false, saw_failed = false;
    for (const auto &rec : engine.hook_history()) {
      if (rec.hook_name == "inject_note" && rec.outcome == HookOutcome::matched_ok)
        saw_ok = true;
      if (rec.hook_name == "block_write" && rec.outcome == HookOutcome::matched_denied)
        saw_denied = true;
      if (rec.hook_name == "fail_gracefully" &&
          rec.outcome == HookOutcome::matched_failed)
        saw_failed = true;
    }
    require(saw_ok && saw_denied && saw_failed,
            "dispatch history records matched_ok, matched_denied, and matched_failed");

    // Declarative explain via operator_call does not execute Lua or add history.
    const auto hist_before = engine.hook_history().size();
    const auto explained =
        engine.operator_call("hooks", Value::object({{"op", Value{"explain"}},
                                                     {"event", Value{"before_tool"}},
                                                     {"tool", Value{"write_file"}}}));
    require(engine.hook_history().size() == hist_before,
            "declarative explain does not execute hooks");
    require(field(explained, "matches").array().size() == 4,
            "explain returns all 4 hook evaluations");

    // Disable block_write via operator_call('hooks', {op='disable',
    // name='block_write'}).
    (void)engine.operator_call(
        "hooks",
        Value::object({{"op", Value{"disable"}}, {"name", Value{"block_write"}}}));
    bool block_disabled = false;
    for (const auto &h : engine.hooks()->definitions()) {
      if (h.name == "block_write")
        block_disabled = !h.enabled;
    }
    require(block_disabled, "disable toggled block_write cleanly at turn boundary");

    // Now guarded_file write succeeds because block_write is disabled!
    engine.turn({"", "local ok = blackbird.call('write_file', {path='" +
                         guarded_file.string() +
                         "', content='now allowed'})\n"
                         "assert(not ok.error)\n"});
    require(std::filesystem::exists(guarded_file),
            "disabling admission hook allows previously blocked write");

    // Trigger context_compact hook via immediate pin.
    const auto hist_pre_compact = engine.hook_history().size();
    engine.turn(
        {"", "blackbird.compact({op='drop', ids=blackbird.array({2}), apply='now'})"});
    bool saw_compact = false;
    for (std::size_t i = hist_pre_compact; i < engine.hook_history().size(); ++i) {
      if (engine.hook_history()[i].hook_name == "compact_watch" &&
          engine.hook_history()[i].outcome == HookOutcome::matched_ok)
        saw_compact = true;
    }
    require(saw_compact, "context_compact hook fired on immediate compaction");
  }

  // Reopen session from disk and verify hooks persisted cleanly in audit log.
  {
    auto root =
        unwrap(RetainedState::open(std::make_unique<NativeJournalDirectory>(
                                       unwrap(NativeJournalDirectory::open(path))),
                                   "audit",
                                   {make_id<EnvironmentId>(1),
                                    make_id<AuditStreamId>(2),
                                    3,
                                    {1024 * 1024, 4 * 1024 * 1024},
                                    std::nullopt},
                                   {64 * 1024 * 1024, 20000}));
    unwrap(root->confirm_recovery());
    recover_coding_session(*root);
    AuditLog log{*root};
    ContextStore context{log};
    QuietProvider provider;
    CodingEngine reopened{log, context, provider, "test-model"};
    require(reopened.hooks()->definitions().size() == 4,
            "reopened engine restored persisted hooks");
    bool block_still_disabled = false;
    for (const auto &h : reopened.hooks()->definitions()) {
      if (h.name == "block_write")
        block_still_disabled = !h.enabled;
    }
    require(block_still_disabled, "disabled hook state persisted across reopen");
  }
}

void test_hooks_view_tui() {
  HooksViewSnapshot snap;
  snap.revision = "rev-abc123456789";
  snap.pending_revision = "rev-def987654321";
  snap.hooks.push_back({.name = "guard_writes",
                        .event = HookEvent::before_tool,
                        .kind = HookKind::admission,
                        .enabled = true,
                        .order = -10,
                        .match = {.tool = "write_file", .prompt_prefix = {}},
                        .description = "Guard sensitive files",
                        .source = "return {allow=true}"});
  snap.hooks.push_back({.name = "note_turns",
                        .event = HookEvent::turn_start,
                        .kind = HookKind::observer,
                        .enabled = false,
                        .order = 5,
                        .match = {},
                        .description = "Observe turn starts",
                        .source = "return 'started'"});
  snap.history.push_back({.sequence = 1,
                          .hook_name = "guard_writes",
                          .revision = "rev-abc123456789",
                          .event = HookEvent::before_tool,
                          .kind = HookKind::admission,
                          .outcome = HookOutcome::matched_denied,
                          .detail = "protected path",
                          .duration_ms = 2});

  HooksView view;
  view.update(std::move(snap));
  view.first_page();
  require(view.open() && view.focused(), "hooks view opens focused");
  require(view.refresh(), "hooks view definitions refresh succeeds");

  ChatGrid grid;
  grid.reset(100, 24);
  const auto layout = unwrap(view.render(grid, {0, 2, 100, 20}));
  require(layout.split, "wide hooks view renders split collection + detail");
  const auto screen1 = render_text(grid);
  require(screen1.find("guard_writes") != std::string::npos &&
              screen1.find("return {allow=true}") != std::string::npos,
          "definitions mode renders hook list and Lua source");

  const auto toggle_cmd = view.action_command("toggle_enabled");
  require(toggle_cmd.command == "/hooks disable guard_writes",
          "F6 on enabled hook emits audited /hooks disable command");

  unwrap(view.act(tui::InspectorAction::next));
  require(view.refresh(), "refresh after selecting second hook");
  const auto enable_cmd = view.action_command("toggle_enabled");
  require(enable_cmd.command == "/hooks enable note_turns",
          "F6 on disabled hook emits audited /hooks enable command");

  // Toggle F9 into Dispatch History mode.
  view.toggle_history();
  require(view.showing_history(), "F9 switches to history mode");
  require(view.refresh(), "history mode refresh succeeds");
  grid.reset(100, 24);
  (void)unwrap(view.render(grid, {0, 2, 100, 20}));
  const auto screen2 = render_text(grid);
  require(screen2.find("DISPATCH #1") != std::string::npos &&
              screen2.find("protected path") != std::string::npos,
          "history mode displays dispatch record and detail");

  const auto cap = view.caption();
  require(cap.find("HOOKS & FABRIC") != std::string::npos &&
              cap.find("history") != std::string::npos &&
              cap.find("1/2 enabled") != std::string::npos &&
              cap.find("1 dispatches") != std::string::npos &&
              cap.find("pending rev") != std::string::npos,
          "caption reports mode, enabled ratio, dispatch count, and pending rev");

  // View picker routes view.hooks-fabric while preserving draft.
  Composer composer;
  composer.draft("draft intact");
  composer.views(tui::ViewRoute::conversation);
  for (const char ch : std::string_view{"view.hooks-fabric"})
    (void)composer.feed(ch);
  const auto chosen = composer.feed('\r');
  require(chosen.action == InputAction::select_view &&
              chosen.view == tui::ViewRoute::hooks_fabric &&
              composer.text() == "draft intact",
          "view picker selects hooks_fabric while preserving draft");
}

} // namespace

int main() {
  try {
    test_hook_registry_validation_and_explain();
    test_engine_hooks_lifecycle_and_execution();
    test_hooks_view_tui();
    return 0;
  } catch (const Error &e) {
    std::cerr << "hooks_fabric_test blackbird::Error: " << error_name(e.code) << " ("
              << e.detail << ")\n";
    return 1;
  } catch (const std::exception &e) {
    std::cerr << "hooks_fabric_test failed: " << e.what() << "\n";
    return 1;
  }
}
