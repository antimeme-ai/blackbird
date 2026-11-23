#include "blackbird/coding.hpp"
#include "blackbird/json.hpp"
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <set>
#include <unistd.h>
using namespace blackbird;
namespace {
void require(bool b) {
  if (!b)
    throw std::runtime_error("Lua tool oracle failed");
}
template <class T> T id(unsigned char n) {
  IdentityBytes b{};
  b[0] = std::byte{n};
  return unwrap(T::from_bytes(b));
}
std::string lua_json_string(const std::filesystem::path &p) {
  return unwrap(dump_json(Value{p.string()}));
}
void test_lua_command_post_bridge(const std::filesystem::path &sandbox) {
  const std::filesystem::path audit_dir = sandbox / "cp-audit";
  const std::filesystem::path auth_dir = sandbox / "cp-empty-auth";
  const std::filesystem::path board_dir = sandbox / "cp-platoon";
  const std::filesystem::path absent_bridge = sandbox / "cp-absent-bridge";
  const std::filesystem::path absent_peers = sandbox / "cp-absent-peers";
  const std::filesystem::path issues_dir = sandbox / "cp-issues";
  const std::filesystem::path absent_memory = sandbox / "cp-absent-memory";
  const std::filesystem::path memory_dir = sandbox / "cp-memory";
  const std::filesystem::path absent_swarm = sandbox / "cp-absent-swarm";
  const std::filesystem::path swarm_dir = sandbox / "cp-local-swarm";
  const std::filesystem::path repo_root = sandbox / "cp-repo";
  const std::filesystem::path blocked_file = sandbox / "cp-blocked-write";
  std::filesystem::create_directories(audit_dir);
  std::filesystem::permissions(audit_dir, std::filesystem::perms::owner_all);
  std::filesystem::create_directories(auth_dir);
  std::filesystem::create_directories(repo_root / "src");
  write_file(repo_root / "src" / "note.cpp", "int note() { return 7; }\n");

  (void)setenv("BLACKBIRD_AUTH_HOME", auth_dir.c_str(), 1);
  (void)unsetenv("TYPESAFE_API_KEY");
  (void)unsetenv("jev");
  (void)unsetenv("BLACKBIRD_JEV_ENV_FILE");
  (void)unsetenv("BLACKBIRD_CLEF_URL");

  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(audit_dir.string()))),
                            "audit",
                            {id<EnvironmentId>(11),
                             id<AuditStreamId>(12),
                             7,
                             {1024 * 1024, 4 * 1024 * 1024},
                             std::nullopt},
                            {64 * 1024 * 1024, 20000}));
  AuditLog log{*root};
  ContextStore context{log};
  class IdleProvider final : public CodingProvider {
  public:
    Value respond(const Value &,
                  const std::function<void(std::string_view)> &) override {
      throw std::runtime_error("unexpected provider call in command_post bridge test");
    }
  } provider;
  DecisionModelConfig offline_decisions;
  offline_decisions.credential_file = sandbox / "no-decision-creds";
  CodingEngine engine{log, context, provider, "test", offline_decisions};

  // 1. platoon_board post + read with untrusted framing & ESC/C1 escaping.
  engine.turn({"", "local board = " + lua_json_string(board_dir) +
                       R"lua(
        local posted = blackbird.command_post("platoon_board", {
          action = "post",
          board_dir = board,
          from = "lua-lead",
          text = "hello \x1b[31mRED\x1b[0m \xc2\x9b2J"
        })
        assert(posted.posted == true)
        assert(posted.message.untrusted_peer_data == true)
        assert(posted.message.text == nil)

        local read = blackbird.command_post("platoon_board", {
          action = "read",
          board_dir = board,
          since_seq = 0,
          limit = 10
        })
        assert(read.board_present == true)
        assert(read.count == 1)
        assert(read.untrusted_peer_data == true)
        local msg = read.messages[1]
        assert(msg.untrusted_peer_data == true)
        assert(msg.text == nil)
        assert(msg.quoted_text:find("\\x1b", 1, true) ~= nil)
        assert(msg.quoted_text:find("\\xc2\\x9b", 1, true) ~= nil)
        assert(msg.quoted_text:find("\x1b", 1, true) == nil)
        assert(msg.quoted_text:find("\xc2\x9b", 1, true) == nil)
        assert(msg.quoted_frame:find("<<<BEGIN_UNTRUSTED_PEER_DATA>>>\n", 1, true) == 1)
        assert(msg.quoted_frame:find("\x1b", 1, true) == nil)

        local alias_read = blackbird.platoon_board({action = "read", board_dir = board})
        assert(alias_read.count == 1 and alias_read.untrusted_peer_data == true)
      )lua"});

  // 2. bridge_guard check on absent bridge dir (zero directory creation).
  engine.turn({"", "local bdir = " + lua_json_string(absent_bridge) +
                       "\nlocal pdir = " + lua_json_string(absent_peers) +
                       R"lua(
        local check = blackbird.command_post("bridge_guard", {
          action = "check",
          bridge_dir = bdir,
          peers_dir = pdir,
          scope = "src/a.cpp"
        })
        assert(check.bridge_present == false)
        assert(check.allowed == true)
        assert(check.blocking_count == 0)
        assert(check.scope == "src/a.cpp")

        local events = blackbird.bridge_guard({action = "events", bridge_dir = bdir})
        assert(events.bridge_present == false and events.count == 0)
      )lua"});
  require(!std::filesystem::exists(absent_bridge));
  require(!std::filesystem::exists(absent_peers));

  // 3. project_issues create + ready + alias list.
  engine.turn({"", "local idir = " + lua_json_string(issues_dir) +
                       R"lua(
        local created = blackbird.command_post("project_issues", {
          action = "create",
          issues_dir = idir,
          title = "Wire Lua command post",
          description = "Expose blackbird.command_post",
          priority = 1
        })
        assert(created.created == true)
        assert(type(created.issue.id) == "string" and #created.issue.id > 0)

        local ready = blackbird.command_post("project_issues", {
          action = "ready",
          issues_dir = idir
        })
        assert(ready.issues_present == true)
        assert(ready.count == 1)
        assert(ready.issues[1].id == created.issue.id)
        assert(ready.issues[1].title == "Wire Lua command post")

        local listed = blackbird.project_issues({action = "list", issues_dir = idir})
        assert(listed.count == 1)
      )lua"});

  // 4. project_memory absent read (zero dir creation) + record/recall freshness.
  engine.turn({"", "local absent_mem = " + lua_json_string(absent_memory) +
                       "\nlocal mdir = " + lua_json_string(memory_dir) +
                       "\nlocal root = " + lua_json_string(repo_root) +
                       R"lua(
        local empty = blackbird.project_memory({action = "recent", memory_dir = absent_mem})
        assert(empty.memory_present == false and empty.count == 0)

        local rec = blackbird.command_post("project_memory", {
          action = "record",
          memory_dir = mdir,
          kind = "invariant",
          title = "Note return contract",
          body = "note() returns 7",
          tags = {"lua"},
          sources = {"src/note.cpp"},
          verify_root = root
        })
        assert(rec.freshness_badge == "[fresh]")

        local hit = blackbird.command_post("project_memory", {
          action = "recall",
          memory_dir = mdir,
          query = "note contract",
          verify_root = root
        })
        assert(hit.memory_present == true and hit.count == 1)
        assert(hit.hits[1].freshness_badge == "[fresh]")
      )lua"});
  require(!std::filesystem::exists(absent_memory));

  // 5. companion_timing silence-by-default & strict schema enforcement.
  engine.turn({"", R"lua(
        local timing = blackbird.command_post("companion_timing", {
          context_summary = "idle",
          candidate_message = "fyi",
          room_state = "quiet",
          unread_peer_count = 0,
          conflict_count = 0
        })
        assert(timing.decision == "stay_quiet")
        assert(timing.basis == "deterministic_heuristic")

        local alias_timing = blackbird.companion_timing({
          context_summary = "idle",
          candidate_message = "fyi",
          room_state = "quiet",
          unread_peer_count = 0,
          conflict_count = 0
        })
        assert(alias_timing.decision == "stay_quiet")

        local missing = blackbird.command_post("companion_timing", {
          context_summary = "idle",
          candidate_message = "fyi"
        })
        assert(missing.error == "invalid_range")

        local extra = blackbird.command_post("companion_timing", {
          context_summary = "idle",
          candidate_message = "fyi",
          room_state = "quiet",
          unread_peer_count = 0,
          conflict_count = 0,
          api_key = "forbidden"
        })
        assert(extra.error == "invalid_range")
      )lua"});

  // 5b. local_swarm via blackbird.local_swarm(...) and blackbird.command_post(...).
  engine.turn({"", "local absent_s = " + lua_json_string(absent_swarm) +
                       "\nlocal sdir = " + lua_json_string(swarm_dir) +
                       R"lua(
        local empty = blackbird.local_swarm({action = "status", board_dir = absent_s})
        assert(empty.swarm_present == false and empty.count == 0)

        local added = blackbird.local_swarm({
          action = "add",
          board_dir = sdir,
          name = "lua-worker",
          role = "builder",
          owned_files = {"src/lua_slice.cpp"},
          brief = "Build lua slice"
        })
        assert(added.added == true and added.worker.name == "lua-worker")

        local conflict = blackbird.local_swarm({
          action = "add",
          board_dir = sdir,
          name = "lua-clash",
          owned_files = {"src/lua_slice.cpp"},
          brief = "Should conflict"
        })
        assert(conflict.error == "conflict")

        local dentist = blackbird.local_swarm({
          action = "dentist",
          board_dir = sdir,
          name = "lua-dentist",
          repo_checks = {"ctest"}
        })
        assert(dentist.added == true and dentist.worker.read_only == true)

        local waited = blackbird.command_post("local_swarm", {
          action = "wait",
          board_dir = sdir,
          agent = "lua-worker",
          since_seq = 0,
          mentions_only = true,
          timeout_ms = 50
        })
        assert(waited.woken == true and waited.count >= 1)
        assert(waited.messages[1].untrusted_peer_data == true)
        assert(waited.messages[1].text == nil)

        local killed = blackbird.local_swarm({
          action = "kill",
          board_dir = sdir,
          name = "lua-worker"
        })
        assert(killed.killed == true and killed.worker.state == "killed")
      )lua"});
  require(!std::filesystem::exists(absent_swarm));

  // 6. Unknown tool rejection, malformed arguments, alias coercion/arity, and
  // effect_policy enforcement.
  engine.turn({"", "local blocked = " + lua_json_string(blocked_file) +
                       R"lua(
        local ok_exec, err_exec = pcall(blackbird.command_post, "exec", {})
        assert(not ok_exec and err_exec == "invalid_range")

        local ok_write, err_write = pcall(blackbird.command_post, "write_file", {
          path = blocked,
          content = "should never exist"
        })
        assert(not ok_write and err_write == "invalid_range")

        local ok_unknown, err_unknown = pcall(blackbird.command_post, "not_a_tool", {})
        assert(not ok_unknown and err_unknown == "invalid_range")

        local ok_num, err_num = pcall(blackbird.command_post, 42, {})
        assert(not ok_num and err_num == "invalid_range")

        local ok_args, err_args = pcall(blackbird.command_post, "platoon_board", "bad")
        assert(not ok_args and err_args == "invalid_range")

        local ok_arity, err_arity = pcall(blackbird.command_post, "platoon_board",
                                          {action = "read"}, "extra")
        assert(not ok_arity and err_arity == "invalid_range")

        local ok_alias_false, err_alias_false = pcall(blackbird.platoon_board, false)
        assert(not ok_alias_false and err_alias_false == "invalid_range")

        local ok_alias_extra, err_alias_extra =
          pcall(blackbird.platoon_board, {}, "extra")
        assert(not ok_alias_extra and err_alias_extra == "invalid_range")
      )lua"});
  require(!std::filesystem::exists(blocked_file));

  // 7. Verify all 5 command-post calls are recorded through the AuditLog boundary.
  std::set<std::string> audited_ops;
  std::uint64_t cursor = 0;
  for (;;) {
    const Value page = log.inspect(Value::object(
        {{"cursor", Value{Number{cursor}}}, {"count", Value{Number{64}}}}));
    for (const auto &rec : field(page, "records").array()) {
      if (const auto *op = rec.find("operation");
          op && std::holds_alternative<std::string>(op->value())) {
        audited_ops.insert(op->string());
      }
    }
    const auto next = std::stoull(field(page, "next").number().text());
    const auto end = std::stoull(field(page, "end").number().text());
    if (next >= end || next == cursor)
      break;
    cursor = next;
  }
  require(
      audited_ops.contains("platoon_board") && audited_ops.contains("bridge_guard") &&
      audited_ops.contains("project_issues") &&
      audited_ops.contains("project_memory") &&
      audited_ops.contains("companion_timing") && audited_ops.contains("local_swarm"));

  engine.effect_policy = [](std::string_view tool_name, const Value &) {
    if (tool_name == "platoon_board")
      throw Error{ErrorCode::conflict};
  };
  engine.turn({"", "local ok, err = pcall(blackbird.command_post, 'platoon_board', "
                   "{action = 'read', board_dir = " +
                       lua_json_string(board_dir) +
                       "}); assert(not ok and err == 'conflict')"});
  engine.effect_policy = {};

  (void)unsetenv("BLACKBIRD_AUTH_HOME");
}
} // namespace
class Observer final : public CodingProvider {
public:
  bool expected = false;
  std::string delivery_path;
  Value respond(const Value &request,
                const std::function<void(std::string_view)> &capture) override {
    bool found = false;
    for (const auto &t : field(request, "tools").array())
      if (string_field(t, "name") == "deliver_note")
        found = true;
    require(found == expected);
    Value::Array output;
    if (!delivery_path.empty()) {
      output.push_back(
          Value::object({{"type", Value{"function_call"}},
                         {"call_id", Value{"live-lua-delivery"}},
                         {"name", Value{"deliver_note"}},
                         {"arguments", Value{unwrap(dump_json(Value::object(
                                           {{"path", Value{delivery_path}}})))}}}));
      delivery_path.clear();
    }
    auto r = Value::object({{"output", Value{std::move(output)}}});

    capture(unwrap(dump_json(r)));
    return r;
  }
};
int main() {
  char name[] = "/tmp/arco-lua-tools-XXXXXX";
  if (!mkdtemp(name))
    return 1;
  const std::filesystem::path path{name};
  try {
    {
      auto root = unwrap(
          RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                    NativeJournalDirectory::open(path.string()))),
                                "audit",
                                {id<EnvironmentId>(1),
                                 id<AuditStreamId>(2),
                                 7,
                                 {1024 * 1024, 4 * 1024 * 1024},
                                 std::nullopt},
                                {64 * 1024 * 1024, 20000}));
      AuditLog log{*root};
      ContextStore context{log};
      Observer provider;
      const std::string definition =
          R"lua(local d={name='deliver_note',description='Write the operating note',parameters={type='object',properties={path={type='string'}},required=arco.array({'path'}),additionalProperties=false},source="return arco.call('write_file',{path=args.path,content='Use retained outputs; never replay unknown effects.\\n'})"}
)lua";
      {
        CodingEngine engine{log, context, provider, "test"};
        engine.turn({"", definition + R"lua(
        assert(arco.define_tool(d).staged)
        assert(#arco.call('tool_registry',{}).effective==0)
        assert(#arco.call('tool_registry',{}).pending==1)
        arco.request()
      )lua"});
        provider.expected = true;
        provider.delivery_path = (path / "requested-note").string();
        engine.turn({"", read_file("programs/turn.lua")});
        require(read_file(path / "requested-note") ==
                "Use retained outputs; never replay unknown effects.\n");

        engine.turn({"", "arco.request(); local r=arco.call('deliver_note',{path=" +
                             unwrap(dump_json(Value{(path / "note").string()})) +
                             "}); assert(r.written)"});
        require(read_file(path / "note") ==
                "Use retained outputs; never replay unknown effects.\n");
        engine.turn({"", definition + R"lua(
        for _,name in ipairs({'exec','lua','tool_define','provider'}) do
          d.name=name; assert(not arco.define_tool(d).staged)
        end
        d.name='deliver_note'; d.source='not lua syntax !!!'; assert(not arco.define_tool(d).staged)
        d.source='return 99'; d.parameters.properties.path.type='mystery'; assert(not arco.define_tool(d).staged)
        assert(arco.call('deliver_note',{}).error)
        assert(arco.call('deliver_note',{path=42}).error)
        assert(arco.call('deliver_note',{path='no',extra=true}).error)
        assert(#arco.call('tool_registry',{}).effective==1)
      )lua"});
        try {
          engine.turn(
              {"", definition +
                       "d.source='return 99'; assert(arco.define_tool(d).staged); "
                       "error('failed workflow')"});
          require(false);
        } catch (const Error &) {
        }
        engine.turn({"", "assert(arco.call('deliver_note',{path=" +
                             unwrap(dump_json(Value{(path / "note2").string()})) +
                             "}).written)"});
        engine.turn({"", definition + R"lua(
        local v=arco.call('tool_registry',{})
        assert(not arco.call('tool_define',{base='stale',definition=d}).staged)
        d.name='roundtrip'; d.source='return args.path'
        assert(arco.define_tool(d).staged)
        d.name='latent_error'; d.source="error('runtime only')"
        assert(arco.define_tool(d).staged)
        d.name='timeout_probe'; d.source="return arco.call('exec',{argv={'/bin/sh','-c','printf original; sleep 2'},timeout_seconds=1})"
        assert(arco.define_tool(d).staged)
      )lua"});
        engine.turn({"", R"lua(
        local text='quote" slash\\ newline\n snowman ☃ nul\0 end'
        assert(arco.call('roundtrip',{path=text})==text)
        assert(arco.call('latent_error',{path='ignored'}).error)
        local r=arco.call('timeout_probe',{path='ignored'})
        assert(r.timed_out and r.effect_outcome=='unknown' and r.output_ref)
        assert(arco.call('read_process_output',{output_ref=r.output_ref}).output=='original')
      )lua"});
        bool paused = false;
        engine.cancelled = [&] { return paused; };
        engine.operation_completed = [&](std::string_view v) {
          if (v.starts_with("tool_define"))
            paused = true;
        };
        try {
          engine.turn(
              {"", definition +
                       "d.source='return 99'; assert(arco.define_tool(d).staged)"});
          require(false);
        } catch (const Error &e) {
          require(e.code == ErrorCode::interrupted);
        }
        engine.cancelled = {};
        engine.operation_completed = {};
        engine.turn({"", "assert(arco.call('deliver_note',{path=" +
                             unwrap(dump_json(Value{(path / "after-pause").string()})) +
                             "}).written)"});
        engine.effect_policy = [](std::string_view n, const Value &) {
          if (n == "write_file")
            throw Error{ErrorCode::conflict};
        };
        engine.turn({"", "assert(arco.call('deliver_note',{path=" +
                             unwrap(dump_json(Value{(path / "blocked").string()})) +
                             "}).error)"});
        require(!std::filesystem::exists(path / "blocked"));
        engine.effect_policy = {};
        engine.turn({"", definition + "d.name='bounded_recursion'; d.source=\"return "
                                      "arco.call('bounded_recursion',args)\"; "
                                      "assert(arco.define_tool(d).staged)"});
        try {
          engine.turn({"", "arco.call('bounded_recursion',{path='none'})"});
          require(false);
        } catch (const Error &e) {
          require(e.code == ErrorCode::capacity);
        }
      }
      {
        CodingEngine reopened{log, context, provider, "test"};
        reopened.turn(
            {"",
             "arco.request(); assert(#arco.call('tool_registry',{}).effective==5)"});
      }
    }
    {
      auto root =
          unwrap(RetainedState::open(std::make_unique<NativeJournalDirectory>(unwrap(
                                         NativeJournalDirectory::open(path.string()))),
                                     "audit",
                                     {id<EnvironmentId>(1),
                                      id<AuditStreamId>(2),
                                      7,
                                      {1024 * 1024, 4 * 1024 * 1024},
                                      std::nullopt},
                                     {64 * 1024 * 1024, 20000}));
      unwrap(root->confirm_recovery());
      recover_coding_session(*root);
      AuditLog log{*root};
      ContextStore context{log};
      Observer provider;
      provider.expected = true;
      CodingEngine engine{log, context, provider, "reopened"};
      engine.turn(
          {"", "arco.request(); assert(#arco.call('tool_registry',{}).effective==5); "
               "assert(arco.call('deliver_note',{path=" +
                   unwrap(dump_json(Value{(path / "disk-reopen").string()})) +
                   "}).written)"});
      require(read_file(path / "disk-reopen") ==
              "Use retained outputs; never replay unknown effects.\n");
    }
    test_lua_command_post_bridge(path);
    std::filesystem::remove_all(path);
    std::cout << "Lua tools oracle passed\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << error_name(e.code) << "\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\n";
  }
  std::cerr << "Evidence retained at " << path << "\n";
  return 1;
}
