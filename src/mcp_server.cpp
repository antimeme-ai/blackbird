#include "blackbird/mcp_server.hpp"
#include "blackbird/json.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <istream>
#include <limits>
#include <ostream>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace blackbird {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxBoardReadLimit = 1024U;
constexpr std::size_t kMaxJsonDepth = 128U;
constexpr std::size_t kMaxJsonNodes = 500000U;
constexpr std::int64_t kDefaultPeerStopGraceMs = 1500;
constexpr std::int64_t kMaxPeerStopGraceMs = 60000;

struct ToolErrorSpec {
  std::string_view code;
  std::string message;
};

struct PathContainment {
  const fs::path &candidate;
  const fs::path &root;
};

struct ToolSchemaEntry {
  std::string_view name;
  std::string_view description;
  Value input_schema;
};

bool is_object(const Value &v) noexcept {
  return std::holds_alternative<Value::Object>(v.value());
}

bool is_array(const Value &v) noexcept {
  return std::holds_alternative<Value::Array>(v.value());
}

bool is_string(const Value &v) noexcept {
  return std::holds_alternative<std::string>(v.value());
}

bool is_bool(const Value &v) noexcept {
  return std::holds_alternative<bool>(v.value());
}

bool is_null(const Value &v) noexcept {
  return std::holds_alternative<std::nullptr_t>(v.value());
}

bool is_number(const Value &v) noexcept {
  return std::holds_alternative<Number>(v.value());
}

bool valid_rpc_id(const Value &v) noexcept {
  return is_string(v) || is_number(v) || is_null(v);
}

bool has_duplicate_keys(const Value::Object &obj) {
  std::set<std::string_view> seen;
  for (const auto &[k, val] : obj) {
    (void)val;
    if (!seen.insert(k).second)
      return true;
  }
  return false;
}

bool only_allowed_keys(const Value::Object &obj,
                       std::span<const std::string_view> allowed) {
  for (const auto &[k, val] : obj) {
    (void)val;
    if (std::ranges::find(allowed, k) == allowed.end())
      return false;
  }
  return true;
}

bool valid_utf8_no_nul(std::string_view text) noexcept {
  return text.find('\0') == std::string_view::npos && valid_utf8(text);
}

bool valid_configured_path(const fs::path &path) {
  const std::string native = path.string();
  if (native.empty() || !valid_utf8_no_nul(native))
    return false;
  return path.is_absolute();
}

// Rejects any ".." component before canonicalization, uses symlink_status during
// ancestor ascent so dangling symlinks cannot slip past canonicalization, and returns
// the symlink-resolved path.
Result<fs::path> resolve_existing_prefix(const fs::path &input) {
  if (!valid_configured_path(input))
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  fs::path cleaned;
  for (const auto &part : input) {
    if (part == "..")
      return Result<fs::path>::failure({ErrorCode::invalid_range});
    if (part.empty() || part == ".")
      continue;
    cleaned /= part;
  }
  if (cleaned.empty() || !cleaned.is_absolute())
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  fs::path probe = cleaned;
  std::vector<fs::path> tail;
  while (true) {
    std::error_code ec;
    const fs::file_status st = fs::symlink_status(probe, ec);
    if (ec && ec != std::errc::no_such_file_or_directory)
      return Result<fs::path>::failure({ErrorCode::io});
    if (st.type() == fs::file_type::not_found) {
      const fs::path parent = probe.parent_path();
      if (parent == probe)
        return Result<fs::path>::failure({ErrorCode::invalid_range});
      tail.push_back(probe.filename());
      probe = parent;
      continue;
    }
    // Existing entry (including live or dangling symlinks): break and let canonical()
    // resolve live symlinks and reject dangling symlinks.
    break;
  }

  std::error_code ec;
  fs::path base = fs::canonical(probe, ec);
  if (ec)
    return Result<fs::path>::failure({ErrorCode::invalid_range});

  for (auto it = tail.rbegin(); it != tail.rend(); ++it)
    base /= *it;
  return Result<fs::path>::success(base);
}

std::string ascii_upper(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text)
    out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
  return out;
}

bool is_valid_mcp_extra_env_key(std::string_view key) noexcept {
  if (key.empty() || key.size() > 256U)
    return false;
  auto is_alpha = [](char ch) noexcept {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
  };
  auto is_alnum = [&](char ch) noexcept {
    return is_alpha(ch) || (ch >= '0' && ch <= '9');
  };
  if (!is_alpha(key.front()) && key.front() != '_')
    return false;
  for (const char ch : key) {
    if (!is_alnum(ch) && ch != '_')
      return false;
  }
  return true;
}

bool is_disallowed_mcp_extra_env_key(std::string_view key) {
  const std::string upper = ascii_upper(key);
  static constexpr std::array<std::string_view, 14> blocked_prefixes{
      "BLACKBIRD_PLATOON_",
      "GIT_",
      "LD_",
      "DYLD_",
      "PERL5",
      "RUBY",
      "NPM_CONFIG_",
      "JAVA_",
      "_JAVA_",
      "PYTHON",
      "NODE_",
      "BASH_",
      "XDG_",
      "LUA_",
  };
  for (const auto prefix : blocked_prefixes) {
    if (upper.starts_with(prefix))
      return true;
  }
  static constexpr std::array<std::string_view, 21> blocked_exact{
      "ENV",           "BASH_ENV",   "ZDOTDIR",    "HOME",
      "SSH_AUTH_SOCK", "GNUPGHOME",  "CARGO_HOME", "RUSTUP_HOME",
      "GEM_HOME",      "GCONV_PATH", "LOCPATH",    "NLSPATH",
      "IFS",           "PATH",       "CURL_HOME",  "PROMPT_COMMAND",
      "SHELL",         "EDITOR",     "VISUAL",     "PAGER",
      "TMPDIR",
  };
  if (std::ranges::find(blocked_exact, upper) != blocked_exact.end())
    return true;
  static constexpr std::array<std::string_view, 7> secret_markers{
      "API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "BEARER"};
  for (const auto marker : secret_markers) {
    if (upper.find(marker) != std::string::npos)
      return true;
  }
  return false;
}

bool path_within_root(PathContainment check) {
  auto cand_it = check.candidate.begin();
  auto root_it = check.root.begin();
  for (; root_it != check.root.end(); ++root_it, ++cand_it) {
    if (cand_it == check.candidate.end() || *cand_it != *root_it)
      return false;
  }
  return true;
}

std::optional<std::uint64_t> parse_uint64_value(const Value &v) {
  if (!is_number(v))
    return std::nullopt;
  const auto &storage = v.number().storage();
  if (const auto *u = std::get_if<std::uint64_t>(&storage))
    return *u;
  if (const auto *i = std::get_if<std::int64_t>(&storage)) {
    if (*i < 0)
      return std::nullopt;
    return static_cast<std::uint64_t>(*i);
  }
  const std::string text = v.number().text();
  if (text.empty() || text.front() == '-')
    return std::nullopt;
  std::uint64_t parsed = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::optional<std::int64_t> parse_int64_value(const Value &v) {
  if (!is_number(v))
    return std::nullopt;
  const auto &storage = v.number().storage();
  if (const auto *i = std::get_if<std::int64_t>(&storage))
    return *i;
  if (const auto *u = std::get_if<std::uint64_t>(&storage)) {
    if (*u > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()))
      return std::nullopt;
    return static_cast<std::int64_t>(*u);
  }
  const std::string text = v.number().text();
  if (text.empty())
    return std::nullopt;
  std::int64_t parsed = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

Value json_rpc_result(const Value &id, Value result) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"id", id},
      {"result", std::move(result)},
  });
}

Value json_rpc_error(const Value &id, std::int64_t code, std::string message) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"id", id},
      {"error", Value::object({
                    {"code", Value{Number{code}}},
                    {"message", Value{std::move(message)}},
                })},
  });
}

Value make_tool_result(const Value &payload, bool is_error) {
  auto dumped = dump_json(payload);
  std::string text;
  if (dumped.has_value()) {
    text = std::move(dumped).value();
  } else {
    is_error = true;
    text = R"({"error":"internal_error","message":"failed to serialize tool result"})";
  }
  Value::Array content;
  content.push_back(Value::object({
      {"type", Value{"text"}},
      {"text", Value{std::move(text)}},
  }));
  return Value::object({
      {"content", Value{std::move(content)}},
      {"isError", Value{is_error}},
  });
}

Value make_tool_error(ToolErrorSpec spec) {
  return make_tool_result(Value::object({
                              {"error", Value{std::string{spec.code}}},
                              {"message", Value{std::move(spec.message)}},
                          }),
                          true);
}

Value make_tool_error_from_code(Error error, std::string_view op_name) {
  std::string message{op_name};
  message += " failed: ";
  message += error_name(error.code);
  Value::Object body;
  body.emplace_back("error", Value{std::string{error_name(error.code)}});
  body.emplace_back("message", Value{std::move(message)});
  if (error.detail != 0)
    body.emplace_back("detail", Value{Number{error.detail}});
  return make_tool_result(Value::object(std::move(body)), true);
}

Value schema_string(std::string_view description) {
  return Value::object({
      {"type", Value{"string"}},
      {"description", Value{std::string{description}}},
  });
}

Value schema_integer(std::string_view description) {
  return Value::object({
      {"type", Value{"integer"}},
      {"description", Value{std::string{description}}},
  });
}

Value schema_boolean(std::string_view description) {
  return Value::object({
      {"type", Value{"boolean"}},
      {"description", Value{std::string{description}}},
  });
}

Value schema_object(Value::Object properties,
                    std::initializer_list<std::string_view> required) {
  Value::Array req;
  req.reserve(required.size());
  for (const auto key : required)
    req.emplace_back(std::string{key});
  return Value::object({
      {"type", Value{"object"}},
      {"properties", Value::object(std::move(properties))},
      {"required", Value{std::move(req)}},
      {"additionalProperties", Value{false}},
  });
}

Value member_to_value(const PlatoonMember &m) {
  return Value::object({
      {"id", Value{m.id}},
      {"role", Value{m.role}},
      {"provider", Value{m.provider}},
      {"model", Value{m.model}},
      {"workspace", Value{m.workspace}},
      {"branch", Value{m.branch}},
      {"state", Value{std::string{platoon_member_state_name(m.state)}}},
      {"pid", Value{Number{m.pid}}},
      {"updated_ns", Value{Number{m.updated_ns}}},
      {"brief", Value{m.brief}},
  });
}

Value message_to_value(const PlatoonMessage &m) {
  Value::Array refs;
  refs.reserve(m.refs.size());
  for (const auto &ref : m.refs)
    refs.emplace_back(ref);
  return Value::object({
      {"seq", Value{Number{m.seq}}},
      {"timestamp_ns", Value{Number{m.timestamp_ns}}},
      {"from", Value{m.from}},
      {"to", Value{m.to}},
      {"kind", Value{std::string{platoon_message_kind_name(m.kind)}}},
      {"text", Value{m.text}},
      {"refs", Value{std::move(refs)}},
  });
}

Value worktree_info_to_value(const WorktreeLeaseInfo &info) {
  return Value::object({
      {"lease_id", Value{info.lease_id}},
      {"branch", Value{info.branch}},
      {"base_ref", Value{info.base_ref}},
      {"base_sha", Value{info.base_sha}},
      {"owner_id", Value{info.owner_id}},
      {"owner_pid", Value{Number{info.owner_pid}}},
      {"created_ns", Value{Number{info.created_ns}}},
      {"path", Value{info.path.string()}},
      {"head_sha", Value{info.head_sha}},
      {"dirty", Value{info.dirty}},
      {"commits_ahead", Value{Number{info.commits_ahead}}},
      {"owner_alive", Value{info.owner_alive}},
      {"worktree_present", Value{info.worktree_present}},
  });
}

Value peer_snapshot_to_value(const PlatoonPeerSnapshot &snap) {
  Value exit_val =
      snap.exit_code.has_value() ? Value{Number{*snap.exit_code}} : Value{nullptr};
  return Value::object({
      {"peer_id", Value{snap.peer_id}},
      {"role", Value{snap.role}},
      {"provider", Value{snap.provider}},
      {"model", Value{snap.model}},
      {"working_dir", Value{snap.working_dir.string()}},
      {"session_dir", Value{snap.session_dir.string()}},
      {"state", Value{std::string{platoon_peer_state_name(snap.state)}}},
      {"pid", Value{Number{snap.pid}}},
      {"exit_code", std::move(exit_val)},
      {"output_tail", Value{snap.output_tail}},
      {"output_bytes", Value{Number{static_cast<std::uint64_t>(snap.output_bytes)}}},
      {"started_ns", Value{Number{snap.started_ns}}},
      {"finished_ns", Value{Number{snap.finished_ns}}},
  });
}

std::optional<std::string> get_required_string(const Value &args, std::string_view key,
                                               Value &err_out) {
  const auto *found = args.find(key);
  if (found == nullptr || !is_string(*found)) {
    err_out = make_tool_error(
        {"invalid_arguments", "missing or non-string field: " + std::string{key}});
    return std::nullopt;
  }
  return found->string();
}

bool get_optional_string(const Value &args, std::string_view key, std::string &out,
                         Value &err_out) {
  const auto *found = args.find(key);
  if (found == nullptr)
    return true;
  if (!is_string(*found)) {
    err_out = make_tool_error(
        {"invalid_arguments", "expected string field: " + std::string{key}});
    return false;
  }
  out = found->string();
  return true;
}

bool get_optional_bool(const Value &args, std::string_view key, bool &out,
                       Value &err_out) {
  const auto *found = args.find(key);
  if (found == nullptr)
    return true;
  if (!is_bool(*found)) {
    err_out = make_tool_error(
        {"invalid_arguments", "expected boolean field: " + std::string{key}});
    return false;
  }
  out = std::get<bool>(found->value());
  return true;
}

bool get_optional_uint64(const Value &args, std::string_view key, std::uint64_t &out,
                         Value &err_out) {
  const auto *found = args.find(key);
  if (found == nullptr)
    return true;
  const auto parsed = parse_uint64_value(*found);
  if (!parsed.has_value()) {
    err_out =
        make_tool_error({"invalid_arguments",
                         "expected non-negative integer field: " + std::string{key}});
    return false;
  }
  out = *parsed;
  return true;
}

bool get_optional_int64(const Value &args, std::string_view key, std::int64_t &out,
                        Value &err_out) {
  const auto *found = args.find(key);
  if (found == nullptr)
    return true;
  const auto parsed = parse_int64_value(*found);
  if (!parsed.has_value()) {
    err_out = make_tool_error(
        {"invalid_arguments", "expected integer field: " + std::string{key}});
    return false;
  }
  out = *parsed;
  return true;
}

} // namespace

struct McpCommandPostServer::Impl {
  std::size_t max_line_bytes = kMcpDefaultMaxLineBytes;
  bool initialized = false;

  std::unique_ptr<PlatoonBoard> board;
  std::unique_ptr<WorktreeLeaseManager> worktree;
  std::unique_ptr<PlatoonRunner> runner;
  std::unique_ptr<DecisionModels> decision_models;

  McpPlatoonPeerConfig runner_config;
  std::vector<fs::path> normalized_allowed_roots;

  std::vector<ToolSchemaEntry> build_tool_schemas() const {
    std::vector<ToolSchemaEntry> tools;
    if (board) {
      tools.push_back(
          {"platoon_board_post",
           "Post a durable message to the Blackbird Platoon Board.",
           schema_object(
               {
                   {"from", schema_string("Sender member ID.")},
                   {"to", schema_string("Recipient member ID or 'all'.")},
                   {"kind", schema_string("Message kind: brief, message, handoff, "
                                          "blocker, decision, artifact, review, "
                                          "status.")},
                   {"text", schema_string("Message text body.")},
                   {"refs",
                    Value::object({
                        {"type", Value{"array"}},
                        {"items", Value::object({{"type", Value{"string"}}})},
                        {"description", Value{"Optional file or artifact refs."}},
                    })},
               },
               {"from", "text"})});
      tools.push_back(
          {"platoon_board_read",
           "Read messages from the Blackbird Platoon Board after a sequence number.",
           schema_object(
               {
                   {"after_seq",
                    schema_integer("Return messages with seq > after_seq.")},
                   {"limit", schema_integer("Maximum messages to return (1..1024).")},
                   {"recipient_filter",
                    schema_string("Optional member ID to filter relevant messages.")},
               },
               {})});
      tools.push_back(
          {"platoon_roster_upsert",
           "Register or update a member entry on the Blackbird Platoon Board roster.",
           schema_object(
               {
                   {"id", schema_string("Unique member ID.")},
                   {"role", schema_string("Member role.")},
                   {"provider", schema_string("Model provider name.")},
                   {"model", schema_string("Model identifier.")},
                   {"workspace", schema_string("Workspace path.")},
                   {"branch", schema_string("Git branch name.")},
                   {"state", schema_string("Member state: starting, working, waiting, "
                                           "completed, failed, stopped.")},
                   {"pid", schema_integer("Non-negative process ID (0 if unset).")},
                   {"updated_ns",
                    schema_integer("Optional timestamp in nanoseconds (0 for now).")},
                   {"brief", schema_string("Member assignment summary.")},
               },
               {"id"})});
      tools.push_back(
          {"platoon_roster_list",
           "List all members currently recorded on the Blackbird Platoon Board roster.",
           schema_object({}, {})});
    }

    if (worktree) {
      tools.push_back(
          {"worktree_acquire", "Acquire a bounded isolated git worktree lease.",
           schema_object(
               {
                   {"lease_id", schema_string("Unique lease identifier.")},
                   {"branch", schema_string("Git branch name for the worktree.")},
                   {"base_ref", schema_string("Base git ref (default 'HEAD').")},
                   {"owner_id", schema_string("Owner actor identifier.")},
                   {"owner_pid", schema_integer("Owner process ID (0 if manual).")},
                   {"use_existing_branch",
                    schema_boolean(
                        "Check out an existing branch instead of creating.")},
               },
               {"lease_id", "branch"})});
      tools.push_back({"worktree_list", "List active isolated git worktree leases.",
                       schema_object({}, {})});
      tools.push_back(
          {"worktree_status",
           "Inspect live status (HEAD, dirty flag, commits ahead) of a worktree lease.",
           schema_object({{"lease_id", schema_string("Lease identifier.")}},
                         {"lease_id"})});
      tools.push_back(
          {"worktree_release",
           "Release a worktree lease. Refuses dirty worktrees unless force is true.",
           schema_object(
               {
                   {"lease_id", schema_string("Lease identifier.")},
                   {"force", schema_boolean("Explicitly discard dirty worktree changes "
                                            "(default false).")},
               },
               {"lease_id"})});
      tools.push_back(
          {"worktree_reclaim",
           "Reclaim clean stale leases whose owner PID has exited while preserving "
           "orphaned dirty worktrees.",
           schema_object({}, {})});
    }

    if (runner) {
      Value::Object spawn_props{
          {"peer_id", schema_string("Unique peer identifier.")},
          {"role", schema_string("Peer role.")},
          {"provider", schema_string("Model provider name.")},
          {"model", schema_string("Model identifier.")},
          {"prompt", schema_string("Task prompt passed to the peer.")},
          {"working_dir", schema_string("Absolute working directory for the peer.")},
          {"session_dir", schema_string("Absolute session directory for the peer.")},
          {"effort", schema_string("Optional reasoning effort token.")},
          {"workflow", schema_string("Optional absolute path to workflow file.")},
          {"max_output_bytes",
           schema_integer("Optional output tail buffer cap in bytes.")},
          {"extra_env",
           Value::object({
               {"type", Value{"object"}},
               {"additionalProperties", Value::object({{"type", Value{"string"}}})},
               {"description",
                Value{"Optional non-secret environment variables for the peer."}},
           })},
      };
      std::vector<std::string_view> required_fields{"peer_id", "role", "provider",
                                                    "model", "prompt"};
      if (runner_config.working_root.empty())
        required_fields.push_back("working_dir");
      if (runner_config.session_root.empty())
        required_fields.push_back("session_dir");
      Value::Array req_arr;
      req_arr.reserve(required_fields.size());
      for (const auto key : required_fields)
        req_arr.emplace_back(std::string{key});
      tools.push_back({"platoon_peer_spawn",
                       "Launch a bounded supervised Blackbird peer process.",
                       Value::object({
                           {"type", Value{"object"}},
                           {"properties", Value::object(std::move(spawn_props))},
                           {"required", Value{std::move(req_arr)}},
                           {"additionalProperties", Value{false}},
                       })});
      tools.push_back({"platoon_peer_list",
                       "List active and recently settled supervised Blackbird peers.",
                       schema_object({}, {})});
      tools.push_back(
          {"platoon_peer_stop", "Stop a running supervised peer process group cleanly.",
           schema_object(
               {
                   {"peer_id", schema_string("Peer identifier to stop.")},
                   {"grace_ms",
                    schema_integer("SIGTERM grace period in milliseconds (0..60000).")},
               },
               {"peer_id"})});
    }

    if (decision_models) {
      tools.push_back(
          {"decision_evaluate",
           "Evaluate structured decision questions via the configured decision model "
           "(credentials are host-managed and never accepted in arguments).",
           schema_object(
               {
                   {"provider",
                    schema_string("Decision provider (e.g. 'jev' or 'clef').")},
                   {"model", schema_string("Optional decision model name.")},
                   {"state",
                    Value::object(
                        {{"description",
                          Value{"State context (string, object, or array)."}}})},
                   {"questions",
                    Value::object(
                        {{"type", Value{"object"}},
                         {"description",
                          Value{
                              "Map of question IDs to typed question definitions."}}})},
                   {"timeout_seconds",
                    schema_integer("Optional timeout in seconds (1..3600).")},
               },
               {"state", "questions"})});
    }

    return tools;
  }

  std::optional<fs::path> resolve_allowed_path(const fs::path &candidate) const {
    const auto resolved = resolve_existing_prefix(candidate);
    if (!resolved.has_value())
      return std::nullopt;
    if (normalized_allowed_roots.empty())
      return resolved.value();
    for (const auto &root : normalized_allowed_roots) {
      if (path_within_root({resolved.value(), root}))
        return resolved.value();
    }
    return std::nullopt;
  }

  Value call_platoon_board_post(const Value &args) {
    static constexpr std::array<std::string_view, 5> allowed{"from", "to", "kind",
                                                             "text", "refs"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in platoon_board_post"});

    Value err;
    const auto from = get_required_string(args, "from", err);
    if (!from.has_value())
      return err;
    const auto text = get_required_string(args, "text", err);
    if (!text.has_value())
      return err;

    std::string to = "all";
    if (!get_optional_string(args, "to", to, err))
      return err;

    std::string kind_name = "message";
    if (!get_optional_string(args, "kind", kind_name, err))
      return err;
    const auto kind = parse_platoon_message_kind(kind_name);
    if (!kind.has_value())
      return make_tool_error({"invalid_arguments", "invalid platoon message kind"});

    std::vector<std::string> refs;
    if (const auto *refs_val = args.find("refs")) {
      if (!is_array(*refs_val))
        return make_tool_error(
            {"invalid_arguments", "refs must be an array of strings"});
      refs.reserve(refs_val->array().size());
      for (const auto &entry : refs_val->array()) {
        if (!is_string(entry))
          return make_tool_error(
              {"invalid_arguments", "each ref in refs must be a string"});
        refs.push_back(entry.string());
      }
    }

    auto posted = board->post(
        PlatoonPost{*from, std::move(to), kind.value(), *text, std::move(refs)});
    if (!posted.has_value())
      return make_tool_error_from_code(posted.error(), "platoon_board_post");
    return make_tool_result(message_to_value(posted.value()), false);
  }

  Value call_platoon_board_read(const Value &args) const {
    static constexpr std::array<std::string_view, 3> allowed{"after_seq", "limit",
                                                             "recipient_filter"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in platoon_board_read"});

    Value err;
    std::uint64_t after_seq = 0;
    if (!get_optional_uint64(args, "after_seq", after_seq, err))
      return err;

    std::uint64_t limit = kPlatoonDefaultReadLimit;
    if (!get_optional_uint64(args, "limit", limit, err))
      return err;
    if (limit > kMaxBoardReadLimit)
      limit = kMaxBoardReadLimit;

    std::string recipient_filter;
    if (!get_optional_string(args, "recipient_filter", recipient_filter, err))
      return err;

    const auto msgs =
        board->read_since(after_seq, static_cast<std::size_t>(limit), recipient_filter);
    if (!msgs.has_value())
      return make_tool_error_from_code(msgs.error(), "platoon_board_read");

    const auto latest = board->latest_seq();
    if (!latest.has_value())
      return make_tool_error_from_code(latest.error(), "platoon_board_read");

    Value::Array arr;
    arr.reserve(msgs.value().size());
    for (const auto &m : msgs.value())
      arr.push_back(message_to_value(m));

    return make_tool_result(
        Value::object({
            {"messages", Value{std::move(arr)}},
            {"latest_seq", Value{Number{latest.value()}}},
            {"count", Value{Number{static_cast<std::uint64_t>(msgs.value().size())}}},
        }),
        false);
  }

  Value call_platoon_roster_upsert(const Value &args) {
    static constexpr std::array<std::string_view, 10> allowed{
        "id",     "role",  "provider", "model",      "workspace",
        "branch", "state", "pid",      "updated_ns", "brief"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in platoon_roster_upsert"});

    Value err;
    const auto id = get_required_string(args, "id", err);
    if (!id.has_value())
      return err;

    PlatoonMember member;
    member.id = *id;
    if (!get_optional_string(args, "role", member.role, err) ||
        !get_optional_string(args, "provider", member.provider, err) ||
        !get_optional_string(args, "model", member.model, err) ||
        !get_optional_string(args, "workspace", member.workspace, err) ||
        !get_optional_string(args, "branch", member.branch, err) ||
        !get_optional_string(args, "brief", member.brief, err))
      return err;

    std::string state_name = "starting";
    if (!get_optional_string(args, "state", state_name, err))
      return err;
    const auto parsed_state = parse_platoon_member_state(state_name);
    if (!parsed_state.has_value())
      return make_tool_error({"invalid_arguments", "invalid platoon member state"});
    member.state = parsed_state.value();

    if (!get_optional_int64(args, "pid", member.pid, err) ||
        !get_optional_int64(args, "updated_ns", member.updated_ns, err))
      return err;

    const auto saved = board->upsert_member(member);
    if (!saved.has_value())
      return make_tool_error_from_code(saved.error(), "platoon_roster_upsert");
    return make_tool_result(member_to_value(saved.value()), false);
  }

  Value call_platoon_roster_list(const Value &args) const {
    if (!args.object().empty())
      return make_tool_error(
          {"invalid_arguments", "platoon_roster_list takes no arguments"});

    const auto list = board->members();
    if (!list.has_value())
      return make_tool_error_from_code(list.error(), "platoon_roster_list");

    Value::Array arr;
    arr.reserve(list.value().size());
    for (const auto &m : list.value())
      arr.push_back(member_to_value(m));

    return make_tool_result(
        Value::object({
            {"members", Value{std::move(arr)}},
            {"count", Value{Number{static_cast<std::uint64_t>(list.value().size())}}},
        }),
        false);
  }

  Value call_worktree_acquire(const Value &args) {
    static constexpr std::array<std::string_view, 6> allowed{
        "lease_id", "branch",    "base_ref",
        "owner_id", "owner_pid", "use_existing_branch"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in worktree_acquire"});

    Value err;
    const auto lease_id = get_required_string(args, "lease_id", err);
    if (!lease_id.has_value())
      return err;
    const auto branch = get_required_string(args, "branch", err);
    if (!branch.has_value())
      return err;

    WorktreeLeaseRequest req;
    req.lease_id = *lease_id;
    req.branch = *branch;
    if (!get_optional_string(args, "base_ref", req.base_ref, err) ||
        !get_optional_string(args, "owner_id", req.owner_id, err) ||
        !get_optional_int64(args, "owner_pid", req.owner_pid, err) ||
        !get_optional_bool(args, "use_existing_branch", req.use_existing_branch, err))
      return err;

    const auto acquired = worktree->acquire(req);
    if (!acquired.has_value())
      return make_tool_error_from_code(acquired.error(), "worktree_acquire");
    return make_tool_result(worktree_info_to_value(acquired.value()), false);
  }

  Value call_worktree_list(const Value &args) const {
    if (!args.object().empty())
      return make_tool_error({"invalid_arguments", "worktree_list takes no arguments"});

    const auto listed = worktree->list();
    if (!listed.has_value())
      return make_tool_error_from_code(listed.error(), "worktree_list");

    Value::Array arr;
    arr.reserve(listed.value().size());
    for (const auto &info : listed.value())
      arr.push_back(worktree_info_to_value(info));

    return make_tool_result(
        Value::object({
            {"leases", Value{std::move(arr)}},
            {"count", Value{Number{static_cast<std::uint64_t>(listed.value().size())}}},
        }),
        false);
  }

  Value call_worktree_status(const Value &args) const {
    static constexpr std::array<std::string_view, 1> allowed{"lease_id"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in worktree_status"});

    Value err;
    const auto lease_id = get_required_string(args, "lease_id", err);
    if (!lease_id.has_value())
      return err;

    const auto st = worktree->status(*lease_id);
    if (!st.has_value())
      return make_tool_error_from_code(st.error(), "worktree_status");
    return make_tool_result(worktree_info_to_value(st.value()), false);
  }

  Value call_worktree_release(const Value &args) {
    static constexpr std::array<std::string_view, 2> allowed{"lease_id", "force"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in worktree_release"});

    Value err;
    const auto lease_id = get_required_string(args, "lease_id", err);
    if (!lease_id.has_value())
      return err;

    // Never silently force dirty release: default is strictly false.
    bool force = false;
    if (!get_optional_bool(args, "force", force, err))
      return err;

    const auto res = worktree->release(*lease_id, force);
    if (!res.has_value())
      return make_tool_error_from_code(res.error(), "worktree_release");

    return make_tool_result(Value::object({
                                {"released", Value{true}},
                                {"lease_id", Value{*lease_id}},
                                {"forced", Value{force}},
                            }),
                            false);
  }

  Value call_worktree_reclaim(const Value &args) {
    if (!args.object().empty())
      return make_tool_error(
          {"invalid_arguments", "worktree_reclaim takes no arguments"});

    const auto report = worktree->reclaim_stale();
    if (!report.has_value())
      return make_tool_error_from_code(report.error(), "worktree_reclaim");

    Value::Array reclaimed;
    reclaimed.reserve(report.value().reclaimed.size());
    for (const auto &id : report.value().reclaimed)
      reclaimed.emplace_back(id);

    Value::Array orphaned;
    orphaned.reserve(report.value().orphaned_dirty.size());
    for (const auto &info : report.value().orphaned_dirty)
      orphaned.push_back(worktree_info_to_value(info));

    return make_tool_result(Value::object({
                                {"reclaimed", Value{std::move(reclaimed)}},
                                {"orphaned_dirty", Value{std::move(orphaned)}},
                            }),
                            false);
  }

  Value call_platoon_peer_spawn(const Value &args) {
    // Host-only `executable` is intentionally excluded from allowed keys.
    static constexpr std::array<std::string_view, 11> allowed{
        "peer_id",  "role",        "provider",        "model",
        "prompt",   "working_dir", "session_dir",     "effort",
        "workflow", "extra_env",   "max_output_bytes"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error({"invalid_arguments",
                              "unknown or disallowed argument in platoon_peer_spawn"});

    Value err;
    const auto peer_id = get_required_string(args, "peer_id", err);
    if (!peer_id.has_value())
      return err;
    const auto role = get_required_string(args, "role", err);
    if (!role.has_value())
      return err;
    const auto provider = get_required_string(args, "provider", err);
    if (!provider.has_value())
      return err;
    const auto model = get_required_string(args, "model", err);
    if (!model.has_value())
      return err;
    const auto prompt = get_required_string(args, "prompt", err);
    if (!prompt.has_value())
      return err;

    PlatoonPeerSpec spec;
    spec.peer_id = *peer_id;
    spec.role = *role;
    spec.provider = *provider;
    spec.model = *model;
    spec.prompt = *prompt;
    spec.executable = runner_config.executable;

    std::string working_dir_str;
    if (!get_optional_string(args, "working_dir", working_dir_str, err))
      return err;
    if (!working_dir_str.empty()) {
      spec.working_dir = fs::path{working_dir_str};
    } else if (!runner_config.working_root.empty()) {
      spec.working_dir = runner_config.working_root;
    } else {
      return make_tool_error(
          {"invalid_arguments", "missing required field: working_dir"});
    }

    std::string session_dir_str;
    if (!get_optional_string(args, "session_dir", session_dir_str, err))
      return err;
    if (!session_dir_str.empty()) {
      spec.session_dir = fs::path{session_dir_str};
    } else if (!runner_config.session_root.empty()) {
      if (!valid_platoon_member_id(spec.peer_id))
        return make_tool_error({"invalid_range", "invalid peer_id for session_dir"});
      spec.session_dir = runner_config.session_root / spec.peer_id;
    } else {
      return make_tool_error(
          {"invalid_arguments", "missing required field: session_dir"});
    }

    const auto resolved_working = resolve_allowed_path(spec.working_dir);
    if (!resolved_working.has_value())
      return make_tool_error(
          {"forbidden_path", "working_dir is outside allowed workspace roots"});
    spec.working_dir = *resolved_working;

    const auto resolved_session = resolve_allowed_path(spec.session_dir);
    if (!resolved_session.has_value())
      return make_tool_error(
          {"forbidden_path", "session_dir is outside allowed workspace roots"});
    spec.session_dir = *resolved_session;

    if (const auto *effort_val = args.find("effort")) {
      if (!is_string(*effort_val))
        return make_tool_error({"invalid_arguments", "effort must be a string"});
      spec.effort = effort_val->string();
    }

    if (const auto *wf_val = args.find("workflow")) {
      if (!is_string(*wf_val) || wf_val->string().empty())
        return make_tool_error(
            {"invalid_arguments", "workflow must be a non-empty string"});
      const auto resolved_wf = resolve_allowed_path(fs::path{wf_val->string()});
      if (!resolved_wf.has_value())
        return make_tool_error(
            {"forbidden_path", "workflow is outside allowed workspace roots"});
      spec.workflow = *resolved_wf;
    }

    std::uint64_t max_out = spec.max_output_bytes;
    if (!get_optional_uint64(args, "max_output_bytes", max_out, err))
      return err;
    if (max_out > PlatoonRunner::max_output_bytes_limit)
      return make_tool_error({"invalid_range", "max_output_bytes exceeds limit"});
    spec.max_output_bytes = static_cast<std::size_t>(max_out);

    if (const auto *env_val = args.find("extra_env")) {
      if (!is_object(*env_val) || has_duplicate_keys(env_val->object()))
        return make_tool_error(
            {"invalid_arguments", "extra_env must be a JSON object with unique keys"});
      for (const auto &[k, v] : env_val->object()) {
        if (!is_string(v))
          return make_tool_error(
              {"invalid_arguments", "extra_env values must be strings"});
        if (!is_valid_mcp_extra_env_key(k))
          return make_tool_error(
              {"invalid_arguments", "invalid environment variable name in extra_env"});
        if (!valid_utf8_no_nul(v.string()))
          return make_tool_error(
              {"invalid_arguments", "invalid environment variable value in extra_env"});
        if (is_disallowed_mcp_extra_env_key(k))
          return make_tool_error(
              {"invalid_arguments", "disallowed environment variable in extra_env"});
        spec.extra_env.emplace_back(k, v.string());
      }
    }
    // Always inject host-authoritative platoon identity and board env vars.
    if (board)
      spec.extra_env.emplace_back("BLACKBIRD_PLATOON_BOARD", board->root().string());
    spec.extra_env.emplace_back("BLACKBIRD_PLATOON_PEER_ID", spec.peer_id);
    spec.extra_env.emplace_back("BLACKBIRD_PLATOON_ROLE", spec.role);

    const auto spawned = runner->spawn(spec);
    if (!spawned.has_value())
      return make_tool_error_from_code(spawned.error(), "platoon_peer_spawn");
    return make_tool_result(peer_snapshot_to_value(spawned.value()), false);
  }

  Value call_platoon_peer_list(const Value &args) const {
    if (!args.object().empty())
      return make_tool_error(
          {"invalid_arguments", "platoon_peer_list takes no arguments"});

    const auto peers = runner->list();
    Value::Array arr;
    arr.reserve(peers.size());
    for (const auto &snap : peers)
      arr.push_back(peer_snapshot_to_value(snap));

    return make_tool_result(
        Value::object({
            {"peers", Value{std::move(arr)}},
            {"active_count",
             Value{Number{static_cast<std::uint64_t>(runner->active_count())}}},
            {"max_peers",
             Value{Number{static_cast<std::uint64_t>(runner->max_peers())}}},
        }),
        false);
  }

  Value call_platoon_peer_stop(const Value &args) {
    static constexpr std::array<std::string_view, 2> allowed{"peer_id", "grace_ms"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments", "unknown argument in platoon_peer_stop"});

    Value err;
    const auto peer_id = get_required_string(args, "peer_id", err);
    if (!peer_id.has_value())
      return err;

    std::int64_t grace_ms = kDefaultPeerStopGraceMs;
    if (!get_optional_int64(args, "grace_ms", grace_ms, err))
      return err;
    if (grace_ms < 0 || grace_ms > kMaxPeerStopGraceMs)
      return make_tool_error({"invalid_range", "grace_ms must be between 0 and 60000"});

    const auto stopped = runner->stop(*peer_id, static_cast<int>(grace_ms));
    if (!stopped.has_value())
      return make_tool_error_from_code(stopped.error(), "platoon_peer_stop");
    return make_tool_result(peer_snapshot_to_value(stopped.value()), false);
  }

  Value call_decision_evaluate(const Value &args) {
    // Strictly allow only model-safe request keys; never accept credentials or
    // transport overrides in tool arguments.
    static constexpr std::array<std::string_view, 5> allowed{
        "provider", "model", "state", "questions", "timeout_seconds"};
    if (!only_allowed_keys(args.object(), allowed))
      return make_tool_error(
          {"invalid_arguments",
           "disallowed argument in decision_evaluate (credentials are host-managed)"});

    try {
      const Value result = decision_models->evaluate(args);
      return make_tool_result(result, false);
    } catch (const Error &e) {
      return make_tool_error_from_code(e, "decision_evaluate");
    } catch (const std::bad_alloc &) {
      return make_tool_error_from_code({ErrorCode::allocation}, "decision_evaluate");
    } catch (const std::exception &) {
      // Never leak raw exception strings that could originate from external transport.
      return make_tool_error(
          {"internal_error", "decision_evaluate encountered an unexpected error"});
    }
  }

  Value dispatch_tool(std::string_view name, const Value &arguments) {
    if (board) {
      if (name == "platoon_board_post")
        return call_platoon_board_post(arguments);
      if (name == "platoon_board_read")
        return call_platoon_board_read(arguments);
      if (name == "platoon_roster_upsert")
        return call_platoon_roster_upsert(arguments);
      if (name == "platoon_roster_list")
        return call_platoon_roster_list(arguments);
    }
    if (worktree) {
      if (name == "worktree_acquire")
        return call_worktree_acquire(arguments);
      if (name == "worktree_list")
        return call_worktree_list(arguments);
      if (name == "worktree_status")
        return call_worktree_status(arguments);
      if (name == "worktree_release")
        return call_worktree_release(arguments);
      if (name == "worktree_reclaim")
        return call_worktree_reclaim(arguments);
    }
    if (runner) {
      if (name == "platoon_peer_spawn")
        return call_platoon_peer_spawn(arguments);
      if (name == "platoon_peer_list")
        return call_platoon_peer_list(arguments);
      if (name == "platoon_peer_stop")
        return call_platoon_peer_stop(arguments);
    }
    if (decision_models) {
      if (name == "decision_evaluate")
        return call_decision_evaluate(arguments);
    }
    return make_tool_error(
        {"unknown_tool", "unknown or unconfigured tool: " + std::string{name}});
  }
};

McpCommandPostServer::McpCommandPostServer(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

McpCommandPostServer::McpCommandPostServer(McpCommandPostServer &&) noexcept = default;
McpCommandPostServer &
McpCommandPostServer::operator=(McpCommandPostServer &&) noexcept = default;
McpCommandPostServer::~McpCommandPostServer() = default;

Result<McpCommandPostServer> McpCommandPostServer::open(McpCommandPostConfig config) {
  if (config.max_line_bytes < kMcpMinLineBytes ||
      config.max_line_bytes > kMcpMaxLineBytesLimit) {
    return Result<McpCommandPostServer>::failure({ErrorCode::invalid_range});
  }

  auto impl = std::make_unique<Impl>();
  impl->max_line_bytes = config.max_line_bytes;

  if (config.board_root.has_value()) {
    auto opened = PlatoonBoard::open(*config.board_root);
    if (!opened.has_value())
      return Result<McpCommandPostServer>::failure(opened.error());
    impl->board = std::make_unique<PlatoonBoard>(std::move(opened).value());
  }

  if (config.worktree_lease.has_value()) {
    auto opened = WorktreeLeaseManager::open(*config.worktree_lease);
    if (!opened.has_value())
      return Result<McpCommandPostServer>::failure(opened.error());
    impl->worktree = std::make_unique<WorktreeLeaseManager>(std::move(opened).value());
  }

  if (config.platoon_runner.has_value()) {
    const auto &rcfg = *config.platoon_runner;
    if (rcfg.max_peers == 0 || rcfg.max_peers > PlatoonRunner::max_peers_limit)
      return Result<McpCommandPostServer>::failure({ErrorCode::invalid_range});
    if (!rcfg.executable.empty() && !valid_configured_path(rcfg.executable))
      return Result<McpCommandPostServer>::failure({ErrorCode::invalid_range});
    if (!rcfg.working_root.empty() && !valid_configured_path(rcfg.working_root))
      return Result<McpCommandPostServer>::failure({ErrorCode::invalid_range});
    if (!rcfg.session_root.empty() && !valid_configured_path(rcfg.session_root))
      return Result<McpCommandPostServer>::failure({ErrorCode::invalid_range});

    for (const auto &root : rcfg.allowed_workspace_roots) {
      auto resolved = resolve_existing_prefix(root);
      if (!resolved.has_value())
        return Result<McpCommandPostServer>::failure(resolved.error());
      impl->normalized_allowed_roots.push_back(std::move(resolved).value());
    }
    if (!impl->normalized_allowed_roots.empty()) {
      auto append_root = [&](const fs::path &p) -> Result<void> {
        if (p.empty())
          return Result<void>::success();
        auto resolved = resolve_existing_prefix(p);
        if (!resolved.has_value())
          return Result<void>::failure(resolved.error());
        impl->normalized_allowed_roots.push_back(std::move(resolved).value());
        return Result<void>::success();
      };
      if (const auto r = append_root(rcfg.working_root); !r.has_value())
        return Result<McpCommandPostServer>::failure(r.error());
      if (const auto r = append_root(rcfg.session_root); !r.has_value())
        return Result<McpCommandPostServer>::failure(r.error());
    }

    impl->runner_config = rcfg;
    try {
      impl->runner = std::make_unique<PlatoonRunner>(rcfg.max_peers);
    } catch (const Error &e) {
      return Result<McpCommandPostServer>::failure(e);
    }
  }

  if (config.decision_models.has_value()) {
    impl->decision_models = std::make_unique<DecisionModels>(*config.decision_models);
  }

  return Result<McpCommandPostServer>::success(McpCommandPostServer{std::move(impl)});
}

std::optional<Value> McpCommandPostServer::handle_message(const Value &msg) {
  if (!impl_) {
    return json_rpc_error(Value{nullptr}, kJsonRpcInternalError,
                          "server is not initialized");
  }
  if (!is_object(msg) || has_duplicate_keys(msg.object()))
    return json_rpc_error(Value{nullptr}, kJsonRpcInvalidRequest, "Invalid Request");

  const Value *id_ptr = msg.find("id");
  const bool has_id = (id_ptr != nullptr);
  if (has_id && !valid_rpc_id(*id_ptr))
    return json_rpc_error(Value{nullptr}, kJsonRpcInvalidRequest,
                          "Invalid Request: id must be string, number, or null");
  const Value id = has_id ? *id_ptr : Value{nullptr};

  const Value *ver_ptr = msg.find("jsonrpc");
  if (ver_ptr == nullptr || !is_string(*ver_ptr) || ver_ptr->string() != "2.0")
    return json_rpc_error(id, kJsonRpcInvalidRequest,
                          "Invalid Request: jsonrpc must be \"2.0\"");

  const Value *method_ptr = msg.find("method");
  if (method_ptr == nullptr || !is_string(*method_ptr) || method_ptr->string().empty())
    return json_rpc_error(id, kJsonRpcInvalidRequest,
                          "Invalid Request: missing method");
  const std::string_view method = method_ptr->string();

  const Value *params_ptr = msg.find("params");
  if (params_ptr != nullptr && !is_object(*params_ptr) && !is_null(*params_ptr)) {
    if (!has_id)
      return std::nullopt;
    return json_rpc_error(id, kJsonRpcInvalidParams,
                          "Invalid params: expected JSON object");
  }
  if (params_ptr != nullptr && is_object(*params_ptr) &&
      has_duplicate_keys(params_ptr->object())) {
    if (!has_id)
      return std::nullopt;
    return json_rpc_error(id, kJsonRpcInvalidParams, "Invalid params: duplicate keys");
  }

  // Notifications without an id never produce a JSON-RPC reply.
  if (method == "notifications/initialized") {
    impl_->initialized = true;
    if (!has_id)
      return std::nullopt;
    return json_rpc_result(id, Value::object({}));
  }
  if (method == "notifications/cancelled") {
    if (!has_id)
      return std::nullopt;
    return json_rpc_result(id, Value::object({}));
  }
  if (!has_id)
    return std::nullopt;

  if (method == "initialize") {
    return json_rpc_result(
        id, Value::object({
                {"protocolVersion", Value{std::string{kMcpProtocolVersion}}},
                {"capabilities", Value::object({{"tools", Value::object({})}})},
                {"serverInfo", Value::object({
                                   {"name", Value{std::string{kMcpServerName}}},
                                   {"version", Value{std::string{kMcpServerVersion}}},
                               })},
            }));
  }

  if (method == "ping")
    return json_rpc_result(id, Value::object({}));

  if (method == "tools/list") {
    auto schemas = impl_->build_tool_schemas();
    Value::Array tools;
    tools.reserve(schemas.size());
    for (auto &entry : schemas) {
      tools.push_back(Value::object({
          {"name", Value{std::string{entry.name}}},
          {"description", Value{std::string{entry.description}}},
          {"inputSchema", std::move(entry.input_schema)},
      }));
    }
    return json_rpc_result(id, Value::object({{"tools", Value{std::move(tools)}}}));
  }

  if (method == "tools/call") {
    if (params_ptr == nullptr || !is_object(*params_ptr)) {
      return json_rpc_error(id, kJsonRpcInvalidParams,
                            "Invalid params: tools/call requires params object");
    }
    static constexpr std::array<std::string_view, 3> allowed_params{"name", "arguments",
                                                                    "_meta"};
    if (!only_allowed_keys(params_ptr->object(), allowed_params)) {
      return json_rpc_error(id, kJsonRpcInvalidParams,
                            "Invalid params: unexpected field in tools/call params");
    }
    const Value *name_ptr = params_ptr->find("name");
    if (name_ptr == nullptr || !is_string(*name_ptr) || name_ptr->string().empty()) {
      return json_rpc_error(
          id, kJsonRpcInvalidParams,
          "Invalid params: tools/call requires non-empty string name");
    }
    Value arguments = Value::object({});
    if (const Value *args_ptr = params_ptr->find("arguments")) {
      if (!is_null(*args_ptr)) {
        if (!is_object(*args_ptr) || has_duplicate_keys(args_ptr->object())) {
          return json_rpc_error(
              id, kJsonRpcInvalidParams,
              "Invalid params: tools/call arguments must be a JSON object");
        }
        arguments = *args_ptr;
      }
    }
    return json_rpc_result(id, impl_->dispatch_tool(name_ptr->string(), arguments));
  }

  return json_rpc_error(id, kJsonRpcMethodNotFound,
                        "Method not found: " + std::string{method});
}

std::optional<Value> McpCommandPostServer::handle_line(std::string_view line) {
  if (!impl_) {
    return json_rpc_error(Value{nullptr}, kJsonRpcInternalError,
                          "server is not initialized");
  }
  if (!line.empty() && line.back() == '\r')
    line.remove_suffix(1);
  if (line.empty())
    return std::nullopt;
  if (line.size() > impl_->max_line_bytes) {
    return json_rpc_error(Value{nullptr}, kJsonRpcParseError,
                          "Parse error: line exceeds maximum size");
  }
  if (!valid_utf8_no_nul(line)) {
    return json_rpc_error(Value{nullptr}, kJsonRpcParseError,
                          "Parse error: invalid UTF-8");
  }
  const auto parsed =
      parse_json(line, {impl_->max_line_bytes, kMaxJsonNodes, kMaxJsonDepth});
  if (!parsed.has_value()) {
    return json_rpc_error(Value{nullptr}, kJsonRpcParseError,
                          "Parse error: malformed JSON");
  }
  return handle_message(parsed.value());
}

int McpCommandPostServer::run_stdio(std::istream &in, std::ostream &out) {
  if (!impl_)
    return 1;

  std::streambuf *buf = in.rdbuf();
  if (buf == nullptr)
    return 1;

  std::string line;
  while (true) {
    line.clear();
    bool saw_any = false;
    bool oversized = false;
    while (true) {
      const int ch = buf->sbumpc();
      if (ch == std::char_traits<char>::eof())
        break;
      saw_any = true;
      if (ch == '\n')
        break;
      if (!oversized) {
        // Allow one extra byte so an exact max_line_bytes line followed by \r\n fits
        // before stripping the trailing \r below.
        if (line.size() <= impl_->max_line_bytes) {
          line.push_back(static_cast<char>(ch));
        } else {
          // Stop buffering and drain until the next newline or EOF.
          oversized = true;
          line.clear();
        }
      }
    }
    if (!saw_any)
      break;

    if (!oversized) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      if (line.size() > impl_->max_line_bytes)
        oversized = true;
    }

    std::optional<Value> reply;
    if (oversized) {
      reply = json_rpc_error(Value{nullptr}, kJsonRpcParseError,
                             "Parse error: line exceeds maximum size");
    } else {
      reply = handle_line(line);
    }

    if (reply.has_value()) {
      const auto encoded = dump_json(*reply);
      if (!encoded.has_value()) {
        const auto fallback = dump_json(json_rpc_error(
            Value{nullptr}, kJsonRpcInternalError, "Internal error: encoding failed"));
        if (!fallback.has_value())
          return 1;
        out << fallback.value() << '\n' << std::flush;
      } else {
        out << encoded.value() << '\n' << std::flush;
      }
      if (!out)
        return 1;
    }
  }
  return 0;
}

std::vector<std::string> McpCommandPostServer::tool_names() const {
  std::vector<std::string> names;
  if (!impl_)
    return names;
  const auto schemas = impl_->build_tool_schemas();
  names.reserve(schemas.size());
  for (const auto &entry : schemas)
    names.emplace_back(entry.name);
  return names;
}

std::size_t McpCommandPostServer::max_line_bytes() const noexcept {
  return impl_ ? impl_->max_line_bytes : 0U;
}

} // namespace blackbird
