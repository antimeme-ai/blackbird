#include "blackbird/command_post_tools.hpp"
#include "blackbird/context_hygiene.hpp"
#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/raw_command.hpp"
#include "blackbird/raw_complaint.hpp"
#include "blackbird/raw_restart.hpp"
#include "blackbird/raw_runtime.hpp"
#include "blackbird/request_cache.hpp"
#include "coding_internal.hpp"
#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <set>

namespace blackbird {
using coding_detail::parse_id;
using coding_detail::program_origin;
using coding_detail::raw_native;
using coding_detail::raw_text;
namespace {
// Intentionally small supported schema: a flat object of scalar JSON types.
// Unsupported schema keywords reject rather than pretending to enforce them.
void validate_tool_schema(const Value &schema, RawProgramCall *trace = nullptr) {
  if (string_field(schema, "type") != "object")
    throw Error{ErrorCode::invalid_range};
  for (const auto &[k, v] : schema.object()) {
    (void)v;
    if (k != "type" && k != "properties" && k != "required" &&
        k != "additionalProperties")
      throw Error{ErrorCode::invalid_range};
  }
  const auto &properties = field(schema, "properties").object();
  if (properties.size() > 64)
    throw Error{ErrorCode::capacity};
  for (const auto &[key, property] : properties) {
    if (trace)
      trace->validation(3, properties.size());
    if (key.empty() || key.size() > 128)
      throw Error{ErrorCode::invalid_range};
    const auto &type = string_field(property, "type");
    if (type != "string" && type != "number" && type != "integer" &&
        type != "boolean" && type != "null")
      throw Error{ErrorCode::invalid_range};
    for (const auto &[k, v] : property.object()) {
      if (k != "type" && k != "description")
        throw Error{ErrorCode::invalid_range};
      if (k == "description" && v.string().size() > 4096)
        throw Error{ErrorCode::invalid_range};
    }
  }
  std::set<std::string> required;
  for (const auto &key : field(schema, "required").array()) {
    if (!field(schema, "properties").find(key.string()) ||
        !required.insert(key.string()).second)
      throw Error{ErrorCode::invalid_range};
  }
  if (std::get<bool>(field(schema, "additionalProperties").value()))
    throw Error{ErrorCode::invalid_range};
}
struct ToolValidation {
  const Value &schema;
  const Value &arguments;
};
void validate_tool_arguments(ToolValidation input) {
  const auto &schema = input.schema;
  const auto &args = input.arguments;
  for (const auto &key : field(schema, "required").array())
    if (!args.find(key.string()))
      throw Error{ErrorCode::invalid_range};
  for (const auto &[key, value] : args.object()) {
    const auto *property = field(schema, "properties").find(key);
    if (!property)
      throw Error{ErrorCode::invalid_range};
    const auto &type = string_field(*property, "type");
    bool ok =
        (type == "string" && std::holds_alternative<std::string>(value.value())) ||
        (type == "boolean" && std::holds_alternative<bool>(value.value())) ||
        (type == "null" && value == Value{}) ||
        (type == "number" && std::holds_alternative<Number>(value.value()));
    if (type == "integer" && std::holds_alternative<Number>(value.value())) {
      const auto &text = value.number().text();
      ok = text.find_first_of(".eE") == std::string::npos;
    }
    if (!ok)
      throw Error{ErrorCode::invalid_range};
  }
}
std::uint64_t command_number(const Value &value, std::string_view key,
                             std::uint64_t limit) {
  const auto *item = value.find(key);
  if (!item || !std::holds_alternative<Number>(item->value()))
    throw Error{ErrorCode::invalid_range};
  const auto text = item->number().text();
  std::uint64_t number = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number);
  if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
      number > limit)
    throw Error{ErrorCode::invalid_range};
  return number;
}
// A program that names no observation budget still gets an observation shaped at
// creation, matching the default coding workflow; more is an explicit request.
// Returns the keys it supplied so the operation record can name them.
std::vector<std::string> default_observation_budget(std::string_view name,
                                                    Value &arguments) {
  std::vector<std::string> supplied;
  if (!std::holds_alternative<Value::Object>(arguments.value()) ||
      arguments.find("output_max_bytes"))
    return supplied;
  const bool selected = arguments.find("range") || arguments.find("byte_start") ||
                        arguments.find("byte_end") || arguments.find("line_start") ||
                        arguments.find("line_end");
  const auto *op = arguments.find("op");
  const bool foreground = name == "process" && op && *op == Value{"foreground"};
  constexpr std::uint64_t budget = 8192, head = 2048, tail = budget - head;
  if (name == "read_process_output" && arguments.find("result_ref")) {
    // Fetch-back is a bounded page (design §5.7): 8192 bytes from the range's start,
    // ranged or not; only an explicit output_max_bytes asks for more (T1). A head
    // alone keeps the default 6144-byte tail after it, as an output_ref read does.
    const auto *requested = arguments.find("output_head_bytes");
    const auto shown =
        requested ? std::max(budget, command_number(arguments, "output_head_bytes",
                                                    16 * 1024 * 1024 - tail) +
                                         tail)
                  : budget;
    arguments.object().emplace_back("output_max_bytes", Value{Number{shown}});
    supplied.emplace_back("output_max_bytes");
  } else if (name == "exec" || foreground ||
             (name == "read_process_output" && !selected)) {
    // A head alone asks for more opening context; keep the default tail after it.
    const auto *requested = arguments.find("output_head_bytes");
    const auto shown =
        requested ? std::max(budget, command_number(arguments, "output_head_bytes",
                                                    16 * 1024 * 1024 - tail) +
                                         tail)
                  : budget;
    arguments.object().emplace_back("output_max_bytes", Value{Number{shown}});
    supplied.emplace_back("output_max_bytes");
    if (!requested) {
      arguments.object().emplace_back("output_head_bytes", Value{Number{head}});
      supplied.emplace_back("output_head_bytes");
    }
  } else if (name == "read_file" && !selected) {
    arguments.object().emplace_back("output_max_bytes",
                                    Value{Number{std::uint64_t{16384}}});
    supplied.emplace_back("output_max_bytes");
  }
  return supplied;
}
// Equal as the model sent them: object keys in any order (a Lua table round trip
// reorders them), everything else as Value equality.
bool equivalent(const Value &a, const Value &b) {
  if (a.same(b))
    return true;
  const auto *left = std::get_if<Value::Object>(&a.value());
  const auto *right = std::get_if<Value::Object>(&b.value());
  if (!left || !right) {
    const auto *first = std::get_if<Value::Array>(&a.value());
    const auto *second = std::get_if<Value::Array>(&b.value());
    if (!first || !second)
      return a == b;
    return first->size() == second->size() &&
           std::equal(first->begin(), first->end(), second->begin(), equivalent);
  }
  if (left->size() != right->size())
    return false;
  return std::all_of(left->begin(), left->end(), [&](const auto &entry) {
    const auto *other = b.find(entry.first);
    return other && equivalent(entry.second, *other);
  });
}
// Native tools that bound their own output: o17's process and file shapes, the paged
// readers of design §9 (their arguments choose the page) and the file-effect
// confirmations. Every other native tool's result is shaped generically (T1).
bool own_result_bound(std::string_view name) {
  constexpr std::array<std::string_view, 12> own{
      "exec",           "process",       "read_process_output",
      "read_file",      "write_file",    "edit_file",
      "context_read",   "audit_inspect", "trajectory_read",
      "variables_read", "tasks_read",    "git_observe"};
  return std::find(own.begin(), own.end(), name) != own.end();
}
} // namespace

namespace {
template <class Refused>
std::string program_encoded(RawProgramCall &trace, std::uint8_t kind,
                            const Value &value, Refused &&refused) {
  const ValueLimits limits{65536, 500000, 128};
  auto data = trace.data(49 + limits.bytes);
  const auto origin = trace.context();
  RawProgramCall encoding{3804, 3805, &origin,
                          std::array{raw_native(kind), raw_native(limits.bytes),
                                     raw_native(limits.nodes),
                                     raw_native(limits.depth)},
                          sizeof(bool)};
  auto encoded = encoding.run([&] {
    auto result = encode_packet_string(value, limits);
    const bool success = result.has_value();
    if (success)
      trace.encoded(kind, result.value(), data);
    encoding.finish(RawOperationBranch::returned, success ? nullptr : &result.error(),
                    std::array{raw_native(success)});
    return result;
  });
  if (!encoded.has_value() && encoded.error().code == ErrorCode::capacity)
    std::forward<Refused>(refused)();
  return unwrap(std::move(encoded));
}
template <class F>
bool program_syntax(RawProgramCall &trace, std::uint8_t kind, std::string_view source,
                    F &&validate) {
  trace.stage(4);
  const auto origin = trace.context();
  const auto size = source.size();
  RawProgramCall syntax{3807, 3808, &origin,
                        std::array{raw_native(kind), raw_native(size)}, sizeof(bool)};
  syntax.stage(4);
  return syntax.run([&] {
    const bool valid = std::forward<F>(validate)();
    syntax.finish(RawOperationBranch::returned, nullptr, std::array{raw_native(valid)});
    return valid;
  });
}
} // namespace

Value CodingEngine::program_config(const Value &arguments, DomainAdmission *admission) {
  const auto origin = program_origin(operation_trace_, generation_);
  RawProgramCall trace{arguments.find("proposal") ? std::uint8_t{2} : std::uint8_t{1},
                       &origin};
  return trace.run([&] {
    trace.stage(1);
    trace.revision(0, program_revision_);
    if (const auto *proposal = arguments.find("proposal")) {
      if (const auto *base = arguments.find("base");
          base && base->string() != program_revision_)
        throw Error{ErrorCode::conflict};
      for (const auto &[key, value] : proposal->object()) {
        (void)value;
        if (key != "modules" && key != "model" && key != "effort" &&
            key != "workflows" && key != "workflow_prefix" && key != "prompt_cache" &&
            key != "hooks")
          throw Error{ErrorCode::invalid_range};
      }
      const auto &model = string_field(*proposal, "model");
      const auto &effort = string_field(*proposal, "effort");
      if (model.size() > 256 ||
          (!effort.empty() && effort != "low" && effort != "medium" &&
           effort != "high" && effort != "xhigh" && effort != "max"))
        throw Error{ErrorCode::invalid_range};
      if (const auto *cache = proposal->find("prompt_cache"))
        (void)prompt_cache_mode(*cache);
      const auto &modules = field(*proposal, "modules").array();
      trace.stage(2);
      if (modules.size() > 32) {
        if (admission)
          admission->reject(AdmissionResource::program_modules, modules.size(), 32);
        throw Error{ErrorCode::capacity};
      }
      (void)program_encoded(trace, 0, *proposal, [&] {
        if (admission)
          admission->reject(AdmissionResource::program_encoding);
      });
      std::set<std::string> names;
      for (const auto &module : modules) {
        trace.stage(3);
        trace.validation(0, modules.size());
        const auto &name = string_field(module, "name");
        const auto &source = string_field(module, "source");
        if (module.object().size() != 2 || name.empty() || name.size() > 64 ||
            !std::all_of(name.begin(), name.end(),
                         [](char c) {
                           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                                  (c >= '0' && c <= '9') || c == '_' || c == '-' ||
                                  c == '.';
                         }) ||
            !names.insert(name).second || source.empty() || source.size() > 16384 ||
            !program_syntax(trace, 0, source,
                            [&] { return runtime_->valid_module_source(source); }))
          throw Error{ErrorCode::invalid_range};
      }
      const auto child_origin = trace.context();
      auto candidate_registry =
          std::make_shared<WorkflowRegistry>(*proposal, "candidate", &child_origin);
      for (const auto &d : candidate_registry->definitions().array())
        if (!program_syntax(trace, 1, string_field(d, "source"), [&] {
              return runtime_->valid_tool_source(string_field(d, "source"));
            }))
          throw Error{ErrorCode::invalid_range};
      auto candidate_hooks = std::make_shared<HookRegistry>(*proposal, "candidate");
      for (const auto &hook : candidate_hooks->definitions())
        if (!program_syntax(trace, 1, hook.source,
                            [&] { return runtime_->valid_hook_source(hook.source); }))
          throw Error{ErrorCode::invalid_range};
      // Copy/issue before publication; validation never executes candidate code.
      auto next = *proposal;
      if (trace.enabled() && !program_issuer_)
        program_issuer_ = RawProgramIssuer::prepare();
      RawProgramLifetime pending{trace.enabled() ? program_issuer_ : nullptr,
                                 trace.reference(), false};
      try {
        trace.stage(5);
        auto issued_credit = trace.control(57);
        const auto issued = unwrap(log_.root().issue<DefinitionGenerationId>());
        const std::uint8_t kind = 0;
        trace.event(3809, std::array{raw_native(kind), ByteView{issued.bytes()}},
                    issued_credit);
        pending.generation(issued.bytes());
        auto revision = hex_identity(issued.bytes());
        trace.stage(6);
        auto registry =
            std::make_shared<WorkflowRegistry>(next, revision, &child_origin);
        auto next_hooks = std::make_shared<HookRegistry>(next, revision);
        trace.stage(7);
        pending_program_trace_.finish(1);
        pending_workflows_ = std::move(registry);
        pending_hooks_ = std::move(next_hooks);
        pending_program_config_ = std::move(next);
        pending_program_revision_ = std::move(revision);
        pending.installed(pending_program_revision_);
        pending_program_trace_ = std::move(pending);
        if (hooks_changed)
          hooks_changed();
      } catch (const Error &error) {
        pending.finish(3, &error);
        throw;
      } catch (...) {
        pending.finish(3);
        throw;
      }
    }
    trace.stage(8);
    return Value::object(
        {{"revision", Value{program_revision_}},
         {"effective", program_config_},
         {"pending", pending_program_config_},
         {"launch_defaults",
          Value::object({{"model", Value{model_}}, {"effort", Value{effort_}}})},
         {"tools", tool_registry()},
         {"request_defaults",
          Value::object(
              {{"model", Value{string_field(program_config_, "model").empty()
                                   ? model_
                                   : string_field(program_config_, "model")}},
               {"effort", Value{string_field(program_config_, "effort").empty()
                                    ? effort_
                                    : string_field(program_config_, "effort")}}})},
         {"governing_workflow",
          Value::object(
              {{"generation", Value{hex_identity(generation_.bytes())}},
               {"source",
                Value{"retained program.source; selected workflow file is read "
                      "at turn admission"}},
               {"selection",
                Value{"--workflow or /workflow; no staged selector in this API"}}})},
         {"pending_revision", pending_program_config_ == Value{}
                                  ? Value{}
                                  : Value{pending_program_revision_}},
         {"staged", Value{arguments.find("proposal") != nullptr}},
         {"activation", Value{"successful-workflow-boundary"}}});
  });
}
Value CodingEngine::module_source(const Value &arguments) {
  const auto origin = program_origin(operation_trace_, generation_);
  const std::uint8_t kind = 2;
  RawProgramCall trace{3815, 3816, &origin, std::array{raw_native(kind)}};
  return trace.run([&] {
    const auto &name = string_field(arguments, "name");
    auto body = trace.data(48 + name.size());
    trace.bytes(3817, name, body);
    for (const auto &module : field(program_config_, "modules").array())
      if (string_field(module, "name") == name)
        return Value::object({{"name", Value{name}},
                              {"source", field(module, "source")},
                              {"revision", Value{program_revision_}}});
    throw Error{ErrorCode::invalid_range};
  });
}
Value CodingEngine::tool_registry() const {
  const auto origin = program_origin(operation_trace_, generation_);
  const std::uint8_t kind = 1;
  RawProgramCall trace{3815, 3816, &origin, std::array{raw_native(kind)}};
  return trace.run([&] {
    return Value::object(
        {{"revision", Value{tools_revision_}},
         {"effective", lua_tools_},
         {"pending", pending_lua_tools_},
         {"pending_revision",
          pending_lua_tools_ == Value{} ? Value{} : Value{pending_tools_revision_}}});
  });
}
void CodingEngine::host_tools(HostToolCatalog catalog, HostToolCallback callback) {
  if (turn_running_ || host_tools_ || !callback)
    throw Error{ErrorCode::busy};
  const auto native = tool_definitions();
  for (const auto &entry : native.array())
    if (catalog.find(string_field(entry, "name")))
      throw Error{ErrorCode::conflict};
  for (const auto *definitions : {&lua_tools_, &pending_lua_tools_}) {
    if (*definitions == Value{})
      continue;
    for (const auto &entry : definitions->array())
      if (catalog.find(string_field(entry, "name")))
        throw Error{ErrorCode::conflict};
  }
  const auto bytes = unwrap(encode_packet_string(catalog.native()));
  auto source = log_.original({"application.host.catalog", bytes,
                               Value::object({{"version", Value{Number{1}}}})});
  host_call_ = std::move(callback);
  host_tools_source_ = std::move(source);
  host_tools_ = std::move(catalog);
}
void CodingEngine::detach_host_tools() {
  if (turn_running_)
    throw Error{ErrorCode::busy};
  host_call_ = {};
  host_tools_.reset();
  host_tools_source_.clear();
}
Value CodingEngine::request_tools() const {
  const auto origin = program_origin(operation_trace_, generation_);
  const std::uint8_t kind = 3;
  RawProgramCall trace{3815, 3816, &origin, std::array{raw_native(kind)}};
  return trace.run([&] {
    auto result = tool_definitions();
    if (host_tools_) {
      const auto host = host_tools_->provider_tools();
      for (const auto &d : host.array())
        result.array().push_back(d);
    }
    for (const auto &d : lua_tools_.array())
      result.array().push_back(Value::object({{"type", Value{"function"}},
                                              {"name", field(d, "name")},
                                              {"description", field(d, "description")},
                                              {"parameters", field(d, "parameters")}}));
    return result;
  });
}
Value CodingEngine::define_tool(const Value &arguments) {
  const auto origin = program_origin(operation_trace_, generation_);
  RawProgramCall trace{4, &origin};
  return trace.run([&] {
    trace.stage(1);
    trace.revision(1, tools_revision_);
    if (const auto *base = arguments.find("base");
        base && base->string() != tools_revision_)
      throw Error{ErrorCode::conflict};
    const auto &definition = field(arguments, "definition");
    for (const auto &[k, v] : definition.object()) {
      (void)v;
      if (k != "name" && k != "description" && k != "parameters" && k != "source" &&
          k != "shape")
        throw Error{ErrorCode::invalid_range};
    }
    // How the tool's results are cut (T1): exec's budget keys, nothing else.
    if (const auto *shape = definition.find("shape")) {
      if (!std::holds_alternative<Value::Object>(shape->value()))
        throw Error{ErrorCode::invalid_range};
      for (const auto &[key, value] : shape->object()) {
        (void)value;
        if (key != "output_max_bytes" && key != "output_head_bytes")
          throw Error{ErrorCode::invalid_range};
      }
      (void)result_shape(*shape);
    }
    const auto &name = string_field(definition, "name");
    if (name.empty() || name.size() > 64 || name == "provider" ||
        !std::all_of(name.begin(), name.end(), [](char c) {
          return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        }))
      throw Error{ErrorCode::invalid_range};
    if (host_tools_ && host_tools_->find(name))
      throw Error{ErrorCode::conflict};
    const auto native_definitions = tool_definitions();
    for (const auto &d : native_definitions.array())
      if (string_field(d, "name") == name)
        throw Error{ErrorCode::conflict};
    const auto &description = string_field(definition, "description");
    const auto &source = string_field(definition, "source");
    if (description.empty() || description.size() > 4096 || source.empty() ||
        source.size() > 16384)
      throw Error{ErrorCode::invalid_range};
    trace.stage(3);
    validate_tool_schema(field(definition, "parameters"), &trace);
    if (!program_syntax(trace, 2, source,
                        [&] { return runtime_->valid_tool_source(source); }))
      throw Error{ErrorCode::invalid_range};
    auto next = pending_lua_tools_ == Value{} ? lua_tools_ : pending_lua_tools_;
    auto found =
        std::find_if(next.array().begin(), next.array().end(),
                     [&](const Value &d) { return string_field(d, "name") == name; });
    if (found == next.array().end())
      next.array().push_back(definition);
    else
      *found = definition;
    trace.stage(2);
    if (next.array().size() > 32 ||
        program_encoded(trace, 2, next, [] {}).size() > 65536)
      throw Error{ErrorCode::capacity};
    if (trace.enabled() && !program_issuer_)
      program_issuer_ = RawProgramIssuer::prepare();
    RawProgramLifetime pending{trace.enabled() ? program_issuer_ : nullptr,
                               trace.reference(), false, 1};
    try {
      trace.stage(5);
      auto issued_credit = trace.control(57);
      const auto issued = unwrap(log_.root().issue<DefinitionGenerationId>());
      const std::uint8_t kind = 1;
      trace.event(3809, std::array{raw_native(kind), ByteView{issued.bytes()}},
                  issued_credit);
      pending.generation(issued.bytes());
      auto revision = hex_identity(issued.bytes());
      trace.stage(7);
      pending_tools_trace_.finish(1);
      pending_lua_tools_ = std::move(next);
      pending_tools_revision_ = std::move(revision);
      pending.installed(pending_tools_revision_);
      pending_tools_trace_ = std::move(pending);
    } catch (const Error &error) {
      pending.finish(3, &error);
      throw;
    } catch (...) {
      pending.finish(3);
      throw;
    }
    trace.stage(8);
    auto result = tool_registry();
    result.object().emplace_back("staged", Value{true});
    return result;
  });
}

namespace {
std::uint64_t parse_block_id(const Value &v) {
  const auto *n = std::get_if<Number>(&v.value());
  if (!n || n->text().empty())
    throw Error{ErrorCode::invalid_range};
  std::uint64_t out = 0;
  const auto &s = n->text();
  const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
  if (r.ec != std::errc{} || r.ptr != s.data() + s.size() || out == 0)
    throw Error{ErrorCode::invalid_range};
  return out;
}
std::size_t parse_nonneg_size(const Value &v) {
  const auto *n = std::get_if<Number>(&v.value());
  if (!n || n->text().empty())
    throw Error{ErrorCode::invalid_range};
  std::size_t out = 0;
  const auto &s = n->text();
  const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
  if (r.ec != std::errc{} || r.ptr != s.data() + s.size())
    throw Error{ErrorCode::invalid_range};
  return out;
}
} // namespace

Value CodingEngine::context_list(bool include_archived) const {
  auto result = context_.list(include_archived);
  result.object().emplace_back("upstream_epoch", Value{Number{upstream_epoch_}});
  result.object().emplace_back("pending_edits",
                               Value{Number{pending_compactions_.size()}});
  if (telemetry_.context_window_tokens)
    result.object().emplace_back("context_window_tokens",
                                 Value{Number{*telemetry_.context_window_tokens}});
  return result;
}

Value CodingEngine::context_compact(const Value &arguments) {
  if (!std::holds_alternative<Value::Object>(arguments.value()))
    throw Error{ErrorCode::invalid_range};
  const auto &op_text = string_field(arguments, "op");
  if (op_text == "flush") {
    const auto flushed = flush_pending_compactions("operator");
    return Value::object({{"ok", Value{true}},
                          {"op", Value{"flush"}},
                          {"flushed", Value{Number{flushed}}},
                          {"upstream_epoch", Value{Number{upstream_epoch_}}}});
  }
  const auto op_parsed = parse_compact_op(op_text);
  if (!op_parsed)
    throw Error{ErrorCode::invalid_range};
  CompactRequest req;
  req.op = *op_parsed;
  if (const auto *ids = arguments.find("ids")) {
    if (!std::holds_alternative<Value::Array>(ids->value()))
      throw Error{ErrorCode::invalid_range};
    for (const auto &v : ids->array())
      req.ids.push_back(parse_block_id(v));
  }
  if (const auto *from = arguments.find("from"))
    req.from = parse_block_id(*from);
  if (const auto *to = arguments.find("to"))
    req.to = parse_block_id(*to);
  if (req.ids.empty() && !req.from.has_value() && !req.to.has_value())
    throw Error{ErrorCode::invalid_range};
  if (const auto *summary = arguments.find("summary")) {
    if (!std::holds_alternative<std::string>(summary->value()))
      throw Error{ErrorCode::invalid_range};
    req.summary = summary->string();
  }
  if (req.op == CompactOp::summarize && req.summary.empty())
    throw Error{ErrorCode::invalid_range};

  std::string apply = "auto";
  if (const auto *ap = arguments.find("apply")) {
    if (!std::holds_alternative<std::string>(ap->value()))
      throw Error{ErrorCode::invalid_range};
    apply = ap->string();
    if (apply != "auto" && apply != "now")
      throw Error{ErrorCode::invalid_range};
  }

  // pin/unpin do not alter wire bytes; restore is needed immediately.
  if (req.op == CompactOp::pin || req.op == CompactOp::unpin ||
      req.op == CompactOp::restore) {
    auto res = context_.compact(req);
    if (req.op == CompactOp::restore && res.find("ok") &&
        field(res, "ok") == Value{true}) {
      ++upstream_epoch_;
      res.object().emplace_back("upstream_epoch", Value{Number{upstream_epoch_}});
    }
    res.object().emplace_back("applied", Value{"now"});
    return res;
  }

  const auto now = std::chrono::steady_clock::now();
  const bool cache_warm = turn_running_ && last_provider_request_at_.has_value() &&
                          (now - *last_provider_request_at_) < cache_ttl_;
  if (apply == "auto" && cache_warm) {
    pending_compactions_.push_back(req);
    Value::Array queued;
    for (const auto id : req.ids)
      queued.push_back(Value{Number{id}});
    Value::Object out{{"ok", Value{true}},
                      {"op", Value{std::string{compact_op_name(req.op)}}},
                      {"applied", Value{"deferred"}},
                      {"pending_edits", Value{Number{pending_compactions_.size()}}},
                      {"note", Value{"Queued while prompt cache is warm; flushes "
                                     "automatically on cold cache, route switch, "
                                     "overflow, or turn end. Pass apply='now' to flush "
                                     "immediately and roll a fresh cache epoch."}}};
    if (!queued.empty())
      out.emplace_back("queued", Value{std::move(queued)});
    return Value::object(std::move(out));
  }

  // apply == "now" or cache is cold / outside a turn: apply immediately.
  auto res = context_.compact(req);
  if (res.find("ok") && field(res, "ok") == Value{true}) {
    ++upstream_epoch_;
    res.object().emplace_back("applied", Value{"now"});
    res.object().emplace_back("upstream_epoch", Value{Number{upstream_epoch_}});
    if (hooks_ && !hooks_->definitions().empty()) {
      const HookMatchSample sample{
          .event = HookEvent::context_compact, .tool = {}, .prompt = {}};
      const auto payload =
          Value::object({{"event", Value{"context_compact"}},
                         {"op", Value{std::string{compact_op_name(req.op)}}},
                         {"upstream_epoch", Value{Number{upstream_epoch_}}},
                         {"live_blocks", Value{Number{context_.blocks().size()}}},
                         {"total_bytes", Value{Number{context_.total_bytes()}}}});
      (void)run_hooks(sample, payload);
    }
  }
  return res;
}

Value CodingEngine::context_read(const Value &arguments) const {
  if (!std::holds_alternative<Value::Object>(arguments.value()))
    throw Error{ErrorCode::invalid_range};
  const auto id = parse_block_id(field(arguments, "id"));
  ReadBlockOptions opts;
  if (const auto *off = arguments.find("offset"))
    opts.offset = parse_nonneg_size(*off);
  if (const auto *lim = arguments.find("limit"))
    opts.limit = parse_nonneg_size(*lim);
  return context_.read_block(id, opts);
}

namespace {
bool tool_result_aging_disabled() noexcept {
  const char *env = std::getenv("BLACKBIRD_DISABLE_TOOL_AGING");
  return env != nullptr && std::string_view{env} == "1";
}

bool is_failed_tool_output_value(const Value &out) noexcept {
  if (coding_detail::failed_tool_output(out))
    return true;
  if (const auto *str = std::get_if<std::string>(&out.value());
      str != nullptr && str->size() <= 65536 && !str->empty() && str->front() == '{') {
    if (auto parsed = parse_json(*str); parsed.has_value())
      return coding_detail::failed_tool_output(parsed.value());
  }
  return false;
}

std::string extract_tool_output_preview(const Value &out) {
  constexpr std::size_t kPreviewCap = 256;
  if (const auto *str = std::get_if<std::string>(&out.value()))
    return str->substr(0, std::min(str->size(), kPreviewCap));
  if (std::holds_alternative<Value::Object>(out.value())) {
    for (const std::string_view key : {"error", "output", "content", "message"}) {
      if (const auto *val = out.find(key)) {
        if (const auto *str = std::get_if<std::string>(&val->value());
            str != nullptr && !str->empty()) {
          return str->substr(0, std::min(str->size(), kPreviewCap));
        }
      }
    }
  }
  if (auto dumped = dump_json(out, {65536, 4096, 16}); dumped.has_value())
    return dumped.value().substr(0, std::min(dumped.value().size(), kPreviewCap));
  return "(structured tool output)";
}

bool has_nonempty_assistant_message(const Value &item) noexcept {
  const auto *role = item.find("role");
  const auto *type = item.find("type");
  const bool is_assistant_role = role != nullptr &&
                                 std::holds_alternative<std::string>(role->value()) &&
                                 role->string() == "assistant";
  const bool is_message_type = type != nullptr &&
                               std::holds_alternative<std::string>(type->value()) &&
                               type->string() == "message";
  if (!is_assistant_role &&
      !(is_message_type && (role == nullptr || is_assistant_role))) {
    return false;
  }
  const auto *content = item.find("content");
  if (!content)
    return false;
  if (const auto *text = std::get_if<std::string>(&content->value()))
    return !text->empty();
  if (const auto *parts = std::get_if<Value::Array>(&content->value())) {
    for (const auto &part : *parts) {
      if (const auto *t = part.find("text");
          t && std::holds_alternative<std::string>(t->value()) &&
          !t->string().empty()) {
        return true;
      }
    }
  }
  return false;
}

std::optional<std::uint64_t> parse_optional_u64_field(const Value &obj,
                                                      std::string_view key) noexcept {
  const auto *item = obj.find(key);
  if (!item)
    return std::nullopt;
  const auto *num = std::get_if<Number>(&item->value());
  if (!num)
    return std::nullopt;
  const std::string text = num->text();
  if (text.empty())
    return std::nullopt;
  std::uint64_t parsed = 0;
  const auto res = std::from_chars(text.data(), text.data() + text.size(), parsed);
  if (res.ec != std::errc{} || res.ptr != text.data() + text.size())
    return std::nullopt;
  return parsed;
}

std::vector<CompactRequest> build_tool_aging_requests(const ContextStore &context) {
  std::vector<ContextEntryView> entries;
  std::map<std::string, std::string> call_id_to_tool;
  std::uint64_t turn_counter = 0;

  for (const auto &block : context.blocks()) {
    // Always record call_id -> tool_name mappings across blocks so split
    // function_call_output blocks resolve their actual tool name.
    for (const auto &item : block.items) {
      const auto *type = item.find("type");
      if (!type || !std::holds_alternative<std::string>(type->value()) ||
          type->string() != "function_call") {
        continue;
      }
      const auto *cid = item.find("call_id");
      const auto *n = item.find("name");
      if (cid && n && std::holds_alternative<std::string>(cid->value()) &&
          std::holds_alternative<std::string>(n->value()) && !cid->string().empty() &&
          !n->string().empty()) {
        call_id_to_tool[cid->string()] = n->string();
      }
    }

    if (block.kind == BlockKind::instruction) {
      bool is_user_turn = (block.label == "operator");
      if (!is_user_turn) {
        for (const auto &item : block.items) {
          if (const auto *role = item.find("role");
              role && std::holds_alternative<std::string>(role->value()) &&
              role->string() == "user") {
            is_user_turn = true;
            break;
          }
        }
      }
      if (is_user_turn)
        ++turn_counter;
      continue;
    }
    if (block.open || block.kind == BlockKind::note)
      continue;

    bool has_tool_output = false;
    bool has_assistant_prose = false;
    bool has_failed_output = false;
    std::string tool_name;
    std::string preview;
    for (const auto &item : block.items) {
      if (has_nonempty_assistant_message(item))
        has_assistant_prose = true;
      const auto *type = item.find("type");
      if (!type || !std::holds_alternative<std::string>(type->value()))
        continue;
      if (type->string() == "function_call" && tool_name.empty()) {
        if (const auto *n = item.find("name");
            n && std::holds_alternative<std::string>(n->value())) {
          tool_name = n->string();
        }
      } else if (type->string() == "function_call_output") {
        has_tool_output = true;
        if (tool_name.empty()) {
          if (const auto *cid = item.find("call_id");
              cid && std::holds_alternative<std::string>(cid->value())) {
            if (const auto it = call_id_to_tool.find(cid->string());
                it != call_id_to_tool.end()) {
              tool_name = it->second;
            }
          }
        }
        if (const auto *out = item.find("output")) {
          if (is_failed_tool_output_value(*out))
            has_failed_output = true;
          if (preview.empty())
            preview = extract_tool_output_preview(*out);
        }
      }
    }
    if (!has_tool_output || has_assistant_prose)
      continue;

    const std::uint64_t entry_turn =
        turn_counter > 0 ? turn_counter
                         : static_cast<std::uint64_t>(entries.size() + 1);
    ContextEntryView view;
    view.entry_id = std::to_string(block.id);
    view.kind = "function_call_output";
    view.tool_name = tool_name.empty() ? "tool" : std::move(tool_name);
    view.turn_index = entry_turn;
    view.bytes = static_cast<std::size_t>(block.bytes);
    view.pinned = block.pinned;
    view.already_stubbed = is_aged_tool_stub(preview);
    view.failed = has_failed_output;
    view.preview = std::move(preview);
    entries.push_back(std::move(view));
  }

  if (entries.empty())
    return {};
  const std::uint64_t current_turn =
      turn_counter > 0 ? turn_counter : static_cast<std::uint64_t>(entries.size());
  const ToolAgingPlan plan = plan_tool_result_aging(entries, current_turn);
  return plan.compact_requests();
}
} // namespace

std::size_t CodingEngine::flush_pending_compactions(std::string_view reason) {
  auto queued = std::move(pending_compactions_);
  pending_compactions_.clear();
  std::size_t applied = 0;
  for (const auto &req : queued) {
    const auto res = context_.compact(req);
    if (res.find("ok") && field(res, "ok") == Value{true})
      ++applied;
  }

  // Lossless turn-end / overflow tool-result aging: replaces old unpinned tool-result
  // blocks with deterministic 1-line stubs while originals stay verbatim in AuditLog.
  std::size_t aged_applied = 0;
  if (!operator_call_ && (reason == "turn end" || reason == "overflow") &&
      !tool_result_aging_disabled()) {
    const auto aging_requests = build_tool_aging_requests(context_);
    for (const auto &req : aging_requests) {
      const auto res = context_.compact(req);
      if (res.find("ok") && field(res, "ok") == Value{true}) {
        ++applied;
        ++aged_applied;
      }
    }
  }

  if (applied > 0) {
    ++upstream_epoch_;
    if (!reason.empty() && (notice || display)) {
      std::string summary;
      if (aged_applied > 0 && aged_applied == applied) {
        summary = "\n[aged " + std::to_string(aged_applied) +
                  " old tool result(s) on " + std::string{reason} +
                  "; upstream epoch " + std::to_string(upstream_epoch_) + "]\n";
      } else {
        summary = "\n[applied " + std::to_string(applied) +
                  " deferred compaction(s) on " + std::string{reason} +
                  "; upstream epoch " + std::to_string(upstream_epoch_) + "]\n";
      }
      (notice ? notice : display)(summary);
    }
    if (hooks_ && !hooks_->definitions().empty()) {
      const HookMatchSample sample{
          .event = HookEvent::context_compact, .tool = {}, .prompt = {}};
      const auto payload =
          Value::object({{"event", Value{"context_compact"}},
                         {"op", Value{"flush"}},
                         {"flushed", Value{Number{applied}}},
                         {"aged", Value{Number{aged_applied}}},
                         {"reason", Value{std::string{reason}}},
                         {"upstream_epoch", Value{Number{upstream_epoch_}}},
                         {"live_blocks", Value{Number{context_.blocks().size()}}},
                         {"total_bytes", Value{Number{context_.total_bytes()}}}});
      (void)run_hooks(sample, payload);
    }
  }
  return applied;
}

void CodingEngine::record_hook_dispatch(HookDispatchRecord record) {
  record.sequence = ++hook_sequence_;
  try {
    (void)log_.record(ApplicationChannel::program,
                      Value::object({{"label", Value{"hook.dispatch"}},
                                     {"dispatch", record.to_value()}}));
  } catch (...) {
  }
  if (hook_history_.size() >= 64)
    hook_history_.pop_front();
  hook_history_.push_back(std::move(record));
  if (hooks_changed)
    hooks_changed();
}

std::optional<CodingEngine::HookDenial>
CodingEngine::run_hooks(const HookMatchSample &sample, const Value &payload) {
  if (!hooks_ || hooks_->definitions().empty())
    return std::nullopt;
  const auto active_registry = hooks_;
  const auto matches = active_registry->matching(sample);
  if (matches.empty())
    return std::nullopt;
  if (hook_depth_ >= 2) {
    for (const auto *def : matches) {
      record_hook_dispatch({.sequence = 0,
                            .hook_name = def->name,
                            .revision = active_registry->revision(),
                            .event = def->event,
                            .kind = def->kind,
                            .outcome = HookOutcome::skipped,
                            .detail = "reentrant",
                            .duration_ms = 0});
    }
    return std::nullopt;
  }

  ++hook_depth_;
  struct DepthGuard {
    unsigned &depth;
    ~DepthGuard() { --depth; }
  } depth_guard{hook_depth_};

  for (const auto *def : matches) {
    const auto started = std::chrono::steady_clock::now();
    const auto elapsed_ms = [&] {
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - started)
                          .count();
      return static_cast<std::uint64_t>(ms > 0 ? ms : 0);
    };
    try {
      Runtime child{*this};
      const Value result = child.invoke_hook(def->source, payload);
      if (def->kind == HookKind::admission && sample.event == HookEvent::before_tool) {
        bool allow = true;
        std::string reason;
        if (std::holds_alternative<bool>(result.value())) {
          allow = std::get<bool>(result.value());
          if (!allow)
            reason = "denied by hook " + def->name;
        } else if (std::holds_alternative<Value::Object>(result.value())) {
          if (const auto *a = result.find("allow");
              a && std::holds_alternative<bool>(a->value()))
            allow = std::get<bool>(a->value());
          if (const auto *r = result.find("reason");
              r && std::holds_alternative<std::string>(r->value()))
            reason = r->string();
          if (!allow && reason.empty())
            reason = "denied by hook " + def->name;
        }
        if (!allow) {
          record_hook_dispatch({.sequence = 0,
                                .hook_name = def->name,
                                .revision = active_registry->revision(),
                                .event = def->event,
                                .kind = def->kind,
                                .outcome = HookOutcome::matched_denied,
                                .detail = reason,
                                .duration_ms = elapsed_ms()});
          return HookDenial{.hook = def->name, .reason = std::move(reason)};
        }
      } else if (def->kind == HookKind::context_transform &&
                 std::holds_alternative<Value::Object>(result.value())) {
        if (const auto *append = result.find("append");
            append && std::holds_alternative<Value::Array>(append->value()) &&
            !append->array().empty()) {
          (void)context_.append(append->array(), "hook:" + def->name, BlockKind::note);
        }
      }
      std::string detail;
      if (std::holds_alternative<Value::Object>(result.value())) {
        if (const auto *note = result.find("note");
            note && std::holds_alternative<std::string>(note->value()))
          detail = note->string();
      } else if (std::holds_alternative<std::string>(result.value())) {
        detail = result.string();
      }
      if (detail.size() > 256)
        detail.resize(256);
      record_hook_dispatch({.sequence = 0,
                            .hook_name = def->name,
                            .revision = active_registry->revision(),
                            .event = def->event,
                            .kind = def->kind,
                            .outcome = HookOutcome::matched_ok,
                            .detail = std::move(detail),
                            .duration_ms = elapsed_ms()});
    } catch (const Error &err) {
      const std::string msg = std::string{error_name(err.code)};
      record_hook_dispatch({.sequence = 0,
                            .hook_name = def->name,
                            .revision = active_registry->revision(),
                            .event = def->event,
                            .kind = def->kind,
                            .outcome = HookOutcome::matched_failed,
                            .detail = msg,
                            .duration_ms = elapsed_ms()});
      if (notice)
        notice("\n[hook " + def->name + " failed: " + msg + "]\n");
      if (def->kind == HookKind::admission && sample.event == HookEvent::before_tool) {
        return HookDenial{.hook = def->name, .reason = "admission hook error: " + msg};
      }
    } catch (const std::exception &err) {
      std::string msg = err.what();
      if (msg.size() > 256)
        msg.resize(256);
      record_hook_dispatch({.sequence = 0,
                            .hook_name = def->name,
                            .revision = active_registry->revision(),
                            .event = def->event,
                            .kind = def->kind,
                            .outcome = HookOutcome::matched_failed,
                            .detail = msg,
                            .duration_ms = elapsed_ms()});
      if (notice)
        notice("\n[hook " + def->name + " failed: " + msg + "]\n");
      if (def->kind == HookKind::admission && sample.event == HookEvent::before_tool) {
        return HookDenial{.hook = def->name, .reason = "admission hook error: " + msg};
      }
    }
  }
  return std::nullopt;
}

Value CodingEngine::hooks_tool(const Value &arguments) {
  if (!std::holds_alternative<Value::Object>(arguments.value()))
    throw Error{ErrorCode::invalid_range};
  std::string op = "list";
  if (const auto *op_val = arguments.find("op")) {
    if (!std::holds_alternative<std::string>(op_val->value()))
      throw Error{ErrorCode::invalid_range};
    op = op_val->string();
  }
  if (op == "list") {
    return Value::object(
        {{"revision", Value{hooks_ ? hooks_->revision() : program_revision_}},
         {"pending_revision",
          pending_hooks_ ? Value{pending_hooks_->revision()} : Value{}},
         {"hooks", hooks_ ? hooks_->definitions_value() : Value{Value::Array{}}},
         {"pending_hooks",
          pending_hooks_ ? pending_hooks_->definitions_value() : Value{}},
         {"history_count", Value{Number{hook_history_.size()}}}});
  }
  if (op == "history") {
    std::size_t limit = 64;
    if (arguments.find("limit"))
      limit = static_cast<std::size_t>(command_number(arguments, "limit", 64));
    if (limit == 0)
      throw Error{ErrorCode::invalid_range};
    Value::Array items;
    const auto start =
        hook_history_.size() > limit ? hook_history_.size() - limit : std::size_t{0};
    for (std::size_t i = start; i < hook_history_.size(); ++i)
      items.push_back(hook_history_[i].to_value());
    return Value::object(
        {{"count", Value{Number{items.size()}}}, {"history", Value{std::move(items)}}});
  }
  if (op == "explain") {
    const auto parsed_event = parse_hook_event(string_field(arguments, "event"));
    if (!parsed_event)
      throw Error{ErrorCode::invalid_range};
    HookMatchSample sample{.event = *parsed_event, .tool = {}, .prompt = {}};
    if (const auto *tool = arguments.find("tool")) {
      if (!std::holds_alternative<std::string>(tool->value()))
        throw Error{ErrorCode::invalid_range};
      sample.tool = tool->string();
    }
    if (const auto *prompt = arguments.find("prompt")) {
      if (!std::holds_alternative<std::string>(prompt->value()))
        throw Error{ErrorCode::invalid_range};
      sample.prompt = prompt->string();
    }
    Value::Array results;
    if (hooks_) {
      for (const auto &ex : hooks_->explain(sample))
        results.push_back(ex.to_value());
    }
    return Value::object(
        {{"revision", Value{hooks_ ? hooks_->revision() : program_revision_}},
         {"event", Value{std::string{hook_event_name(sample.event)}}},
         {"matches", Value{std::move(results)}}});
  }
  if (op == "enable" || op == "disable") {
    const auto &name = string_field(arguments, "name");
    const bool target_enabled = op == "enable";
    const Value &source_config =
        pending_program_config_ == Value{} ? program_config_ : pending_program_config_;
    const auto *existing_hooks = source_config.find("hooks");
    if (!existing_hooks ||
        !std::holds_alternative<Value::Array>(existing_hooks->value()))
      throw Error{ErrorCode::invalid_range};
    Value::Array updated_hooks;
    bool found = false;
    for (const auto &entry : existing_hooks->array()) {
      if (string_field(entry, "name") == name) {
        found = true;
        Value::Object copy;
        bool had_enabled = false;
        for (const auto &[k, v] : entry.object()) {
          if (k == "enabled") {
            copy.emplace_back(k, Value{target_enabled});
            had_enabled = true;
          } else {
            copy.emplace_back(k, v);
          }
        }
        if (!had_enabled)
          copy.emplace_back("enabled", Value{target_enabled});
        updated_hooks.push_back(Value::object(std::move(copy)));
      } else {
        updated_hooks.push_back(entry);
      }
    }
    if (!found)
      throw Error{ErrorCode::invalid_range};
    Value::Object proposal;
    for (const auto &[k, v] : source_config.object()) {
      if (k != "hooks")
        proposal.emplace_back(k, v);
    }
    proposal.emplace_back("hooks", Value{std::move(updated_hooks)});
    auto staged = program_config(
        Value::object({{"proposal", Value::object(std::move(proposal))}}));
    staged.object().emplace_back("hook", Value{name});
    staged.object().emplace_back("enabled", Value{target_enabled});
    return staged;
  }
  throw Error{ErrorCode::invalid_range};
}

bool CodingEngine::auto_compact_for_overflow() {
  const auto before_bytes = context_.total_bytes();
  if (!pending_compactions_.empty()) {
    (void)flush_pending_compactions("overflow");
    if (context_.total_bytes() < before_bytes)
      return true;
  }
  const auto &blocks = context_.blocks();
  const bool anthropic = provider_->provider_identity() == "anthropic-messages" ||
                         provider_->provider_identity().starts_with("anthropic");
  std::vector<std::uint64_t> removable;
  for (const auto &b : blocks) {
    if (b.open || b.pinned || b.kind == BlockKind::instruction)
      continue;
    removable.push_back(b.id);
  }
  if (removable.empty())
    return false;
  const std::size_t drop_count = std::max<std::size_t>(1, (removable.size() + 1) / 2);
  removable.resize(drop_count);
  if (anthropic && !removable.empty()) {
    std::set<std::uint64_t> dropping(removable.begin(), removable.end());
    auto first_remaining_is_user = [&] {
      for (const auto &b : blocks) {
        if (dropping.contains(b.id))
          continue;
        for (const auto &item : b.items) {
          if (const auto *type = item.find("type"); type && *type == Value{"reasoning"})
            continue;
          const auto *role = item.find("role");
          return role != nullptr &&
                 (*role == Value{"user"} || *role == Value{"developer"} ||
                  *role == Value{"system"});
        }
      }
      return false;
    };
    while (!removable.empty() && !first_remaining_is_user()) {
      dropping.erase(removable.front());
      removable.erase(removable.begin());
    }
  }
  if (removable.empty())
    return false;
  CompactRequest drop_req;
  drop_req.ids = std::move(removable);
  drop_req.op = CompactOp::drop;
  const auto res = context_.compact(drop_req);
  if (res.find("ok") && field(res, "ok") == Value{true}) {
    ++upstream_epoch_;
    return true;
  }
  return false;
}

Value CodingEngine::retained_process_output(const Value &arguments) {
  const auto &reference = string_field(arguments, "output_ref");
  auto read_credit = raw_command_claim(58);
  const auto reference_size = reference.size();
  const std::uint8_t mode = 2;
  const auto request =
      raw_command_data(2037, std::array{detail::raw_native_field(reference_size),
                                        detail::raw_string_field(reference),
                                        detail::raw_native_field(mode)});
  bool known = command_jobs_->contains(reference);
  std::string raw;
  try {
    // Index only newly committed metadata; keep locators, never resident output bodies.
    for (; process_original_cursor_ < log_.root().fact_count();
         ++process_original_cursor_) {
      const auto fact = unwrap(log_.root().fact(process_original_cursor_));
      const auto *record = std::get_if<ApplicationRecordEvent>(&fact.event.body);
      if (!record || record->channel != ApplicationChannel::log)
        continue;
      const auto packet = unwrap(read_packet(record->payload));
      const auto &label = string_field(packet, "label");
      if (label != "operation.result" && label != "process.output")
        continue;
      const auto &metadata = field(packet, "metadata");
      const auto *old_attempt = metadata.find("attempt");
      if (!old_attempt)
        continue;
      if (label == "operation.result") {
        const auto *op = metadata.find("operation");
        if (op && op->string() == "exec")
          process_originals_[old_attempt->string()].known = true;
      } else {
        auto &entry = process_originals_[old_attempt->string()];
        // Reserve before mutating: an allocation failure must not duplicate chunks
        // when this fact is encountered again.
        if (fact.event.dependencies.size() >
            entry.chunks.max_size() - entry.chunks.size())
          throw Error{ErrorCode::capacity};
        const auto required = entry.chunks.size() + fact.event.dependencies.size();
        if (required > entry.chunks.capacity()) {
          const auto grown = entry.chunks.capacity() <= entry.chunks.max_size() / 2
                                 ? entry.chunks.capacity() * 2
                                 : entry.chunks.max_size();
          entry.chunks.reserve(std::max(required, grown));
        }
        for (const auto dependency : fact.event.dependencies)
          entry.chunks.emplace_back(fact.record, dependency);
        entry.known = true;
      }
    }
    if (const auto found = process_originals_.find(reference);
        found != process_originals_.end()) {
      known = known || found->second.known;
      for (const auto &[record, dependency] : found->second.chunks) {
        auto source_credit = raw_command_claim(96);
        const auto bytes = unwrap(log_.root().source(dependency));
        const auto source_size = bytes.size();
        (void)raw_command_linked(
            2038, request,
            std::array{ByteView{record.journal.bytes()},
                       detail::raw_native_field(record.sequence),
                       ByteView{dependency.journal.bytes()},
                       detail::raw_native_field(dependency.sequence),
                       detail::raw_native_field(source_size)},
            source_credit ? &*source_credit : nullptr);
        raw.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
      }
    }
    if (!known)
      throw Error{ErrorCode::invalid_range};
    auto result = process_output_presentation(raw, arguments);
    const std::uint8_t branch = 1;
    const Error error{};
    const auto source_size = raw.size();
    (void)raw_command_linked(2039, request,
                             std::array{detail::raw_native_field(branch),
                                        detail::raw_native_field(error.code),
                                        detail::raw_native_field(error.detail),
                                        detail::raw_native_field(source_size)},
                             read_credit ? &*read_credit : nullptr);
    return result;
  } catch (const Error &error) {
    const std::uint8_t branch = 2;
    const auto source_size = raw.size();
    (void)raw_command_linked(2039, request,
                             std::array{detail::raw_native_field(branch),
                                        detail::raw_native_field(error.code),
                                        detail::raw_native_field(error.detail),
                                        detail::raw_native_field(source_size)},
                             read_credit ? &*read_credit : nullptr);
    throw;
  } catch (...) {
    const std::uint8_t branch = 3;
    const Error error{ErrorCode::allocation};
    const auto source_size = raw.size();
    (void)raw_command_linked(2039, request,
                             std::array{detail::raw_native_field(branch),
                                        detail::raw_native_field(error.code),
                                        detail::raw_native_field(error.detail),
                                        detail::raw_native_field(source_size)},
                             read_credit ? &*read_credit : nullptr);
    throw;
  }
}
// The full original behind a shaped result (T1): the operation.result record named by
// result_ref, read by identity (also from the archive) and paged as the same text the
// shaping measured, with read_process_output's ranges and budgets.
Value CodingEngine::retained_result_output(const Value &arguments) {
  const auto *reference = arguments.find("result_ref");
  if (arguments.find("output_ref") || !reference ||
      !std::holds_alternative<std::string>(reference->value()))
    throw Error{ErrorCode::invalid_range};
  if (arguments.find("output_max_bytes")) // At most 16777216 per page.
    (void)command_number(arguments, "output_max_bytes", 16 * 1024 * 1024);
  const auto &ref = reference->string();
  if (ref.empty())
    throw Error{ErrorCode::invalid_range};
  if (ref != cached_result_ref_) {
    const auto identity = [&] {
      try {
        return parse_id<ApplicationRecordId>(ref);
      } catch (const Error &) {
        throw Error{ErrorCode::invalid_range};
      }
    }();
    auto &root = log_.root();
    const auto fact =
        root.lookup(root.visible(), 1, RetainedKind::application, identity.bytes());
    if (!fact)
      throw Error{ErrorCode::invalid_range};
    const auto *record = std::get_if<ApplicationRecordEvent>(&fact->event.body);
    if (!record || record->identity != identity ||
        record->channel != ApplicationChannel::log ||
        fact->event.dependencies.size() != 1)
      throw Error{ErrorCode::invalid_range};
    const auto packet = unwrap(read_packet(record->payload));
    const auto &label = string_field(packet, "label");
    if (label != "operation.result" && label != "application.observations")
      throw Error{ErrorCode::invalid_range};
    const auto source = unwrap(root.source(fact->event.dependencies.front()));
    // One decoded original per turn: paging it does not decode it again.
    cached_result_ref_.clear();
    cached_result_text_.clear();
    const auto decoded = unwrap(decode_packet(source));
    if (const auto *string = std::get_if<std::string>(&decoded.value());
        string && valid_utf8(*string))
      cached_result_text_ = *string;
    else if (auto text = dump_json(decoded, result_text_limits); text.has_value())
      cached_result_text_ = std::move(text).value();
    else // No text form within the provider limits: a recorded refusal.
      throw Error{ErrorCode::unsupported};
    cached_result_ref_ = ref;
  }
  return process_output_presentation(cached_result_text_, arguments);
}
void CodingEngine::note_answered(const Value::Array &items) {
  for (const auto &item : items) {
    const auto *type = item.find("type");
    const auto *call = item.find("call_id");
    if (!type || *type != Value{"function_call_output"} || !call ||
        !std::holds_alternative<std::string>(call->value()))
      continue;
    if (const auto found = model_calls_.find(call->string());
        found != model_calls_.end()) {
      answered_calls_.insert(found->first);
      model_calls_.erase(found);
    }
  }
}
Value CodingEngine::dispatch(std::string name, Value arguments, const Value &options) {
  if (name == "provider")
    throw Error{ErrorCode::invalid_range};
  // The operator's own call stays exact; anything it nests (a lua program, a
  // workflow's model loop) is a program observation again.
  const bool exact = operator_call_ && operation_depth_ == 0;
  auto supplied =
      exact ? std::vector<std::string>{} : default_observation_budget(name, arguments);
  // Generic shaping (T1) happens once, where a result becomes visible to the model:
  // the output of the model's own function call. A program's own calls (any nesting)
  // return whole results; o17's native defaults above still apply to them. A call is
  // the model's when it dispatches an unclaimed model call by name and arguments.
  std::optional<ResultShape> shape;
  std::string call_id, refusal, declared_id;
  bool shape_refused = false;
  bool model_explicit_budget = false;
  if (options != Value{}) {
    // A relay declares the model call it answers: a recorded call no output has
    // answered yet. Anything else is refused and recorded with its reason.
    const auto *fields = std::get_if<Value::Object>(&options.value());
    const auto *declared =
        fields && fields->size() == 1 ? options.find("call_id") : nullptr;
    if (!declared || !std::holds_alternative<std::string>(declared->value()))
      throw Error{ErrorCode::invalid_range};
    declared_turn_ = true;
    const auto &id = declared->string();
    declared_id = id;
    if (const auto found = model_calls_.find(id); found != model_calls_.end()) {
      found->second.dispatched = true;
      call_id = id;
      model_explicit_budget =
          std::holds_alternative<Value::Object>(found->second.arguments.value()) &&
          (found->second.arguments.find("output_max_bytes") != nullptr ||
           found->second.arguments.find("output_head_bytes") != nullptr);
    } else
      refusal = answered_calls_.contains(id) ? "call_id_answered" : "call_id_unknown";
  } else if (!exact && !declared_turn_) {
    // Undeclared: the first undispatched model call with this name and equivalent
    // arguments, until the turn's dispatcher declares.
    auto claimed = model_calls_.end();
    for (auto entry = model_calls_.begin(); entry != model_calls_.end(); ++entry) {
      const auto &candidate = entry->second;
      if (!candidate.dispatched && candidate.generation > boundary_floor_ &&
          candidate.name == name && equivalent(candidate.arguments, arguments) &&
          (claimed == model_calls_.end() ||
           candidate.sequence < claimed->second.sequence))
        claimed = entry;
    }
    if (claimed != model_calls_.end()) {
      claimed->second.dispatched = true;
      call_id = claimed->first;
      model_explicit_budget =
          std::holds_alternative<Value::Object>(claimed->second.arguments.value()) &&
          (claimed->second.arguments.find("output_max_bytes") != nullptr ||
           claimed->second.arguments.find("output_head_bytes") != nullptr);
    }
  }
  const bool model_call = !call_id.empty();
  // A Lua-defined tool's arguments are its own: its shape comes only from its
  // definition. A native tool's budget keys never reach its body; the operation input
  // keeps them as requested.
  Value requested;
  bool stripped = false;
  const auto lua_tool =
      std::find_if(lua_tools_.array().begin(), lua_tools_.array().end(),
                   [&](const Value &d) { return string_field(d, "name") == name; });
  if (lua_tool != lua_tools_.array().end()) {
    if (model_call) {
      try {
        const auto *declared = lua_tool->find("shape");
        shape = declared ? result_shape(*declared) : ResultShape{};
      } catch (const Error &) {
        shape_refused = true;
      }
    }
  } else if (!own_result_bound(name)) {
    const bool object = std::holds_alternative<Value::Object>(arguments.value());
    const bool keys = object && (arguments.find("output_max_bytes") ||
                                 arguments.find("output_head_bytes"));
    if (model_call) {
      try {
        shape = result_shape(object ? arguments : Value::object({}));
      } catch (const Error &) {
        shape_refused = true;
      }
      if (!keys)
        supplied = {"output_max_bytes", "output_head_bytes"};
    }
    if (keys) {
      // Shares the argument values (copy-on-write storage); only the top-level entry
      // list without the two keys is built.
      requested = std::move(arguments);
      stripped = true;
      Value::Object rest;
      for (const auto &entry : std::as_const(requested).object())
        if (entry.first != "output_max_bytes" && entry.first != "output_head_bytes")
          rest.push_back(entry);
      arguments = Value::object(std::move(rest));
    }
  }
  const auto continuation_shape = shape;
  // Shape a job's result from its retained originals within the selected budget.
  const auto shaped = [this, model_call, exact, model_explicit_budget, &name](
                          Value result, const std::string &id, const Value &arguments) {
    const auto output_budget = static_cast<std::size_t>(
        arguments.find("output_max_bytes")
            ? command_number(arguments, "output_max_bytes", 16 * 1024 * 1024)
            : 16 * 1024 * 1024);
    auto selection =
        Value::object({{"output_ref", Value{id}},
                       {"output_max_bytes", Value{Number{output_budget}}}});
    if (const auto *head = arguments.find("output_head_bytes"))
      selection.object().emplace_back("output_head_bytes", *head);
    auto projection = retained_process_output(selection);
    for (auto &[key, value] : projection.object()) {
      auto old = std::find_if(result.object().begin(), result.object().end(),
                              [&](const auto &entry) { return entry.first == key; });
      if (old != result.object().end())
        old->second = std::move(value);
      else
        result.object().emplace_back(std::move(key), std::move(value));
    }

    // For model-invoked exec/foreground calls without an explicit model byte budget,
    // apply lossless diagnostic-preserving context projection on oversized verbose
    // UTF-8 outputs while full verbatim bytes remain untouched under output_ref.
    if (model_call && !exact && !model_explicit_budget &&
        output_budget > kToolProjectionFooterHeadroomBytes) {
      constexpr std::uint64_t kMaxProjectionScanBytes = 4ULL * 1024ULL * 1024ULL;
      const std::uint64_t output_bytes =
          parse_optional_u64_field(result, "output_bytes").value_or(0);
      const std::uint64_t omitted_bytes =
          parse_optional_u64_field(result, "omitted_bytes").value_or(0);
      std::string raw_for_projection;
      if (omitted_bytes == 0 && output_bytes <= kMaxProjectionScanBytes) {
        if (const auto *out_val = result.find("output")) {
          if (const auto *out_str = std::get_if<std::string>(&out_val->value()))
            raw_for_projection = *out_str;
        }
      } else if (output_bytes > 0 && output_bytes <= kMaxProjectionScanBytes) {
        if (const auto found = process_originals_.find(id);
            found != process_originals_.end()) {
          raw_for_projection.reserve(static_cast<std::size_t>(output_bytes));
          for (const auto &[_, dependency] : found->second.chunks) {
            const auto bytes = unwrap(log_.root().source(dependency));
            if (bytes.size() > static_cast<std::size_t>(kMaxProjectionScanBytes) -
                                   raw_for_projection.size()) {
              raw_for_projection.clear();
              break;
            }
            raw_for_projection.append(reinterpret_cast<const char *>(bytes.data()),
                                      bytes.size());
          }
        }
      }

      if (!raw_for_projection.empty() && valid_utf8(raw_for_projection)) {
        std::optional<int> exit_code;
        if (const auto *code_val = result.find("exit_code")) {
          if (const auto *num = std::get_if<Number>(&code_val->value())) {
            int parsed = 0;
            const std::string text = num->text();
            const auto res =
                std::from_chars(text.data(), text.data() + text.size(), parsed);
            if (res.ec == std::errc{} && res.ptr == text.data() + text.size())
              exit_code = parsed;
          }
        }
        ToolProjectionPolicy policy;
        policy.max_inline_bytes =
            std::min(policy.max_inline_bytes,
                     output_budget - kToolProjectionFooterHeadroomBytes);
        const auto projected = project_tool_output_for_context(
            {.tool_name = name,
             .raw_output = std::move(raw_for_projection),
             .exit_code = exit_code},
            policy);
        if (projected.was_compacted &&
            projected.projected_text.size() <= output_budget &&
            ((omitted_bytes == 0 &&
              projected.projected_bytes < projected.original_bytes) ||
             (omitted_bytes > 0 && projected.diagnostic_lines_extracted > 0))) {
          auto upsert_field = [&result](std::string key, Value value) {
            auto old =
                std::find_if(result.object().begin(), result.object().end(),
                             [&](const auto &entry) { return entry.first == key; });
            if (old != result.object().end())
              old->second = std::move(value);
            else
              result.object().emplace_back(std::move(key), std::move(value));
          };
          const std::size_t compacted_omitted =
              projected.original_bytes > projected.projected_bytes
                  ? projected.original_bytes - projected.projected_bytes
                  : std::size_t{0};
          upsert_field("output", Value{projected.projected_text});
          upsert_field("truncated", Value{true});
          upsert_field("returned_bytes", Value{Number{projected.projected_bytes}});
          upsert_field("omitted_bytes", Value{Number{compacted_omitted}});
          upsert_field("context_projected", Value{true});
          upsert_field("diagnostic_lines_extracted",
                       Value{Number{projected.diagnostic_lines_extracted}});
        }
      }
    }
    return result;
  };
  CommandStartStatus command_start;
  DomainAdmission domain_admission;
  FileEffectObservation file_effect;
  const Value &input = stripped ? requested : arguments;
  const bool fire_tool_hooks =
      !exact && name != "hooks" && hooks_ && !hooks_->definitions().empty();
  if (fire_tool_hooks) {
    const HookMatchSample sample{
        .event = HookEvent::before_tool, .tool = name, .prompt = {}};
    const auto payload = Value::object({{"event", Value{"before_tool"}},
                                        {"tool", Value{name}},
                                        {"arguments", input},
                                        {"model_call", Value{model_call}}});
    if (const auto denial = run_hooks(sample, payload)) {
      return Value::object({{"error", Value{"hook_refused"}},
                            {"hook", Value{denial->hook}},
                            {"reason", Value{denial->reason}},
                            {"tool", Value{name}}});
    }
  }
  auto outcome = operation(
      name, input,
      [&](OperationAttemptId attempt, InvocationId invocation,
          DefinitionGenerationId admitted_generation, CommandTaskActivity *activity,
          RawRetainedExec *raw_exec) {
        if (shape_refused || !refusal.empty())
          throw Error{ErrorCode::invalid_range};
        if (host_tools_ && host_tools_->find(name)) {
          host_tools_->validate_arguments(name, arguments);
          auto result =
              host_call_({name, arguments, attempt, invocation, admitted_generation});
          const auto &outcome = string_field(result, "outcome");
          if (outcome != "success" && outcome != "error" && outcome != "cancelled" &&
              outcome != "unknown")
            throw Error{ErrorCode::invalid_range};
          if (outcome == "success")
            host_tools_->validate_result(name, field(result, "result"));
          return result;
        }
        if (name == "exec") {
          const auto id = hex_identity(attempt.bytes());
          const auto limits = log_.root().journal_limits();
          if (limits.max_payload < 2048 || limits.max_batch_bytes < 4096)
            throw Error{ErrorCode::capacity};
          JobWaitOptions options;
          if (arguments.find("yield_ms"))
            options.yield_ms = command_number(arguments, "yield_ms", 3600000);
          if (arguments.find("output_max_bytes"))
            options.max_output = static_cast<std::size_t>(
                command_number(arguments, "output_max_bytes", 16 * 1024 * 1024));
          const auto output_budget = options.max_output;
          if (arguments.find("output_head_bytes") &&
              command_number(arguments, "output_head_bytes", 16 * 1024 * 1024) >
                  output_budget)
            throw Error{ErrorCode::invalid_range};
          options.max_output = 0;
          options.stop_on_cancel = true;
          command_jobs_->start(id, arguments, raw_exec, &command_start);
          if (activity) {
            if (!activity->pending_node || !activity->transferred)
              throw Error{ErrorCode::conflict};
            auto inserted = command_tasks_.insert(std::move(*activity->pending_node));
            if (!inserted.inserted) {
              *activity->pending_node = std::move(inserted.node);
              throw Error{ErrorCode::conflict};
            }
            *activity->transferred = true;
            activity->pending_node = nullptr;
            activity->transferred = nullptr;
          }
          auto result = command_jobs_->wait(
              id, options, [this] { poll_commands(); },
              [this] { return cancelled && cancelled(); });
          return shaped(std::move(result), id, arguments);
        }
        if (name == "process") {
          if (string_field(arguments, "op") == "foreground") {
            JobWaitOptions options;
            if (arguments.find("yield_ms"))
              options.yield_ms = command_number(arguments, "yield_ms", 3600000);
            const auto output_budget =
                arguments.find("output_max_bytes")
                    ? command_number(arguments, "output_max_bytes", 16 * 1024 * 1024)
                    : 16 * 1024 * 1024;
            if (arguments.find("output_head_bytes") &&
                command_number(arguments, "output_head_bytes", 16 * 1024 * 1024) >
                    output_budget)
              throw Error{ErrorCode::invalid_range};
            options.max_output = 0;
            const auto &job = string_field(arguments, "job_id");
            auto result = command_jobs_->wait(
                job, options, [this] { poll_commands(); },
                [this] { return cancelled && cancelled(); });
            return shaped(std::move(result), job, arguments);
          }
          return command_jobs_->control(arguments);
        }
        if (name == "decision_model") {
          decision_models_.cancelled = cancelled;
          decision_models_.observer = [&](std::string_view label,
                                          std::string_view raw) {
            log_.original(
                {label, raw,
                 Value::object({{"attempt", Value{hex_identity(attempt.bytes())}}})});
          };
          const RawAdapterContext raw_context{
              nullptr,
              operation_trace_ ? std::optional{operation_trace_->reference()}
                               : std::nullopt,
              nullptr, nullptr};
          auto result = decision_models_.evaluate(arguments, &raw_context);
          result.object().emplace_back("audit_ref",
                                       Value{hex_identity(attempt.bytes())});
          return result;
        }
        if (name == "beads") {
          beads_.cancelled = cancelled;
          beads_.observer = [&](std::string_view label, std::string_view raw) {
            log_.original(
                {label, raw,
                 Value::object({{"attempt", Value{hex_identity(attempt.bytes())}}})});
          };
          const RawAdapterContext beads_capture{
              nullptr,
              operation_trace_ ? std::optional{operation_trace_->reference()}
                               : std::nullopt,
              nullptr, nullptr};
          auto result = beads_.run(arguments, &beads_capture);
          result.object().emplace_back("audit_ref",
                                       Value{hex_identity(attempt.bytes())});
          return result;
        }

        if (name == "workflow_registry") {
          const auto origin = program_origin(operation_trace_, generation_);
          return workflows_->discover(&origin);
        }
        if (name == "workflow_invoke") {
          const auto origin = program_origin(operation_trace_, generation_);
          RawProgramCall selection_trace{7, &origin};
          return selection_trace.run([&] {
            const auto selected_origin = selection_trace.context();
            RawEventRef selected;
            const auto &definition = workflows_->named(string_field(arguments, "name"),
                                                       &selected_origin, &selected);
            WorkflowContinuation continuation{definition,
                                              arguments,
                                              workflows_->revision(),
                                              hex_identity(attempt.bytes()),
                                              selected,
                                              {},
                                              continuation_shape};
            const auto selection = Value::object(
                {{"name", field(definition, "name")},
                 {"revision", Value{workflows_->revision()}},
                 {"definition", definition},
                 {"invocation", arguments},
                 {"selection_attempt", Value{continuation.selection_attempt}}});
            log_.original(
                {"workflow.selection", string_field(definition, "source"), selection});
            log_.record(ApplicationChannel::program, selection);
            if (context_.has_open_exchanges()) {
              if (workflow_continuations_.size() >= 8)
                throw Error{ErrorCode::capacity};
              if (selection_trace.enabled() && !program_issuer_)
                program_issuer_ = RawProgramIssuer::prepare();
              RawProgramLifetime parked{selection_trace.enabled() ? program_issuer_
                                                                  : nullptr,
                                        selected, true};
              parked.queued(workflow_continuations_.size());
              continuation.parked = std::move(parked);
              try {
                workflow_continuations_.push_back(std::move(continuation));
              } catch (const Error &error) {
                continuation.parked.finish(2, &error, {}, RawOperationBranch::error);
                throw;
              } catch (const std::bad_alloc &) {
                continuation.parked.finish(2, nullptr, {},
                                           RawOperationBranch::allocation);
                throw;
              } catch (...) {
                continuation.parked.finish(2, nullptr, {},
                                           RawOperationBranch::nonstandard);
                throw;
              }
              workflow_continuations_.back().parked.installed(
                  workflow_continuations_.size());
              return Value::object(
                  {{"status", Value{"accepted"}},
                   {"name", field(definition, "name")},
                   {"revision", Value{workflows_->revision()}},
                   {"execution",
                    Value{"same-turn after tool outputs, before next request or "
                          "successful boundary"}}});
            }
            return execute_workflow(continuation);
          });
        }
        if (name == "program_config")
          return program_config(arguments, &domain_admission);
        if (name == "module_source")
          return module_source(arguments);
        if (name == "tool_define")
          return define_tool(arguments);
        if (name == "tool_registry")
          return tool_registry();
        for (const auto &definition : lua_tools_.array()) {
          if (string_field(definition, "name") != name)
            continue;
          const auto origin = program_origin(operation_trace_, generation_);
          const auto revision_size = tools_revision_.size();
          const auto source_size = string_field(definition, "source").size();
          RawProgramCall tool_trace{3827, 3828, &origin,
                                    std::array{raw_native(revision_size),
                                               raw_text(tools_revision_),
                                               raw_native(source_size)}};
          return tool_trace.run([&] {
            validate_tool_arguments(
                {.schema = field(definition, "parameters"), .arguments = arguments});
            log_.original(
                {"tool.source", string_field(definition, "source"),
                 Value::object({{"name", Value{name}},
                                {"revision", Value{tools_revision_}},
                                {"attempt", Value{hex_identity(attempt.bytes())}}})});
            const auto wrapper_origin = tool_trace.context();
            return runtime_->invoke_tool({.definition = definition,
                                          .arguments = arguments,
                                          .origin = &wrapper_origin});
          });
        }
        if (name == "restart") {
          const RawAdapterContext parent{
              nullptr,
              operation_trace_ ? std::optional{operation_trace_->reference()}
                               : std::nullopt,
              nullptr, nullptr};
          const std::uint8_t method = 1;
          RawSessionCall call{
              4420, 4421, &parent,
              std::array{raw_native(method), ByteView{generation_.bytes()}}};
          return call.run([&] {
            const auto &borrowed = string_field(arguments, "note");
            (void)raw_restart_source(call, 1, borrowed);
            auto note = borrowed;
            if (note.empty() || note.size() > 65536)
              throw Error{ErrorCode::invalid_range};
            raw_restart_mutation(
                call, 1, [&] { restart_note_ = std::move(note); }, 4423);
            return Value::object({{"scheduled", Value{true}}});
          });
        }
        if (name == "read_process_output") {
          if (arguments.find("result_ref"))
            return retained_result_output(arguments);
          if (!arguments.find("output_ref"))
            throw Error{ErrorCode::invalid_range};
          return retained_process_output(arguments);
        }
        if (name == "context_list") {
          bool include_archived = false;
          if (const auto *inc = arguments.find("include_archived")) {
            if (!std::holds_alternative<bool>(inc->value()))
              throw Error{ErrorCode::invalid_range};
            include_archived = std::get<bool>(inc->value());
          }
          return context_list(include_archived);
        }
        if (name == "context_compact")
          return context_compact(arguments);
        if (name == "context_read")
          return context_read(arguments);
        if (name == "hooks")
          return hooks_tool(arguments);
        if (auto cp = try_dispatch_command_post_tool(
                name, arguments,
                CommandPostToolContext{.decision_models = &decision_models_,
                                       .cancelled = cancelled})) {
          return std::move(*cp);
        }
        if (name == "rageshake") {
          const RawAdapterContext origin{
              nullptr,
              operation_trace_ ? std::optional{operation_trace_->reference()}
                               : std::nullopt,
              nullptr, nullptr};
          RawSessionCall complaint_trace{
              4500, 4501, &origin,
              std::array{ByteView{attempt.bytes()}, ByteView{invocation.bytes()},
                         ByteView{admitted_generation.bytes()}}};
          return complaint_trace.run([&] {
            auto predicate = [&](RawSessionCall &owner, std::uint8_t kind,
                                 auto &&evaluate) {
              auto credit = owner.control(42);
              const bool value = evaluate();
              (void)owner.event(4503, std::array{raw_native(kind), raw_native(value)},
                                credit);
              return value;
            };
            auto hexadecimal = [&](RawSessionCall &owner, std::uint8_t role,
                                   const IdentityBytes &bytes) {
              auto native_credit = owner.control(57);
              auto source_credit = owner.source_credit(32);
              (void)owner.event(4505, std::array{raw_native(role), ByteView{bytes}},
                                native_credit);
              auto text = hex_identity(bytes);
              (void)owner.source(role, text, source_credit, 4502);
              return text;
            };
            auto borrowed = [&](std::uint8_t role,
                                const std::string &bytes) -> const std::string & {
              (void)complaint_trace.source(role, bytes, 4502);
              return bytes;
            };
            complaint_trace.stage(1);
            const auto &observation = string_field(arguments, "observation");
            (void)complaint_trace.source(1, observation, 4502);
            if (predicate(complaint_trace, 1, [&] { return observation.empty(); }) ||
                predicate(complaint_trace, 2,
                          [&] { return observation.size() > 65536; }))
              throw Error{ErrorCode::invalid_range};
            complaint_trace.stage(2);
            const auto references = arguments.find("references")
                                        ? field(arguments, "references")
                                        : Value::object({});
            if (!predicate(complaint_trace, 3, [&] {
                  return std::holds_alternative<Value::Object>(references.value());
                }))
              throw Error{ErrorCode::invalid_range};
            auto references_credit = complaint_trace.source_credit(ValueLimits{}.bytes);
            const auto encoded_references = unwrap(encode_packet_string(references));
            (void)complaint_trace.source(2, encoded_references, references_credit,
                                         4502);
            if (predicate(complaint_trace, 4,
                          [&] { return encoded_references.size() > 65536; }))
              throw Error{ErrorCode::invalid_range};
            complaint_trace.stage(3);
            std::set<std::string> active;
            for (const auto &unresolved : unwrap(log_.root().unresolved_attempts())) {
              auto credit = complaint_trace.control(56);
              (void)complaint_trace.event(
                  4504, std::array{ByteView{unresolved.admission.attempt.bytes()}},
                  credit);
              active.insert(hexadecimal(complaint_trace, 3,
                                        unresolved.admission.attempt.bytes()));
            }
            Value::Array active_ids;
            for (const auto &id : active) {
              auto credit = complaint_trace.control(50);
              const auto size = active_ids.size();
              const bool full = size == 64;
              const std::uint8_t kind = 5;
              (void)complaint_trace.event(
                  4503,
                  std::array{raw_native(kind), raw_native(full), raw_native(size)},
                  credit);
              if (full)
                break;
              active_ids.push_back(Value{id});
            }
            complaint_trace.stage(4);
            auto detail = Value::object(
                {{"observation", Value{observation}},
                 {"references", references},
                 {"active_attempts", Value{std::move(active_ids)}},
                 {"active_attempt_count", Value{Number{[&] {
                    auto credit = complaint_trace.control(48);
                    const auto size = active.size();
                    (void)complaint_trace.event(4506, std::array{raw_native(size)},
                                                credit);
                    return size;
                  }()}}},
                 {"revision", Value{borrowed(4, context_.head())}},
                 {"generation",
                  Value{hexadecimal(complaint_trace, 5, generation_.bytes())}},
                 {"actor",
                  Value{hexadecimal(complaint_trace, 6, identity_.actor.bytes())}},
                 {"conversation", Value{hexadecimal(complaint_trace, 7,
                                                    identity_.conversation.bytes())}},
                 {"workflow",
                  Value{hexadecimal(complaint_trace, 8, identity_.workflow.bytes())}},
                 {"model", Value{borrowed(17, model_)}},
                 {"effort", Value{borrowed(18, effort_)}},
                 {"audit_end", Value{Number{[&] {
                    auto credit = complaint_trace.control(48);
                    const auto count = log_.root().fact_count();
                    (void)complaint_trace.event(4507, std::array{raw_native(count)},
                                                credit);
                    return count;
                  }()}}},
                 {"reporting_attempt",
                  Value{hexadecimal(complaint_trace, 9, attempt.bytes())}},
                 {"repair_required_now", Value{false}}});
            auto detail_credit = complaint_trace.source_credit(ValueLimits{}.bytes);
            const auto encoded_detail = unwrap(encode_packet_string(detail));
            const auto detail_original =
                complaint_trace.source(10, encoded_detail, detail_credit, 4502);
            complaint_trace.stage(5);
            RawEventRef complaint_original;
            const auto complaint = [&] {
              const auto parent = complaint_trace.context();
              RawSessionCall retain{4510, 4511, &parent,
                                    std::array{ByteView{detail_original.lane},
                                               raw_native(detail_original.ordinal)},
                                    24};
              retain.stage(5);
              return retain.run([&] {
                auto locator_credit = retain.source_credit(32);
                auto locator = log_.original(
                    {"complaint.detail", encoded_detail,
                     Value::object({{"attempt", Value{hexadecimal(
                                                    retain, 9, attempt.bytes())}}})});
                complaint_original = retain.source(11, locator, locator_credit, 4502);
                retain.require_capture();
                retain.finish(RawOperationBranch::returned, nullptr,
                              std::array{ByteView{complaint_original.lane},
                                         raw_native(complaint_original.ordinal)});
                return locator;
              });
            }();
            complaint_trace.stage(6);
            constexpr char title_prefix[] = "Blackbird model complaint ";
            auto title_credit = complaint_trace.source_credit(
                raw_session_bound(sizeof(title_prefix) - 1, complaint.size()));
            auto title = title_prefix + complaint;
            const auto title_original =
                complaint_trace.source(12, title, title_credit, 4502);
            constexpr char description_prefix[] = "Local audit complaint ";
            constexpr char description_middle[] = "; conversation ";
            constexpr char description_suffix[] =
                ". Inspect complaint.detail locally. Advisory; no immediate repair "
                "required.";
            auto description_credit = complaint_trace.source_credit(raw_session_bound(
                raw_session_bound(
                    raw_session_bound(sizeof(description_prefix) - 1, complaint.size()),
                    sizeof(description_middle) - 1),
                raw_session_bound(32, sizeof(description_suffix) - 1)));
            auto description =
                description_prefix + complaint + description_middle +
                hexadecimal(complaint_trace, 7, identity_.conversation.bytes()) +
                description_suffix;
            const auto description_original =
                complaint_trace.source(13, description, description_credit, 4502);
            complaint_trace.stage(7);
            const auto parent = complaint_trace.context();
            RawSessionCall deliver{4520, 4521, &parent,
                                   std::array{ByteView{complaint_original.lane},
                                              raw_native(complaint_original.ordinal),
                                              ByteView{title_original.lane},
                                              raw_native(title_original.ordinal),
                                              ByteView{description_original.lane},
                                              raw_native(description_original.ordinal)},
                                   1};
            deliver.stage(7);
            bool delivered = false;
            auto delivery = deliver.run([&] {
              auto acquired =
                  call("exec",
                       Value::object(
                           {{"argv",
                             Value{Value::Array{
                                 Value{"bd"}, Value{"create"}, Value{std::move(title)},
                                 Value{"--type"}, Value{"bug"}, Value{"--description"},
                                 Value{std::move(description)}, Value{"--json"}}}},
                            {"timeout_seconds", Value{Number{"20"}}},
                            {"output_max_bytes", Value{Number{"4096"}}}}));
              deliver.require_capture();
              complaint_trace.require_capture();
              complaint_trace.stage(8);
              deliver.stage(8);
              const auto *exit = acquired.find("exit_code");
              if (predicate(deliver, 6, [&] { return exit != nullptr; })) {
                auto text_credit = deliver.source_credit(21);
                const auto text = exit->number().text();
                (void)deliver.source(16, text, text_credit, 4502);
                delivered = predicate(deliver, 7, [&] { return text == "0"; });
              }
              deliver.finish(RawOperationBranch::returned, nullptr,
                             std::array{raw_native(delivered)});
              return acquired;
            });
            auto result =
                Value::object({{"complaint", Value{complaint}},
                               {"retained_locally", Value{true}},
                               {"bead_created", Value{delivered}},
                               {"delivery", delivery},
                               {"sink", Value{"external consumer not configured"}},
                               {"repair_required_now", Value{false}}});
            complaint_trace.stage(9);
            auto delivery_credit = complaint_trace.source_credit(ValueLimits{}.bytes);
            const auto encoded_delivery = unwrap(encode_packet_string(result));
            const auto delivery_original =
                complaint_trace.source(14, encoded_delivery, delivery_credit, 4502);
            complaint_trace.stage(10);
            RawSessionCall retain{4530, 4531, &parent,
                                  std::array{ByteView{delivery_original.lane},
                                             raw_native(delivery_original.ordinal)},
                                  24};
            retain.stage(10);
            retain.run([&] {
              auto locator_credit = retain.source_credit(32);
              const auto locator =
                  log_.original({"complaint.delivery", encoded_delivery,
                                 Value::object({{"complaint", Value{complaint}}})});
              const auto locator_original =
                  retain.source(15, locator, locator_credit, 4502);
              retain.require_capture();
              retain.finish(RawOperationBranch::returned, nullptr,
                            std::array{ByteView{locator_original.lane},
                                       raw_native(locator_original.ordinal)});
            });
            return result;
          });
        }
        if (name == "audit_inspect")
          return log_.inspect(field(arguments, "query"), attempt);
        if (name == "trajectory_read")
          return log_.trajectory(field(arguments, "query"), attempt);
        if (name == "variables_read")
          return log_.variables(field(arguments, "query"), attempt);
        if (name == "git_observe") {
          const RawAdapterContext raw_context{
              nullptr,
              operation_trace_ ? std::optional{operation_trace_->reference()}
                               : std::nullopt,
              nullptr, nullptr};
          return observations_->git(arguments, cancelled, &raw_context);
        }
        if (name == "participant_configure")
          return participants_->configure(arguments);
        if (name == "participant_read")
          return participants_->read(arguments);
        if (name == "participant_send")
          return participants_->send(
              arguments,
              {{},
               RawParticipantIdentities{attempt.bytes(), invocation.bytes(),
                                        admitted_generation.bytes()}},
              &domain_admission);
        if (name == "participant_cancel")
          return participants_->cancel(arguments);
        if (name == "participant_await")
          return participants_->await(arguments, cancelled);
        if (name == "participant_join")
          return participants_->join(arguments, cancelled);
        if (name == "participant_archive")
          return participants_->archive(arguments);
        if (name == "participant_start") {
          if (const auto *task = arguments.find("task_id");
              task && !task->string().empty())
            if (field(tasks_.read(Value::object({{"id", *task}})), "items")
                    .array()
                    .empty())
              throw Error{ErrorCode::invalid_range};
          const auto transport =
              participant_transport
                  ? participant_transport
                  : ParticipantTransport{[&](const Value &prepared,
                                             const ColleagueCapture &capture,
                                             const std::function<bool()> &stop,
                                             const RawAdapterContext *context) {
                      return native_colleague_transport(prepared, capture, stop,
                                                        nullptr, context);
                    }};
          return participants_->start(
              hex_identity(attempt.bytes()), arguments, transport,
              {{},
               RawParticipantIdentities{attempt.bytes(), invocation.bytes(),
                                        admitted_generation.bytes()}},
              &domain_admission);
        }
        if (name == "provider_auth_status")
          return ProviderAuth{}.status();
        if (name == "colleague_catalog")
          return colleague_catalog();
        if (name == "colleague") {
          const auto capture = [&](std::string_view label, std::string_view raw) {
            log_.original(
                {"colleague." + std::string{label}, raw,
                 Value::object({{"attempt", Value{hex_identity(attempt.bytes())}},
                                {"request_id", arguments.find("request_id")
                                                   ? field(arguments, "request_id")
                                                   : Value{}}})});
          };
          const auto transport =
              colleague_transport
                  ? colleague_transport
                  : ColleagueTransport{[&](const Value &prepared,
                                           const ColleagueCapture &retain,
                                           const RawAdapterContext *context) {
                      return native_colleague_transport(prepared, retain, cancelled,
                                                        nullptr, context);
                    }};
          const RawProviderOwner owner{
              attempt.bytes(), invocation.bytes(), admitted_generation.bytes(), {}};
          const RawAdapterContext context{&owner, std::nullopt, nullptr, nullptr};
          return call_colleague(arguments, capture, transport, &context);
        }
        if (name == "tasks_read")
          return tasks_.read(arguments.find("query") ? field(arguments, "query")
                                                     : Value::object({}));
        if (name == "tasks_edit")
          return tasks_.edit(arguments, {}, &domain_admission);
        if (name == "lua") {
          if (runtime_)
            runtime_->error.clear();
          return runtime_->eval(string_field(arguments, "code"));
        }
        if (name == "read_file" && arguments.find("snapshot")) {
          if (arguments.find("path"))
            throw Error{ErrorCode::invalid_range};
          const auto &snapshot = field(arguments, "snapshot");
          if (!std::holds_alternative<Value::Object>(snapshot.value()) ||
              snapshot.object().size() != 2 || !snapshot.find("journal") ||
              !snapshot.find("sequence") ||
              !std::holds_alternative<std::string>(field(snapshot, "journal").value()))
            throw Error{ErrorCode::invalid_range};
          const auto journal =
              parse_id<AuditStreamId>(string_field(snapshot, "journal"));
          const auto sequence = command_number(snapshot, "sequence", UINT64_MAX);
          if (sequence == 0)
            throw Error{ErrorCode::invalid_range};
          const auto raw = unwrap(log_.root().source({journal, sequence}));
          const std::string bytes{reinterpret_cast<const char *>(raw.data()),
                                  raw.size()};
          auto result = file_content_presentation(bytes, arguments);
          result.object().emplace_back("snapshot", snapshot);
          return result;
        }
        std::optional<SourceReference> file_snapshot;
        LocalTools tools{[&](std::string_view label, std::string_view raw) {
          try {
            const auto source = log_.original(
                log_.issue(),
                {label, raw,
                 Value::object({{"attempt", Value{hex_identity(attempt.bytes())}}})});
            if (label == "file.read")
              file_snapshot = source;
          } catch (const Error &e) {
            if (e.code == ErrorCode::capacity)
              unretained_bytes_ += raw.size();
            throw;
          }
          if (label == "process.output" && process_output)
            process_output(raw);
        }};
        tools.cancelled = [this] {
          poll_commands();
          return cancelled && cancelled();
        };
        // File surfaces nest under this actual operation, as sibling adapters do.
        const RawAdapterContext raw_context{
            nullptr,
            operation_trace_ ? std::optional{operation_trace_->reference()}
                             : std::nullopt,
            nullptr, nullptr};
        auto result = tools.run(name, arguments, &raw_context, nullptr, &file_effect);
        if (name == "read_file" && file_snapshot)
          result.object().emplace_back(
              "snapshot",
              Value::object(
                  {{"journal", Value{hex_identity(file_snapshot->journal.bytes())}},
                   {"sequence", Value{Number{file_snapshot->sequence}}}}));
        if (name == "exec" && process_output)
          process_output("\n[exit " + field(result, "exit_code").number().text() +
                         "]\n");
        return result;
      },
      nullptr, name == "exec" ? &command_start : nullptr, &domain_admission,
      &file_effect, {std::move(supplied), shape, call_id, declared_id, refusal});
  if (fire_tool_hooks) {
    const HookMatchSample sample{
        .event = HookEvent::after_tool, .tool = name, .prompt = {}};
    const auto payload =
        Value::object({{"event", Value{"after_tool"}},
                       {"tool", Value{name}},
                       {"arguments", input},
                       {"result", outcome},
                       {"failed", Value{coding_detail::failed_tool_output(outcome)}}});
    (void)run_hooks(sample, payload);
  }
  return outcome;
}

} // namespace blackbird
