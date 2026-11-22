#include "blackbird/json.hpp"
#include "blackbird/local_timing.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/provider_auth.hpp"
#include "blackbird/raw_auth.hpp"
#include "blackbird/raw_provider.hpp"
#include "blackbird/raw_runtime.hpp"
#include "blackbird/request_cache.hpp"
#include "coding_internal.hpp"
#include "stream_capture.hpp"
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <thread>

namespace blackbird {
using coding_detail::raw_native;
using coding_detail::raw_text;
using coding_detail::validate_protocol;
namespace {
void emit_provider_fact(std::uint32_t site, std::span<const ByteView> fields,
                        RawControlToken *claim = nullptr) {
  struct RestoreErrno {
    int saved = errno;
    ~RestoreErrno() { errno = saved; }
  } restore;
  if (claim == nullptr) {
    std::uint64_t bytes = raw_envelope_size;
    for (const auto field : fields) {
      if (field.size() > UINT32_MAX - bytes) {
        raw_fence({ErrorCode::overflow});
        throw Error{ErrorCode::overflow};
      }
      bytes += field.size();
    }
    const auto admitted = raw_wait_data(bytes);
    if (!admitted.has_value()) {
      if (admitted.error().code != ErrorCode::interrupted)
        raw_fence(admitted.error());
      throw admitted.error();
    }
  }
  const auto emitted =
      raw_emit(site, fields, claim ? RawPartition::control : RawPartition::data, claim);
  if (!emitted.has_value())
    throw emitted.error();
}
} // namespace

void OpenAiCodingProvider::begin_request_group(const Value &,
                                               const RawAdapterContext *context) {
  if (request_binding_)
    throw Error{ErrorCode::busy};
  auto config = config_;
  config.cancelled = cancelled;
  config.raw_context = context;
  request_binding_ = unwrap(openai_request_binding(config));
}
void OpenAiCodingProvider::end_request_group() noexcept { request_binding_.reset(); }
bool OpenAiCodingProvider::supports_prompt_cache_policy() const noexcept {
  if (!request_binding_)
    return false;
  const auto matches = [&](std::string_view key, std::string_view expected) {
    const auto *value = request_binding_->find(key);
    const auto *text = value ? std::get_if<std::string>(&value->value()) : nullptr;
    return text && *text == expected;
  };
  return matches("kind", "api_key") &&
         matches("base_url", "https://api.openai.com/v1") &&
         matches("protocol", "responses");
}
Value OpenAiCodingProvider::respond(
    const Value &request, const std::function<void(std::string_view)> &capture) {
  return respond(request, capture, nullptr);
}
Value OpenAiCodingProvider::respond(
    const Value &request, const std::function<void(std::string_view)> &capture,
    const RawProviderOwner *owner) {
  return respond(request, capture, owner, nullptr);
}
Value OpenAiCodingProvider::respond(
    const Value &request, const std::function<void(std::string_view)> &capture,
    const RawProviderOwner *owner, const RawAdapterContext *context) {
  std::optional<RawWaitScope> deadline_scope;
  if (config_.timeout_seconds >= 1 && config_.timeout_seconds <= 3600) {
    auto control = raw_wait_control();
    control.deadline = std::chrono::steady_clock::now() +
                       std::chrono::seconds{config_.timeout_seconds};
    deadline_scope.emplace(control);
  }
  RawProviderPhase adapter;
  return adapter.run([&] {
    adapter.start(5, context);
    if (responding_)
      throw Error{ErrorCode::busy};
    responding_ = true;
    struct Responding {
      bool &active;
      ~Responding() { active = false; }
    } responding{responding_};
    auto config = config_;
    config.raw_owner = owner;
    config.raw_context = context;
    config.response_observer = capture;
    config.cancelled = cancelled;
    const bool temporary_group = !request_binding_;
    if (temporary_group)
      begin_request_group(request, context);
    struct End {
      OpenAiCodingProvider &provider;
      bool temporary;
      ~End() {
        if (temporary)
          provider.end_request_group();
      }
    } end{*this, temporary_group};
    if (!request_binding_)
      throw Error{ErrorCode::corrupt};
    auto login = unwrap(codex_login(config, false, &*request_binding_));
    auto raw = unwrap(openai_http(config, login, "responses", &request));
    return unwrap(completed_response(raw, {}, context));
  });
}

std::optional<std::uint64_t>
known_context_window_tokens(std::string_view model) noexcept {
  if (model.empty())
    return std::nullopt;
  auto has_icase = [](std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty() || hay.size() < needle.size())
      return false;
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
      bool ok = true;
      for (std::size_t j = 0; j < needle.size(); ++j) {
        auto a = static_cast<unsigned char>(hay[i + j]);
        auto b = static_cast<unsigned char>(needle[j]);
        if (a >= 'A' && a <= 'Z')
          a = static_cast<unsigned char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
          b = static_cast<unsigned char>(b - 'A' + 'a');
        if (a != b) {
          ok = false;
          break;
        }
      }
      if (ok)
        return true;
    }
    return false;
  };
  auto has_token_icase = [](std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty() || hay.size() < needle.size())
      return false;
    auto boundary = [](char ch) noexcept {
      return ch == '/' || ch == '-' || ch == ':' || ch == '@' || ch == '_';
    };
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
      if (i > 0 && !boundary(hay[i - 1]))
        continue;
      if (i + needle.size() < hay.size() && !boundary(hay[i + needle.size()]))
        continue;
      bool ok = true;
      for (std::size_t j = 0; j < needle.size(); ++j) {
        auto a = static_cast<unsigned char>(hay[i + j]);
        auto b = static_cast<unsigned char>(needle[j]);
        if (a >= 'A' && a <= 'Z')
          a = static_cast<unsigned char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
          b = static_cast<unsigned char>(b - 'A' + 'a');
        if (a != b) {
          ok = false;
          break;
        }
      }
      if (ok)
        return true;
    }
    return false;
  };
  if (has_icase(model, "gemini-2.5") || has_icase(model, "gemini-3"))
    return 1048576ULL;
  if (has_icase(model, "claude-opus-4") || has_icase(model, "claude-sonnet-4") ||
      has_icase(model, "claude-haiku-4") || has_icase(model, "claude-3-7") ||
      has_icase(model, "claude-3.7") || has_icase(model, "claude-3-5") ||
      has_icase(model, "claude-3.5"))
    return 200000ULL;
  if (has_icase(model, "gpt-6") || has_icase(model, "gpt-5") ||
      has_icase(model, "kimi-k2"))
    return 256000ULL;
  if (has_token_icase(model, "o3") || has_token_icase(model, "o4-mini"))
    return 200000ULL;
  if (has_icase(model, "gpt-4o") || has_icase(model, "deepseek"))
    return 128000ULL;
  return std::nullopt;
}
namespace {
Value::Array project_input_for_provider(Value::Array items,
                                        std::string_view provider_identity) {
  if (provider_identity == "unavailable")
    return items;
  const bool anthropic = provider_identity == "anthropic-messages" ||
                         provider_identity.starts_with("anthropic");
  const bool keeps_encrypted = provider_identity == "openai-codex" ||
                               provider_identity == "openrouter-responses";
  Value::Array projected;
  projected.reserve(items.size());
  for (auto &item : items) {
    const auto *type = item.find("type");
    if (type && *type == Value{"reasoning"}) {
      const bool has_anthropic = item.find("anthropic_content") != nullptr;
      const auto *anth_id = item.find("anthropic_message_id");
      const bool valid_anthropic =
          has_anthropic && anth_id != nullptr &&
          std::holds_alternative<std::string>(anth_id->value()) &&
          !anth_id->string().empty();
      const bool has_encrypted = item.find("encrypted_content") != nullptr;
      if (anthropic) {
        if (!valid_anthropic)
          continue;
      } else {
        if (has_anthropic)
          continue;
        if (!keeps_encrypted && has_encrypted)
          continue;
      }
    }
    projected.push_back(std::move(item));
  }
  return projected;
}
} // namespace

Value CodingEngine::request(Value options) {
  const bool custom_input = std::holds_alternative<Value::Object>(options.value()) &&
                            options.find("input") != nullptr;
  try {
    return request_impl(options);
  } catch (const Error &e) {
    if (custom_input || e.code != ErrorCode::provider_context_overflow ||
        log_.root().state() != JournalWriterState::live)
      throw;
    if (!auto_compact_for_overflow())
      throw;
    const auto msg = "provider context overflow: auto-archived oldest unpinned units "
                     "(originals retained), rolling upstream epoch " +
                     std::to_string(upstream_epoch_) + " and retrying";
    if (status)
      status(msg);
    if (notice || display)
      (notice ? notice : display)("\n[" + msg + "]\n");
    return request_impl(std::move(options));
  }
}
Value CodingEngine::request_impl(Value options) {
  struct RequestGroup {
    CodingProvider &provider;
    bool &active;
    bool owned = false;
    bool began = false;
    ~RequestGroup() {
      if (!owned)
        return;
      if (began)
        provider.end_request_group();
      provider.request_group_owned_ = false;
      active = false;
    }
  } request_group{provider_, request_group_active_};
  RawProviderPhase assembly{2 * provider_scalar_credit + sizeof(IdentityBytes) +
                            sizeof(std::size_t) + 32};
  return assembly.run([&] {
    assembly.start(1);
    if (request_group_active_ || provider_.request_group_owned_)
      throw Error{ErrorCode::busy};
    assembly.stage(10);
    RawRegion preparation{raw_regions::provider_prepare};
    if (restart_note_)
      throw Error{ErrorCode::busy};
    assembly.stage(11);
    validate_protocol(context_.items(), assembly.reference());
    assembly.stage(12);
    drain_workflows();
    if (!std::holds_alternative<Value::Object>(options.value()))
      throw Error{ErrorCode::invalid_range};
    unsigned max_attempts = 5;
    unsigned base_ms = 1000;
    unsigned cap_ms = 16000;
    if (const auto *policy = options.find("retry_policy")) {
      if (!std::holds_alternative<Value::Object>(policy->value()))
        throw Error{ErrorCode::invalid_range};
      for (const auto &[key, value] : policy->object()) {
        if (!std::holds_alternative<Number>(value.value()))
          throw Error{ErrorCode::invalid_range};
        unsigned n = 0;
        const auto &text = value.number().text();
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), n);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size())
          throw Error{ErrorCode::invalid_range};
        if (key == "max_attempts" && n >= 1 && n <= 100)
          max_attempts = n;
        else if (key == "base_ms" && n <= 60000)
          base_ms = n;
        else if (key == "cap_ms" && n <= 60000)
          cap_ms = n;
        else
          throw Error{ErrorCode::invalid_range};
      }
    }
    const auto cache_mode =
        options.find("cache_policy") ? prompt_cache_mode(field(options, "cache_policy"))
        : program_config_.find("prompt_cache")
            ? prompt_cache_mode(field(program_config_, "prompt_cache"))
            : PromptCacheMode::provider_default;
    const auto *state_choice = options.find("state_context");
    if (state_choice && *state_choice != Value{"auto"} &&
        *state_choice != Value{"omit"})
      throw Error{ErrorCode::invalid_range};
    const bool state_context = !state_choice || *state_choice == Value{"auto"};
    if (const auto *opt_store = options.find("store")) {
      const auto *b = std::get_if<bool>(&opt_store->value());
      if (b == nullptr || *b)
        throw Error{ErrorCode::unsupported};
    }
    if (const auto *opt_stream = options.find("stream")) {
      const auto *b = std::get_if<bool>(&opt_stream->value());
      if (b == nullptr || !*b)
        throw Error{ErrorCode::unsupported};
    }
    const std::string target_model = [&] {
      if (const auto *opt_model = options.find("model");
          opt_model && std::holds_alternative<std::string>(opt_model->value()) &&
          !opt_model->string().empty())
        return opt_model->string();
      return string_field(program_config_, "model").empty()
                 ? model_
                 : string_field(program_config_, "model");
    }();
    const auto target_identity = provider_.provider_identity();
    if (!pending_compactions_.empty()) {
      const auto now = std::chrono::steady_clock::now();
      const bool cold_cache = last_provider_request_at_.has_value() &&
                              (now - *last_provider_request_at_) >= cache_ttl_;
      const bool route_switched =
          (!last_provider_model_.empty() && last_provider_model_ != target_model) ||
          (!last_provider_identity_.empty() &&
           last_provider_identity_ != target_identity);
      if (cold_cache || route_switched) {
        (void)flush_pending_compactions(route_switched ? "route switch" : "cold cache");
      }
    }
    auto items = context_.items();
    auto origin = context_.head();
    validate_protocol(items, assembly.reference());
    items = project_input_for_provider(std::move(items), target_identity);
    auto request = Value::object(
        {{"model", Value{target_model}},
         {"instructions",
          Value{"You are Blackbird, a programmable coding colleague for an expert "
                "operator. Use local file/process tools without approval ceremony. "
                "Gather source with targeted searches and ranges; expand when the "
                "question remains unresolved. Inspect omission counts and recover "
                "needed facts from captured originals. Compose mechanical reads, "
                "loops and projections in Lua rather than requesting a model decision "
                "for each step; return useful results with recovery handles. Preserve "
                "constraints and complete tool groups. Select model/effort explicitly "
                "for the task; smaller prompts alone do not prove cheaper work. "
                "Context is ordinary editable data: inspect it, transform it with Lua, "
                "repair it from originals. A timed-out tool returns a result: inspect "
                "its "
                "retained output and choose a new attempt or another approach; never "
                "blindly repeat an effect with unknown outcome. Keep tool call/result "
                "linkage valid. Governing "
                "Lua workflow changes activate next turn. For compiled changes, build "
                "build/release/blackbird and request restart with a note listing "
                "changes, "
                "checks and next steps; the same session will resume with continue. "
                "Bound hardening before starting: list concrete remediation tasks, "
                "direct checks and a time/resource allowance. Layer one: remediate "
                "and fix. Layer two: one recheck and fix its findings within that "
                "allowance. Never a third assurance layer: no reviews of reviews, "
                "certifying rechecks, unrelated full-suite reruns or silent budget "
                "resets. Settled checks stay settled absent relevant change or new "
                "defect evidence. If blocked at the bound, retain the unsafe candidate "
                "inactive and continue independent useful work; do not call it safe. "
                "Work carefully and verify "
                "actual results. Host cwd: " +
                std::filesystem::current_path().string()}},
         {"reasoning",
          Value::object(
              {{"effort", Value{string_field(program_config_, "effort").empty()
                                    ? effort_
                                    : string_field(program_config_, "effort")}}})},
         {"input", Value{std::move(items)}},
         {"tools", request_tools()},
         {"parallel_tool_calls", Value{false}},
         {"include", Value{Value::Array{Value{"reasoning.encrypted_content"}}}},
         {"store", Value{false}},
         {"stream", Value{true}}});
    assembly.stage(13);
    for (auto &[key, value] : options.object()) {
      if (key == "retry_policy" || key == "cache_policy" || key == "state_context")
        continue;
      auto &fields = request.object();
      auto found = std::find_if(fields.begin(), fields.end(),
                                [&](const auto &f) { return f.first == key; });
      if (found == fields.end())
        fields.emplace_back(key, std::move(value));
      else
        found->second = std::move(value);
    }
    const auto *store = std::get_if<bool>(&field(request, "store").value());
    std::string operational_state;
    if (state_context && (!tasks_.state().empty() || tasks_.state().revision() != 0)) {
      operational_state +=
          "CURRENT_TASKS " +
          unwrap(format_value(tasks_.read(Value::object({{"status", Value{"open"}},
                                                         {"limit", Value{Number{"16"}}},
                                                         {"compact", Value{true}}})))) +
          "\nTasks are durable session working state. Read more with tasks_read; use "
          "tasks_edit for small atomic batches at real work transitions. Keep stable "
          "IDs through renames. Exactly tasks and subtasks, no deeper nesting. "
          "Multiple "
          "active tasks are fine. Completion is explicit, including parents. Use item "
          "versions for set, and current list base for structural edits. Preserve "
          "op_id "
          "and arguments for retries; resolve conflicts by reading before a new edit. "
          "Use exec task_id for observed activity; a running command does not itself "
          "complete a task. Unfinished tasks remain across turns and compaction.\n";
    }
    const auto *stream = std::get_if<bool>(&field(request, "stream").value());
    if (store == nullptr || *store || stream == nullptr || !*stream)
      throw Error{ErrorCode::unsupported};
    validate_protocol(field(request, "input").array(), assembly.reference());
    const auto input_bytes =
        unwrap(encode_packet_string(field(request, "input"))).size();
    if (state_context && !provider_.retain_request_state()) {
      operational_state += "CONTEXT_SIZE input_bytes=" + std::to_string(input_bytes) +
                           " blocks=" + std::to_string(context_.blocks().size()) +
                           " upstream_epoch=" + std::to_string(upstream_epoch_) +
                           " (native packet bytes, not tokens)\n";
    }
    auto reusable_input_items = field(request, "input").array().size();
    // Before anything enters context (a provider that retains request state appends
    // its state item below): a start binding the auth store could not give is read
    // now, before the adapter reads the store itself, so its failure is an auth-store
    // refusal; and the request's final model must resolve against it, so a refused
    // attempt leaves nothing behind.
    std::optional<Value> start_binding;
    if (profiles_) {
      const RawAuthParent parent{assembly.reference()};
      auto binding = session_binding(*profiles_, &parent);
      if (!binding.has_value()) {
        if (notice || display)
          (notice ? notice : display)("\n[" + binding.error().message() + "]\n");
        throw Error{ErrorCode::provider_auth};
      }
      start_binding = std::move(binding).value();
      const auto model = string_field(request, "model");
      if (const auto resolved = resolve_profile_for(*profiles_, model, *start_binding);
          !resolved.has_value()) {
        if (notice || display)
          (notice ? notice : display)("\n[provider profile refused for model " + model +
                                      ": " + resolved.error().message() + "]\n");
        throw Error{ErrorCode::invalid_range};
      }
    }
    if (!operational_state.empty()) {
      auto state_item =
          Value::object({{"role", Value{"developer"}},
                         {"content", Value{std::move(operational_state)}}});
      if (provider_.retain_request_state()) {
        context_.append({state_item}, "provider.request-state");
        origin = context_.head();
        ++reusable_input_items;
      }
      for (auto &[key, input] : request.object())
        if (key == "input") {
          input.array().push_back(std::move(state_item));
          break;
        }
    }
    assembly.stage(14);
    request_group_active_ = true;
    provider_.request_group_owned_ = true;
    request_group.owned = true;
    const RawAdapterContext preparation_context{nullptr, assembly.reference(), nullptr,
                                                nullptr};
    provider_.cancelled = [this] {
      poll_commands();
      return cancelled && cancelled();
    };
    request_group.began = true;
    provider_.begin_request_group(request, &preparation_context);
    // The request's profile: its final model and this group's binding (design §15.4).
    // Nothing reads the behavioural rows yet. Shared storage; fixed for every attempt.
    Value profile_metadata;
    if (profiles_ && start_binding) {
      const auto *group = provider_.group_binding();
      const auto model = string_field(request, "model");
      const auto resolved =
          resolve_profile_for(*profiles_, model, group ? *group : *start_binding);
      if (!resolved.has_value()) {
        if (notice || display)
          (notice ? notice : display)("\n[provider profile refused for model " + model +
                                      ": " + resolved.error().message() + "]\n");
        throw Error{ErrorCode::invalid_range};
      }
      profile_metadata = resolved.value()->record;
    }
    prepare_request_cache(request,
                          {cache_mode, provider_.supports_prompt_cache_policy(),
                           provider_.provider_identity(), reusable_input_items});
    // Cache affinity follows the conversation and current upstream cache epoch,
    // so it survives reopen/restart and rolls cleanly after context cuts.
    // An authored key wins.
    if (provider_.supports_prompt_cache_key() && !request.find("prompt_cache_key")) {
      auto key = hex_identity(identity_.conversation.bytes());
      if (upstream_epoch_ > 0)
        key += ":e" + std::to_string(upstream_epoch_);
      request.object().emplace_back("prompt_cache_key", Value{std::move(key)});
    }
    if (context_.head() != origin)
      throw Error{ErrorCode::conflict};
    ProviderOriginalLease final_packet{{ProviderOriginalRole::request_packet,
                                        ProviderOriginalMode::codec_adopt,
                                        ValueLimits{}.bytes,
                                        {}},
                                       assembly.reference()};
    final_packet.adopt(unwrap(encode_packet_string(request)));
    const auto prepared_request = final_packet.response_body();
    last_request_bytes_ = Value{Number{prepared_request.size()}};
    usage_ = Value{};
    if (diagnostic || display)
      (diagnostic ? diagnostic : display)("\n[request " +
                                          last_request_bytes_.number().text() +
                                          " native request bytes]\n");
    assembly.stage(15);
    if (origin.size() > 32)
      throw Error{ErrorCode::invalid_range};
    const auto origin_bytes = origin.size();
    const std::array generation_fields{ByteView{generation_.bytes()}};
    assembly.scalar(15, 8, generation_fields);
    const std::array origin_fields{raw_native(origin_bytes), raw_text(origin)};
    assembly.scalar(15, 7, origin_fields);
    if (preparation.enabled()) {
      preparation.linkage({raw_text(origin), {}});
      preparation.observe({RawObservationKind::request_bytes, 0,
                           prepared_request.size(), log_.root().cursor().sequence});
      preparation.outcome(RawRegionOutcome::success);
    }
    preparation.finish();
    assembly.finish(1);
    constexpr std::uint64_t decision_bytes = raw_envelope_size + provider_ref_bytes +
                                             sizeof(unsigned) + provider_ref_bytes +
                                             sizeof(unsigned) + sizeof(bool);
    constexpr std::uint64_t clock_bytes = raw_envelope_size + provider_ref_bytes +
                                          sizeof(clockid_t) + 2 * sizeof(int) +
                                          sizeof(time_t) + sizeof(long);
    constexpr std::uint64_t wait_bytes = provider_phase_credit + 2 * clock_bytes;
    const std::uint64_t retry_extra =
        raw_envelope_size + provider_ref_bytes + sizeof(IdentityBytes) +
        3 * sizeof(unsigned) +
        static_cast<std::uint64_t>(max_attempts) * decision_bytes +
        static_cast<std::uint64_t>(max_attempts - 1) * wait_bytes;
    RawProviderPhase group{retry_extra};
    return group.run([&] {
      const RawAdapterContext group_context{nullptr, assembly.reference(), nullptr,
                                            nullptr};
      group.start(2, &group_context);
      group.stage(22);
      // One live request group; each failed attempt stays independently recorded.
      const auto retry_id = unwrap(log_.root().issue<OperationAttemptId>());
      const auto group_ref = group.reference();
      const std::array policy_fields{
          ByteView{group_ref.lane},   raw_native(group_ref.ordinal),
          ByteView{retry_id.bytes()}, raw_native(max_attempts),
          raw_native(base_ms),        raw_native(cap_ms)};
      group.emit(1325, policy_fields);
      const auto retry_group = hex_identity(retry_id.bytes());
      provider_.cancelled = [this] {
        poll_commands();
        return cancelled && cancelled();
      };
      Value response;
      unsigned delay_ms = std::min(base_ms, cap_ms);
      auto attempt_started = std::chrono::steady_clock::now();
      std::optional<std::chrono::steady_clock::time_point> first_delta_at;
      for (unsigned ordinal = 1;; ++ordinal) {
        attempt_started = std::chrono::steady_clock::now();
        first_delta_at.reset();
        RawProviderPhase attempt_phase{2 * provider_link_credit};
        RawProviderOperationContext operation_context;
        operation_context.attempt_phase = &attempt_phase;
        operation_context.parent = group.reference();
        group.stage(20);
        if (cancelled && cancelled())
          throw Error{ErrorCode::interrupted};
        group.stage(21);
        const auto journal = log_.root().journal_usage();
        if (journal.approaching() || journal.extent_error) {
          const auto remaining = journal.remaining_bytes();
          const auto warning =
              "audit headroom: " +
              (remaining ? std::to_string(*remaining) + " bytes"
                         : "bytes unavailable") +
              ", " + std::to_string(journal.remaining_records()) +
              " indexed records remaining; observation only, no handoff reserve; "
              "context compaction does not reclaim audit history";
          if (status)
            status(warning);
          if (notice || display)
            (notice ? notice : display)("\n[" + warning + "]\n");
        }
        ResponsePreview preview;
        previewed_.clear();
        try {
          group.stage(22);
          response = attempt_phase.run([&] {
            return operation(
                "provider", request,
                [&](OperationAttemptId attempt, InvocationId, DefinitionGenerationId,
                    CommandTaskActivity *, RawRetainedExec *) {
                  const auto admission = unwrap(log_.root().attempt(attempt));
                  const auto *instructions = request.find("instructions");
                  if (instructions &&
                      std::holds_alternative<std::string>(instructions->value()))
                    observations_->doctrine(instructions->string(),
                                            admission.admission.invocation, attempt);
                  Value::Object request_metadata{
                      {"attempt", Value{hex_identity(attempt.bytes())}},
                      {"revision", Value{origin}},
                      {"generation", Value{hex_identity(generation_.bytes())}},
                      {"input_binding", Value{"attempt-invocation-v1"}},
                      {"retry_group", Value{retry_group}},
                      {"ordinal", Value{Number{ordinal}}}};
                  if (profile_metadata != Value{})
                    request_metadata.emplace_back("profile", profile_metadata);
                  log_.record(ApplicationChannel::log,
                              Value::object(
                                  {{"label", Value{"provider.request"}},
                                   {"metadata", Value{std::move(request_metadata)}}}));
                  RawRegion transport{raw_regions::provider_transport, {.cpu = false}};
                  if (transport.enabled())
                    transport.linkage({raw_text(origin), attempt.bytes()});
                  RawProviderPhase receipt{provider_link_credit};
                  RawProviderPhase acceptance{provider_link_credit +
                                              provider_scalar_credit +
                                              sizeof(std::size_t) + 32};
                  StreamCapture capture{[&](std::string_view block) {
                    try {
                      log_.original(
                          {"provider.stream", block,
                           Value::object(
                               {{"attempt", Value{hex_identity(attempt.bytes())}},
                                {"revision", Value{origin}},
                                {"capture_policy", Value{"bounded-blocks-v1"}}})});
                    } catch (const Error &e) {
                      if (e.code == ErrorCode::capacity)
                        unretained_bytes_ += block.size();
                      throw;
                    }
                  }};
                  Value result;
                  try {
                    operation_context.owner.dispatch = {raw_lane_epoch(),
                                                        transport.begin_ordinal()};
                    const auto &owner = operation_context.owner;
                    const RawAdapterContext source_context{
                        &owner, attempt_phase.reference(), nullptr,
                        &operation_context.receipt};
                    attempt_phase.stage(23);
                    result = provider_.respond(
                        request,
                        [&](std::string_view raw) {
                          poll_commands();
                          capture.append(raw);
                          // Preview follows transport delivery, not diagnostic flush
                          // cadence.
                          for (const auto &delta : preview.feed(raw, &source_context)) {
                            if (!first_delta_at && !delta.text.empty())
                              first_delta_at = std::chrono::steady_clock::now();
                            RawProviderPhase presentation;
                            presentation.run([&] {
                              presentation.start(8, &source_context);
                              previewed_[delta.item_id] += delta.text;
                              if (display)
                                display(delta.text);
                            });
                          }
                        },
                        &owner, &source_context);
                    receipt.start(9, &source_context);
                    if (operation_context.receipt.response)
                      receipt.link(*operation_context.receipt.response);
                    receipt.finish(1);
                  } catch (const Error &error) {
                    transport.error(error);
                    transport.outcome(RawRegionOutcome::exception);
                    transport.finish();
                    // No destructor I/O and no retry if a prior sink write was
                    // uncertain.
                    capture.flush();
                    throw;
                  } catch (...) {
                    transport.outcome(RawRegionOutcome::exception);
                    transport.finish();
                    capture.flush();
                    throw;
                  }
                  transport.outcome(RawRegionOutcome::returned);
                  transport.finish();
                  attempt_phase.stage(24);
                  capture.flush();
                  return acceptance.run([&] {
                    const RawAdapterContext acceptance_context{
                        &operation_context.owner, attempt_phase.reference(), nullptr,
                        &operation_context.receipt};
                    acceptance.start(10, &acceptance_context);
                    if (operation_context.receipt.response)
                      acceptance.link(*operation_context.receipt.response);
                    acceptance.stage(25);
                    return import_provider_response(std::move(result));
                  });
                },
                &operation_context);
          });
          const bool eligible = false;
          const auto attempt_ref = attempt_phase.reference();
          const std::array decision_fields{ByteView{group_ref.lane},
                                           raw_native(group_ref.ordinal),
                                           raw_native(ordinal),
                                           ByteView{attempt_ref.lane},
                                           raw_native(attempt_ref.ordinal),
                                           raw_native(delay_ms),
                                           raw_native(eligible)};
          group.emit(1326, decision_fields);
          break;
        } catch (const Error &e) {
          const bool transient_http =
              e.code == ErrorCode::external_unknown &&
              (e.detail == 408 || e.detail == 429 || e.detail == 500 ||
               e.detail == 502 || e.detail == 503 || e.detail == 504);
          const bool transient_curl =
              e.code == ErrorCode::provider_transport &&
              (e.detail == 5 || e.detail == 6 || e.detail == 7 || e.detail == 16 ||
               e.detail == 18 || e.detail == 28 || e.detail == 52 || e.detail == 55 ||
               e.detail == 56 || e.detail == 92 || e.detail == 95 || e.detail == 96);
          const bool typed_http429 =
              e.code == ErrorCode::provider_rate_limit && e.detail == 429;
          group.stage(27);
          const bool eligible = ordinal < max_attempts &&
                                (transient_http || transient_curl || typed_http429) &&
                                log_.root().state() == JournalWriterState::live;
          const auto attempt_ref = attempt_phase.reference();
          const std::array decision_fields{ByteView{group_ref.lane},
                                           raw_native(group_ref.ordinal),
                                           raw_native(ordinal),
                                           ByteView{attempt_ref.lane},
                                           raw_native(attempt_ref.ordinal),
                                           raw_native(delay_ms),
                                           raw_native(eligible)};
          // No attempt begin exists if native retained admission itself refused.
          if (attempt_ref.ordinal)
            group.emit(1326, decision_fields);
          if (!eligible)
            throw;
          const auto message =
              "provider attempt " + std::to_string(ordinal) + " stopped (" +
              error_name(e.code) + ":" + std::to_string(e.detail) +
              "); partial output not accepted; retry " + std::to_string(ordinal + 1) +
              "/" + std::to_string(max_attempts) + " in " + std::to_string(delay_ms) +
              "ms";
          log_.original({"provider.retry", message,
                         Value::object({{"retry_group", Value{retry_group}}})});
          if (status)
            status(message);
          if (notice || display)
            (notice ? notice : display)("\n[" + message + "]\n");
          group.stage(28);
          RawProviderPhase wait_phase{group.split(wait_bytes)};
          wait_phase.run([&] {
            const RawAdapterContext wait_context{nullptr, group.reference(), nullptr,
                                                 nullptr};
            wait_phase.start(4, &wait_context);
            auto clocks = wait_phase.split(2 * clock_bytes);
            const auto clock = [&] {
              const int saved_errno = errno;
              const clockid_t method = CLOCK_MONOTONIC;
              timespec value{};
              const int result = ::clock_gettime(method, &value);
              const int native_errno = errno;
              const auto ref = wait_phase.reference();
              const std::array fields{
                  ByteView{ref.lane},       raw_native(ref.ordinal),
                  raw_native(method),       raw_native(result),
                  raw_native(native_errno), raw_native(value.tv_sec),
                  raw_native(value.tv_nsec)};
              emit_provider_fact(1327, fields, clocks ? &*clocks : nullptr);
              errno = saved_errno;
            };
            clock();
            const auto until =
                std::chrono::steady_clock::now() + std::chrono::milliseconds{delay_ms};
            try {
              while (std::chrono::steady_clock::now() < until) {
                if (cancelled && cancelled())
                  throw Error{ErrorCode::interrupted};
                std::this_thread::sleep_for(std::chrono::milliseconds{25});
              }
            } catch (...) {
              clock();
              throw;
            }
            clock();
          });
          delay_ms = std::min(cap_ms, delay_ms * 2);
        }
      }
      group.stage(29);
      const auto completed_at = std::chrono::steady_clock::now();
      const auto duration_ms = static_cast<std::uint64_t>(std::max<std::int64_t>(
          0, std::chrono::duration_cast<std::chrono::milliseconds>(completed_at -
                                                                   attempt_started)
                 .count()));
      const auto ttft_ms =
          first_delta_at ? static_cast<std::uint64_t>(std::max<std::int64_t>(
                               0, std::chrono::duration_cast<std::chrono::milliseconds>(
                                      *first_delta_at - attempt_started)
                                      .count()))
                         : std::uint64_t{0};
      if (const auto *usage = response.find("usage");
          usage && std::holds_alternative<Value::Object>(usage->value())) {
        Value::Object selected;
        auto parse_u64 = [](const Value *v) -> std::optional<std::uint64_t> {
          if (!v || !std::holds_alternative<Number>(v->value()))
            return std::nullopt;
          const auto &n = v->number().text();
          if (n.empty() || !std::all_of(n.begin(), n.end(),
                                        [](char c) { return c >= '0' && c <= '9'; }))
            return std::nullopt;
          std::uint64_t out = 0;
          const auto parsed = std::from_chars(n.data(), n.data() + n.size(), out);
          if (parsed.ec != std::errc{} || parsed.ptr != n.data() + n.size())
            return std::nullopt;
          return out;
        };
        auto parse_double = [](const Value *v) -> std::optional<double> {
          if (!v || !std::holds_alternative<Number>(v->value()))
            return std::nullopt;
          const auto &n = v->number().text();
          double out = 0.0;
          const auto parsed = std::from_chars(n.data(), n.data() + n.size(), out);
          if (parsed.ec != std::errc{} || parsed.ptr != n.data() + n.size() ||
              !std::isfinite(out) || out < 0.0)
            return std::nullopt;
          return out;
        };
        auto sat_add = [](std::uint64_t a, std::uint64_t b) noexcept {
          return a > UINT64_MAX - b ? UINT64_MAX : a + b;
        };
        auto object_field = [](const Value &source,
                               std::string_view key) -> const Value * {
          const auto *v = source.find(key);
          return v && std::holds_alternative<Value::Object>(v->value()) ? v : nullptr;
        };
        auto select = [&](const Value &source, std::string_view key,
                          Value::Object &dest) -> std::optional<std::uint64_t> {
          const auto *v = source.find(key);
          const auto parsed = parse_u64(v);
          if (parsed)
            dest.emplace_back(std::string{key}, *v);
          return parsed;
        };
        const bool has_prompt_tokens =
            parse_u64(usage->find("prompt_tokens")).has_value();
        auto in_tok = parse_u64(usage->find("input_tokens"));
        if (!in_tok)
          in_tok = parse_u64(usage->find("prompt_tokens"));
        auto out_tok = parse_u64(usage->find("output_tokens"));
        if (!out_tok)
          out_tok = parse_u64(usage->find("completion_tokens"));
        const auto *in_details = object_field(*usage, "input_tokens_details");
        if (!in_details)
          in_details = object_field(*usage, "prompt_tokens_details");
        std::optional<std::uint64_t> cached_opt;
        std::optional<std::uint64_t> cache_write_opt;
        if (in_details) {
          cached_opt = parse_u64(in_details->find("cached_tokens"));
          cache_write_opt = parse_u64(in_details->find("cache_write_tokens"));
        }
        const auto raw_anth_read = parse_u64(usage->find("cache_read_input_tokens"));
        const auto raw_anth_write =
            parse_u64(usage->find("cache_creation_input_tokens"));
        if (!cached_opt && raw_anth_read)
          cached_opt = raw_anth_read;
        if (!cache_write_opt && raw_anth_write)
          cache_write_opt = raw_anth_write;
        // Raw Anthropic Messages API reports input_tokens as uncached-only; include
        // cache read/creation tokens in total input_tokens when not already normalized.
        const bool raw_anthropic_usage =
            in_tok.has_value() && !has_prompt_tokens && in_details == nullptr &&
            (raw_anth_read.has_value() || raw_anth_write.has_value());
        if (raw_anthropic_usage) {
          in_tok = sat_add(*in_tok, raw_anth_read.value_or(0));
          in_tok = sat_add(*in_tok, raw_anth_write.value_or(0));
        }
        if (in_tok)
          selected.emplace_back("input_tokens", Value{Number{*in_tok}});
        if (out_tok)
          selected.emplace_back("output_tokens", Value{Number{*out_tok}});
        (void)select(*usage, "total_tokens", selected);
        Value::Object kept_input_details;
        if (cached_opt)
          kept_input_details.emplace_back("cached_tokens", Value{Number{*cached_opt}});
        if (cache_write_opt)
          kept_input_details.emplace_back("cache_write_tokens",
                                          Value{Number{*cache_write_opt}});
        if (!kept_input_details.empty())
          selected.emplace_back("input_tokens_details",
                                Value::object(std::move(kept_input_details)));
        const std::uint64_t cached_tok = cached_opt.value_or(0);
        const std::uint64_t cache_write_tok = cache_write_opt.value_or(0);
        std::uint64_t reasoning_tok = 0;
        const auto *out_details = object_field(*usage, "output_tokens_details");
        if (!out_details)
          out_details = object_field(*usage, "completion_tokens_details");
        if (out_details) {
          Value::Object kept;
          if (const auto r = select(*out_details, "reasoning_tokens", kept))
            reasoning_tok = *r;
          if (!kept.empty())
            selected.emplace_back("output_tokens_details",
                                  Value::object(std::move(kept)));
        }
        const auto cost = parse_double(usage->find("cost"));
        if (!selected.empty()) {
          usage_ = Value::object(std::move(selected));
          telemetry_.requests = sat_add(telemetry_.requests, 1);
          telemetry_.last_input_tokens = in_tok.value_or(0);
          telemetry_.last_output_tokens = out_tok.value_or(0);
          telemetry_.last_cached_tokens = cached_tok;
          telemetry_.last_cache_write_tokens = cache_write_tok;
          telemetry_.last_reasoning_tokens = reasoning_tok;
          telemetry_.input_tokens =
              sat_add(telemetry_.input_tokens, telemetry_.last_input_tokens);
          telemetry_.output_tokens =
              sat_add(telemetry_.output_tokens, telemetry_.last_output_tokens);
          telemetry_.cached_tokens =
              sat_add(telemetry_.cached_tokens, telemetry_.last_cached_tokens);
          telemetry_.cache_write_tokens = sat_add(telemetry_.cache_write_tokens,
                                                  telemetry_.last_cache_write_tokens);
          telemetry_.reasoning_tokens =
              sat_add(telemetry_.reasoning_tokens, telemetry_.last_reasoning_tokens);
          telemetry_.last_duration_ms = duration_ms;
          telemetry_.last_ttft_ms = ttft_ms;
          telemetry_.upstream_epoch = upstream_epoch_;
          telemetry_.model = string_field(request, "model");
          telemetry_.context_window_tokens =
              known_context_window_tokens(telemetry_.model);
          telemetry_.last_cost_usd = cost;
          if (cost) {
            const double next = telemetry_.session_cost_usd.value_or(0.0) + *cost;
            if (std::isfinite(next))
              telemetry_.session_cost_usd = next;
          }
          if (observed_telemetry)
            observed_telemetry(telemetry_);
          if (observed_usage)
            observed_usage(usage_);
          if (diagnostic || display)
            (diagnostic ? diagnostic : display)("\n[provider usage " +
                                                unwrap(format_value(usage_)) + "]\n");
        }
      }
      group.stage(30);
      if (context_.head() != origin)
        throw Error{ErrorCode::conflict};
      RawProviderPhase final_acceptance{provider_scalar_credit + sizeof(std::size_t) +
                                        32};
      const RawAdapterContext final_context{nullptr, group.reference(), nullptr,
                                            nullptr};
      final_acceptance.run([&] {
        final_acceptance.start(10, &final_context);
        final_acceptance.stage(31);
        context_.append(field(response, "output").array(), "provider.branch:" + origin);
        const auto &head = context_.head();
        const auto size = head.size();
        if (size > 32)
          throw Error{ErrorCode::invalid_range};
        const std::array fields{raw_native(size), raw_text(head)};
        final_acceptance.scalar(31, 7, fields);
      });
      // The model's own calls in this response: dispatching one is a model boundary.
      ++response_generation_;
      for (const auto &item : field(response, "output").array())
        if (const auto *type = item.find("type");
            type && *type == Value{"function_call"} && item.find("call_id") &&
            item.find("name") && item.find("arguments"))
          model_calls_.insert_or_assign(
              string_field(item, "call_id"),
              ModelCall{string_field(item, "name"), field(item, "arguments"),
                        response_generation_, ++call_sequence_});
      last_provider_request_at_ = std::chrono::steady_clock::now();
      last_provider_model_ = string_field(request, "model");
      last_provider_identity_ = std::string{provider_.provider_identity()};
      if (const auto *st = response.find("status");
          st && *st == Value{"incomplete"} && (notice || display)) {
        (notice ? notice : display)(
            "\n[response hit max_output_tokens; partial reply preserved]\n");
      }
      return response;
    });
  });
}

ProfileResult<void> CodingEngine::profiles(SessionProfiles profiles) {
  if (!profiles.set)
    return std::unexpected(ProfileError{"session", 0, 0, "profile", "no profile set"});
  resolved_profiles_.clear();
  const auto &pinned = profiles_.emplace(std::move(profiles));
  if (!pinned.binding)
    return {}; // deferred: the first provider request reads it
  auto resolved = resolve_profile_for(pinned, definition_model(), *pinned.binding);
  if (!resolved.has_value())
    return std::unexpected(resolved.error());
  return {};
}
ProfileResult<const CodingEngine::ResolvedProfile *>
CodingEngine::resolve_profile_for(const SessionProfiles &profiles,
                                  const std::string &model, const Value &binding,
                                  RouteQuery *route) {
  auto query = route_query(binding, model);
  if (!query.has_value())
    return std::unexpected(query.error());
  if (route)
    *route = query.value();
  auto key = std::pair{model, binding_digest(query.value().query)};
  if (const auto found = resolved_profiles_.find(key);
      found != resolved_profiles_.end())
    return &found->second;
  const auto &layer = profiles.session_override;
  auto resolved =
      resolve_route(*profiles.set, query.value(), layer ? &*layer : nullptr);
  if (!resolved.has_value())
    return std::unexpected(resolved.error());
  auto record = profile_request_record(resolved.value(), query.value());
  return &resolved_profiles_
              .emplace(std::move(key),
                       ResolvedProfile{std::move(resolved).value(), std::move(record)})
              .first->second;
}
// The start binding, or the deferred one read now; an auth-store failure is refused
// as such, naming the store, never as a bare error code.
ProfileResult<Value> CodingEngine::session_binding(SessionProfiles &profiles,
                                                   const RawAuthParent *parent) {
  if (const auto &bound = profiles.binding)
    return *bound;
  try {
    if (!profiles.bind)
      throw Error{ErrorCode::unsupported};
    auto bound = profiles.bind(parent);
    profiles.binding = bound;
    profiles.deferral.clear();
    return bound;
  } catch (const Error &error) {
    return std::unexpected(
        ProfileError{profiles.auth_store.string(), 0, 0, "auth store",
                     std::string{"the provider auth store could not be read ("} +
                         error_name(error.code) + ", " + std::to_string(error.detail) +
                         "); repair or remove it, or set BLACKBIRD_AUTH_HOME"});
  }
}
ProfileResult<ProfileView>
CodingEngine::effective_profile(const RawAuthParent *parent) {
  if (!profiles_)
    return ProfileView{};
  auto &profiles = *profiles_;
  auto binding = session_binding(profiles, parent);
  if (!binding.has_value())
    return std::unexpected(binding.error());
  ProfileView view;
  auto resolved =
      resolve_profile_for(profiles, definition_model(), binding.value(), &view.route);
  if (!resolved.has_value())
    return std::unexpected(resolved.error());
  view.profile = &resolved.value()->profile;
  return view;
}

} // namespace blackbird
