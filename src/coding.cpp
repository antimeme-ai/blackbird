#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/process_lifetime.hpp"
#include "blackbird/raw_command.hpp"
#include "blackbird/raw_operation.hpp"
#include "blackbird/raw_provider.hpp"
#include "blackbird/raw_restart.hpp"
#include "blackbird/raw_runtime.hpp"
#include "coding_internal.hpp"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <set>

namespace blackbird {
namespace coding_detail {
Value error_value(Error e) {
  return Value::object(
      {{"error", Value{error_name(e.code)}}, {"detail", Value{Number{e.detail}}}});
}
void validate_protocol(const Value::Array &items, std::optional<RawEventRef> parent) {
  (void)parent;
  std::set<std::string> seen, pending;
  for (const auto &item : items) {
    const auto *type = item.find("type");
    if (type == nullptr)
      continue;
    const auto &s = type->string();
    if (s == "function_call") {
      const auto &call = string_field(item, "call_id");
      if (!seen.insert(call).second)
        throw Error{ErrorCode::conflict};
      pending.insert(call);
    }
    if (s == "function_call_output") {
      const auto &call = string_field(item, "call_id");
      if (pending.erase(call) != 1)
        throw Error{ErrorCode::conflict};
    }
  }
  if (!pending.empty())
    throw Error{ErrorCode::conflict};
}
bool failed_tool_output(const Value &result) noexcept {
  if (!std::holds_alternative<Value::Object>(result.value()))
    return false;
  if (result.find("error") != nullptr)
    return true;
  if (const auto *code = result.find("exit_code");
      code && std::holds_alternative<Number>(code->value()))
    return code->number().text() != "0";
  return false;
}
} // namespace coding_detail

using coding_detail::error_value;
using coding_detail::failed_tool_output;
using coding_detail::parse_id;
using coding_detail::program_origin;
using coding_detail::raw_native;
using coding_detail::raw_text;
using coding_detail::validate_protocol;

CodingEngine::CodingEngine(AuditLog &log, ContextStore &context,
                           CodingProvider &provider, std::string model,
                           DecisionModelConfig decisions)
    : log_(log), context_(context), tasks_(log), provider_(&provider),
      model_(std::move(model)), decision_models_(std::move(decisions)),
      identity_(session_identity(log)),
      generation_(unwrap(log.root().issue<DefinitionGenerationId>())) {
  const RawProgramContext bootstrap{{}, generation_.bytes()};
  RawProgramCall trace{0, &bootstrap};
  trace.run([&] {
    command_jobs_ = std::make_shared<CommandJobs>();
    observations_ = std::make_unique<Observations>(log_);
    program_config_.object().emplace_back("workflows", default_workflows());
    program_config_.object().emplace_back("workflow_prefix", Value{""});
    constexpr std::string_view builtin_prefix = "builtin-ultracode-v";
    const std::string builtin = std::string{builtin_prefix} + "6";
    program_revision_ = builtin;
    for (const auto &fact : log_.root().tail_facts()) {
      const auto *record = std::get_if<ApplicationRecordEvent>(&fact.event.body);
      if (!record || record->channel != ApplicationChannel::context)
        continue;
      const auto packet = read_packet(record->payload);
      if (!packet.has_value())
        continue;
      const auto *op = packet.value().find("op");
      if (!op || !std::holds_alternative<std::string>(op->value()))
        continue;
      const auto &kind = op->string();
      if (kind == "compact" || kind == "restore" || kind == "replace")
        ++upstream_epoch_;
    }
    std::optional<Value> recorded_config;
    for (const auto &packet : log_.root().current_programs()) {
      if (packet.find("label") && string_field(packet, "label") == "session.recovery")
        if (const auto *metadata = packet.find("metadata"))
          if (const auto *uncontained = metadata->find("uncontained_exec"))
            uncontained_exec_recovery_ = *uncontained == Value{true};
      const auto *label = packet.find("label");
      if (label && label->string() == "workflow-config-effective-v1") {
        if (const auto *config = packet.find("program_config")) {
          program_config_ = *config;
          program_revision_ = string_field(packet, "program_revision");
          recorded_config = packet;
        }
        lua_tools_ = field(packet, "tools");
        tools_revision_ = string_field(packet, "tools_revision");
      }
    }
    // A recorded built-in revision is the built-in program, never a session choice.
    // Any built-in revision other than this binary's (older, or newer from a later
    // binary whose source may use API this one refuses) is replaced with this
    // binary's built-in workflows, and the replacement is recorded with the revision
    // it replaced. A supplied program (a definition-generation revision) is kept.
    if (recorded_config && program_revision_.starts_with(builtin_prefix) &&
        program_revision_ != builtin) {
      auto &workflows = program_config_.object();
      std::erase_if(workflows,
                    [](const auto &pair) { return pair.first == "workflows"; });
      workflows.emplace_back("workflows", default_workflows());
      auto current = *recorded_config;
      bool activation = false;
      for (auto &[key, value] : current.object()) {
        if (key == "program_config")
          value = program_config_;
        if (key == "program_revision")
          value = Value{builtin};
        if (key == "activation") {
          value = Value{"builtin-current"};
          activation = true;
        }
      }
      if (!activation)
        current.object().emplace_back("activation", Value{"builtin-current"});
      std::erase_if(current.object(),
                    [](const auto &pair) { return pair.first == "replaced_revision"; });
      current.object().emplace_back("replaced_revision", Value{program_revision_});
      log_.record(log_.issue(), ApplicationChannel::program, current);
      program_revision_ = builtin;
    }
    Value participants_saved;
    for (const auto &packet : log_.root().current_programs())
      if (string_field(packet, "label") == "participants-state-v1")
        participants_saved = packet;
    participants_ = std::make_unique<Participants>(
        participants_saved,
        [&](const OriginalCapture &capture) {
          return log_.original(log_.issue(), capture);
        },
        [&](const Value &snapshot) {
          const auto identity = log_.issue();
          log_.record(identity, ApplicationChannel::program, snapshot);
          return std::optional{identity};
        },
        [&](const Value &activity) {
          if (task_activity)
            task_activity(activity);
        },
        [&](const Value &activity, RawEventRef source) {
          if (task_activity_native)
            task_activity_native(
                activity,
                RawTaskPresentation{
                    source.ordinal ? std::optional{source} : std::nullopt, {}, {}});
          else if (task_activity)
            task_activity(activity);
        });
    const auto origin = trace.context();
    workflows_ =
        std::make_shared<WorkflowRegistry>(program_config_, program_revision_, &origin);
    hooks_ = std::make_shared<HookRegistry>(program_config_, program_revision_);
  });
}
CodingEngine::~CodingEngine() { command_jobs_->shutdown(); }
void CodingEngine::shutdown_commands() {
  command_jobs_->shutdown();
  std::optional<Error> error;
  for (unsigned round = 0; round < 4 && command_jobs_->debt(); ++round) {
    try {
      poll_commands();
    } catch (const Error &failure) {
      error = failure;
    }
  }
  if (error)
    throw *error;
}
void CodingEngine::poll_commands() {
  if (pumping_commands_)
    return;
  pumping_commands_ = true;
  struct Reset {
    bool &flag;
    ~Reset() { flag = false; }
  } reset{pumping_commands_};
  try {
    if (!command_failure_)
      for (const auto &request : command_jobs_->requests())
        (void)call("process", request);
    for (unsigned drain_round = 0; drain_round < 4; ++drain_round) {
      auto events = command_jobs_->drain();
      for (auto &event : events) {
        if (event.bytes) {
          if (command_failure_) {
            continue;
          }
          auto preserve_credit = raw_command_claim(154);
          const auto id_size = event.job_id.size(), byte_size = event.bytes->size();
          const auto preserve_request =
              raw_command_linked(2011, event.original,
                                 std::array{detail::raw_native_field(id_size),
                                            detail::raw_string_field(event.job_id),
                                            detail::raw_native_field(event.offset),
                                            detail::raw_native_field(byte_size)},
                                 preserve_credit ? &*preserve_credit : nullptr);
          const auto semantic_before = log_.root().cursor();
          try {
            if (command_jobs_->retained_end(event.job_id) != event.offset)
              throw Error{ErrorCode::conflict};
            log_.original(
                {"process.output", *event.bytes,
                 Value::object({{"attempt", Value{event.job_id}},
                                {"byte_start", Value{Number{event.offset}}}})});
            command_jobs_->retained(event.job_id, event.offset + event.bytes->size());
            const auto retained_end = event.offset + event.bytes->size();
            const std::uint8_t branch = 1;
            const Error error{};
            (void)raw_command_linked(2012, preserve_request,
                                     std::array{detail::raw_native_field(retained_end),
                                                detail::raw_native_field(branch),
                                                detail::raw_native_field(error.code),
                                                detail::raw_native_field(error.detail)},
                                     preserve_credit ? &*preserve_credit : nullptr);
            if (process_output) {
              try {
                if (string_field(command_jobs_->foreground(), "job_id") == event.job_id)
                  process_output(*event.bytes);
                else
                  process_output("\n[command " + event.job_id + "]\n" + *event.bytes);
              } catch (...) {
              } // Presentation cannot undo successfully retained bytes.
            }
          } catch (const Error &error) {
            const std::uint8_t branch = 2;
            const auto retained_end = event.offset;
            (void)raw_command_linked(2012, preserve_request,
                                     std::array{detail::raw_native_field(retained_end),
                                                detail::raw_native_field(branch),
                                                detail::raw_native_field(error.code),
                                                detail::raw_native_field(error.detail)},
                                     preserve_credit ? &*preserve_credit : nullptr);
            if (error.code == ErrorCode::interrupted &&
                log_.root().state() == JournalWriterState::live &&
                log_.root().cursor().journal == semantic_before.journal &&
                log_.root().cursor().sequence == semantic_before.sequence &&
                log_.root().cursor().end_offset == semantic_before.end_offset)
              throw;
            if (diagnostic)
              diagnostic(
                  "command capture failed: " + std::string{error_name(error.code)} +
                  ":" + std::to_string(error.detail) + "\n");
            command_failure_ = error;
            capacity_stopped_ = error.code == ErrorCode::capacity;
            command_jobs_->shutdown();
            // The job still owns the unacknowledged exact original. No drop.
            command_jobs_->capture_failed_all();
          } catch (...) {
            const std::uint8_t branch = 3;
            const Error error{ErrorCode::allocation};
            const auto retained_end = event.offset;
            (void)raw_command_linked(2012, preserve_request,
                                     std::array{detail::raw_native_field(retained_end),
                                                detail::raw_native_field(branch),
                                                detail::raw_native_field(error.code),
                                                detail::raw_native_field(error.detail)},
                                     preserve_credit ? &*preserve_credit : nullptr);
            command_jobs_->shutdown();
            command_jobs_->capture_failed_all();
            throw error;
          }
          continue;
        }
        if (command_failure_) {
          for (auto &[key, value] : event.result.object()) {
            if (key == "effect_outcome")
              value = Value{"unknown"};
            if (key == "capture_complete")
              value = Value{false};
          }
        }
        event.result.object().emplace_back(
            "retained_bytes", Value{Number{command_jobs_->retained_end(event.job_id)}});
        const auto encoded = unwrap(encode_packet(event.result));
        const auto disposition =
            string_field(event.result, "effect_outcome") == "unknown"
                ? AttemptDisposition::unknown
            : event.result.find("exit_code") &&
                    field(event.result, "exit_code") == Value{Number{0}}
                ? AttemptDisposition::success
                : AttemptDisposition::failure;
        command_jobs_->settlement(event, [&](RawRetainedJobLoan *loan) {
          const auto submitted = unwrap(log_.root().submit_settlement(
              {{},
               AttemptObservationEvent{parse_id<OperationAttemptId>(event.job_id),
                                       AttemptPhase::terminal,
                                       disposition,
                                       {encoded.begin(), encoded.end()}}},
              loan ? loan->acknowledgment() : std::span<PhysicalJournalRecord>{},
              loan ? loan->acknowledged_flag() : nullptr));
          if (submitted.evidence == RetainedEvidence::uncertain ||
              submitted.evidence == RetainedEvidence::recovered_pending)
            throw Error{ErrorCode::audit_unavailable};
        });
        if (const auto task = command_tasks_.find(event.job_id);
            task != command_tasks_.end()) {
          auto accepted = command_tasks_.extract(task);
          const auto branch =
              disposition == AttemptDisposition::success   ? std::uint8_t{1}
              : disposition == AttemptDisposition::failure ? std::uint8_t{2}
                                                           : std::uint8_t{3};
          accepted.mapped().emit(branch, event.result.find("exit_code"));
        }
        if (process_output && event.result.find("exit_code") &&
            string_field(command_jobs_->foreground(), "job_id") == event.job_id)
          try {
            process_output("\n[exit " +
                           field(event.result, "exit_code").number().text() + "]\n");
          } catch (...) {
          }
      }
      if (!command_failure_)
        break;
    }
  } catch (const Error &error) {
    if (error.code == ErrorCode::interrupted)
      throw;
    command_jobs_->stop_all();
    command_failure_ = error;
    if (error.code != ErrorCode::capacity)
      log_.root().block_admission();
    throw;
  }
  if (!turn_running_ && !command_jobs_->debt())
    settlement_.reset();
  if (command_failure_)
    throw *command_failure_;
}
void CodingEngine::poll_participants() { participants_->drain(); }
ParticipantObservationReader CodingEngine::participant_observer() const {
  return participants_->observer();
}
void CodingEngine::shutdown_participants() {
  participants_->shutdown();
  if ((!cancelled || !cancelled()) && log_.root().state() == JournalWriterState::live)
    participants_->drain();
}
void recover_coding_session(RetainedState &root, RecoveryMode mode,
                            const RawAdapterContext *context) {
  const auto cursor = root.cursor();
  RawSessionCall whole{4440, 4441, context,
                       std::array{raw_native(mode), ByteView{cursor.journal.bytes()},
                                  raw_native(cursor.sequence),
                                  raw_native(cursor.end_offset)}};
  whole.run([&] {
    auto blocked = whole.control(41);
    struct CodingRecovery final : CustodyVerifier {
      struct Abandoned {
        OperationAttemptId attempt;
        std::string operation;
        bool local;
        bool uncontained;
      };
      RetainedState &root;
      RecoveryMode mode;
      RawSessionCall &whole;
      std::vector<Abandoned> abandoned;
      CodingRecovery(RetainedState &value, RecoveryMode selected, RawSessionCall &owner)
          : root(value), mode(selected), whole(owner) {}
      Result<void> verify(std::span<const AttemptState> attempts) override {
        const auto owner = whole.context();
        const auto count = attempts.size();
        RawSessionCall verify{4442, 4443, &owner, std::array{raw_native(count)}, 10};
        return verify.run([&] {
          for (const auto &attempt : attempts) {
            const auto parent = verify.context();
            RawSessionCall check{
                4444, 4445, &parent,
                std::array{ByteView{attempt.admission.attempt.bytes()},
                           ByteView{attempt.admission.decision.bytes()},
                           ByteView{attempt.admission.invocation.bytes()},
                           raw_native(attempt.opened)},
                10};
            const auto checked = check.run([&] {
              auto classify = [&]() -> Result<void> {
                auto decision_credit = check.control(89);
                const auto recovered_decision =
                    root.decision(attempt.admission.decision);
                if (!recovered_decision.has_value()) {
                  const std::uint8_t kind = 3;
                  const auto &error = recovered_decision.error();
                  (void)check.event(4446,
                                    std::array{raw_native(kind), raw_native(error.code),
                                               raw_native(error.detail)},
                                    decision_credit);
                  return Result<void>::failure(error);
                }
                const auto *decision = &recovered_decision.value();
                const std::uint8_t decision_kind = 1;
                (void)check.event(4446,
                                  std::array{raw_native(decision_kind),
                                             ByteView{decision->decision.bytes()},
                                             ByteView{decision->definition.bytes()},
                                             ByteView{decision->context.bytes()}},
                                  decision_credit);
                const auto metadata =
                    raw_restart_packet(check, 9, decision->continuation);
                if (!raw_restart_predicate(
                        check, 1, [&] { return metadata.has_value(); }, 4447))
                  return Result<void>::failure({ErrorCode::external_unknown});
                const auto *operation = metadata.value().find("operation");
                if (!raw_restart_predicate(
                        check, 2,
                        [&] {
                          return operation && std::holds_alternative<std::string>(
                                                  operation->value());
                        },
                        4447))
                  return Result<void>::failure({ErrorCode::external_unknown});
                const auto &name = operation->string();
                (void)raw_restart_source(check, 8, name);
                const bool provider = raw_restart_predicate(
                    check, 3,
                    [&] {
                      return name == "provider" || name == "colleague" ||
                             name == "participant_start" ||
                             name == "participant_send" || name == "participant_read" ||
                             name == "participant_cancel" ||
                             name == "participant_await" ||
                             name == "participant_join" ||
                             name == "participant_archive" ||
                             name == "participant_configure";
                    },
                    4447);
                const bool local = raw_restart_predicate(
                    check, 4,
                    [&] {
                      return name == "exec" || name == "process" ||
                             name == "read_file" || name == "write_file" ||
                             name == "edit_file" || name == "lua" ||
                             name == "workflow_execute" || name == "workflow_invoke";
                    },
                    4447);
                if (!provider &&
                    (!local || !raw_restart_predicate(
                                   check, 5,
                                   [&] {
                                     return mode ==
                                            RecoveryMode::acknowledge_local_unknowns;
                                   },
                                   4447)))
                  return Result<void>::failure({ErrorCode::external_unknown});
                const auto *input = metadata.value().find("input");
                const auto *generation = metadata.value().find("generation");
                const auto *revision = metadata.value().find("revision");
                const std::string_view admitted_input{
                    reinterpret_cast<const char *>(attempt.admission.input.data()),
                    attempt.admission.input.size()};
                (void)raw_restart_source(check, 14, admitted_input);
                auto invocation_credit = check.control(97);
                const auto recovered_invocation =
                    root.invocation(attempt.admission.invocation);
                if (!recovered_invocation.has_value()) {
                  const std::uint8_t kind = 4;
                  const auto &error = recovered_invocation.error();
                  (void)check.event(4446,
                                    std::array{raw_native(kind), raw_native(error.code),
                                               raw_native(error.detail)},
                                    invocation_credit);
                  (void)raw_restart_predicate(
                      check, 6, [&] { return recovered_invocation.has_value(); }, 4447);
                  return Result<void>::failure(error);
                }
                const auto &invocation = recovered_invocation.value();
                const std::uint8_t invocation_kind = 2;
                const auto input_size = invocation.input.size();
                (void)check.event(4446,
                                  std::array{raw_native(invocation_kind),
                                             ByteView{invocation.invocation.bytes()},
                                             ByteView{invocation.decision.bytes()},
                                             ByteView{invocation.definition.bytes()},
                                             raw_native(input_size)},
                                  invocation_credit);
                (void)raw_restart_predicate(
                    check, 6, [&] { return recovered_invocation.has_value(); }, 4447);
                const bool linked = raw_restart_predicate(
                    check, 7,
                    [&] {
                      return invocation.decision == decision->decision &&
                             invocation.definition == decision->definition &&
                             invocation.input == attempt.admission.input &&
                             decision->planned_invocations.size() == 1 &&
                             decision->planned_invocations.front() ==
                                 invocation.invocation;
                    },
                    4447);
                bool input_bound = false;
                if (const auto *binding = metadata.value().find("input_binding")) {
                  const auto *invocation_id = metadata.value().find("invocation");
                  const auto parsed_input = decode_packet_string(admitted_input);
                  input_bound =
                      parsed_input.has_value() &&
                      std::holds_alternative<Value::Object>(
                          parsed_input.value().value()) &&
                      !input && *binding == Value{"invocation-v1"} && invocation_id &&
                      *invocation_id ==
                          Value{raw_restart_hex(check, invocation.invocation.bytes())};
                } else if (input) {
                  auto encoded_credit = check.source_credit(ValueLimits{}.bytes);
                  const auto encoded_input = encode_packet_string(*input);
                  if (encoded_input.has_value())
                    (void)raw_restart_source(check, 10, encoded_input.value(),
                                             encoded_credit);
                  input_bound = std::holds_alternative<Value::Object>(input->value()) &&
                                encoded_input.has_value() &&
                                encoded_input.value() == admitted_input;
                }
                if (!linked ||
                    !raw_restart_predicate(
                        check, 8, [&] { return input_bound; }, 4447) ||
                    !raw_restart_predicate(
                        check, 9, [&] { return generation != nullptr; }, 4447) ||
                    !raw_restart_predicate(
                        check, 10, [&] { return revision != nullptr; }, 4447) ||
                    !raw_restart_predicate(
                        check, 11,
                        [&] {
                          return std::holds_alternative<std::string>(
                              generation->value());
                        },
                        4447) ||
                    !raw_restart_predicate(
                        check, 12,
                        [&] {
                          return std::holds_alternative<std::string>(revision->value());
                        },
                        4447))
                  return Result<void>::failure({ErrorCode::external_unknown});
                (void)raw_restart_source(check, 13, generation->string());
                if (!raw_restart_predicate(
                        check, 13,
                        [&] {
                          return generation->string() ==
                                 raw_restart_hex(check, decision->definition.bytes());
                        },
                        4447))
                  return Result<void>::failure({ErrorCode::external_unknown});
                (void)raw_restart_source(check, 13, revision->string());
                if (!raw_restart_predicate(
                        check, 14,
                        [&] {
                          return revision->string() ==
                                 raw_restart_hex(check, decision->context.bytes());
                        },
                        4447))
                  return Result<void>::failure({ErrorCode::external_unknown});
                auto collected = check.control(41);
                auto identity = check.control(56);
                abandoned.push_back(
                    {attempt.admission.attempt, name, local,
                     attempt.opened && (name == "exec" || name == "process")});
                const std::uint8_t mutation = 1;
                (void)check.event(4448, std::array{raw_native(mutation)}, collected);
                (void)check.event(
                    4449, std::array{ByteView{attempt.admission.attempt.bytes()}},
                    identity);
                return Result<void>::success();
              };
              const auto result = classify();
              raw_restart_result(check, result);
              return result;
            });
            if (!checked.has_value()) {
              raw_restart_result(verify, checked);
              return checked;
            }
          }
          const auto result = Result<void>::success();
          raw_restart_result(verify, result);
          return result;
        });
      }
    } custody{root, mode, whole};
    whole.stage(1);
    raw_restart_mutation(whole, 2, [&] { unwrap(root.reconcile(custody)); }, 4448);
    try {
      whole.stage(2);
      std::vector<RetainedEvent> observations;
      Value::Array uncontained_attempts;
      for (const auto &abandoned : custody.abandoned) {
        if (abandoned.local) {
          auto credit = whole.source_credit(ValueLimits{}.bytes);
          const auto observation = unwrap(encode_packet(Value::object(
              {{"recovery", Value{"acknowledge-local-unknowns"}},
               {"attempt", Value{raw_restart_hex(whole, abandoned.attempt.bytes())}},
               {"operation", Value{abandoned.operation}},
               {"outcome", Value{"unknown"}},
               {"uncontained_exec", Value{abandoned.uncontained}},
               {"message", Value{"Prior process operation abandoned; outcome unknown. "
                                 "No effect replayed, PID adopted or process exit "
                                 "or containment established."}}})));
          (void)raw_restart_source(
              whole, 11,
              {reinterpret_cast<const char *>(observation.data()), observation.size()},
              credit);
          observations.push_back(
              {{},
               AttemptObservationEvent{abandoned.attempt, AttemptPhase::terminal,
                                       AttemptDisposition::unknown, observation}});
          if (abandoned.uncontained)
            uncontained_attempts.emplace_back(
                raw_restart_hex(whole, abandoned.attempt.bytes()));
          continue;
        }
        constexpr std::string_view message =
            "Provider or participant operation abandoned during "
            "prior process; outcome unknown. "
            "No response accepted and no request replayed.";
        (void)raw_restart_source(whole, 11, message);
        const auto bytes = std::as_bytes(std::span{message.data(), message.size()});
        observations.push_back({{},
                                AttemptObservationEvent{abandoned.attempt,
                                                        AttemptPhase::terminal,
                                                        AttemptDisposition::unknown,
                                                        {bytes.begin(), bytes.end()}}});
      }
      if (!uncontained_attempts.empty()) {
        auto credit = whole.source_credit(ValueLimits{}.bytes);
        const auto marker = unwrap(encode_packet(Value::object(
            {{"label", Value{"session.recovery"}},
             {"metadata",
              Value::object({{"mode", Value{"acknowledge-local-unknowns"}},
                             {"uncontained_exec", Value{true}},
                             {"attempts", Value{std::move(uncontained_attempts)}}})},
             {"message", Value{"Prior process custody unavailable; outcome unknown. "
                               "No PID adopted or effect replayed."}}})));
        (void)raw_restart_source(
            whole, 12, {reinterpret_cast<const char *>(marker.data()), marker.size()},
            credit);
        observations.push_back(
            {{},
             ApplicationRecordEvent{unwrap(root.issue<ApplicationRecordId>()),
                                    ApplicationChannel::program, marker}});
      }
      if (!observations.empty()) {
        whole.stage(3);
        const auto parent = whole.context();
        const auto at = root.cursor();
        const auto count = observations.size();
        RawSessionCall append{4450, 4451, &parent,
                              std::array{ByteView{at.journal.bytes()},
                                         raw_native(at.sequence),
                                         raw_native(at.end_offset), raw_native(count)},
                              32};
        append.run([&] {
          auto completion = whole.control(41);
          const auto returned = unwrap(root.append(at, {}, observations));
          append.require_capture();
          append.finish(RawOperationBranch::returned, nullptr,
                        std::array{ByteView{returned.journal.bytes()},
                                   raw_native(returned.sequence),
                                   raw_native(returned.end_offset)});
          const std::uint8_t mutation = 3;
          (void)whole.event(4448, std::array{raw_native(mutation)}, completion);
        });
      }
    } catch (...) {
      root.block_admission();
      const std::uint8_t mutation = 4;
      (void)whole.event(4448, std::array{raw_native(mutation)}, blocked);
      throw;
    }
  });
}

Value CodingEngine::operation(
    std::string_view name, const Value &input,
    const std::function<Value(OperationAttemptId, InvocationId, DefinitionGenerationId,
                              CommandTaskActivity *, RawRetainedExec *)> &body,
    RawProviderOperationContext *provider_operation,
    const CommandStartStatus *command_start, const DomainAdmission *domain_admission,
    const FileEffectObservation *file_effect, OperationShaping shaping) {
  const auto &native_defaults = shaping.native_defaults;
  const auto &shape = shaping.shape;
  // Inside a model-boundary operation, a nested call answers only model calls from
  // responses that arrive after it began (T1).
  struct BoundaryFloor {
    std::uint64_t &floor;
    std::uint64_t previous;
    ~BoundaryFloor() { floor = previous; }
  } boundary_floor{boundary_floor_, boundary_floor_};
  if (shape)
    boundary_floor_ = response_generation_;
  auto &root = log_.root();
  struct FileObservationFence {
    const FileEffectObservation *effect;
    bool &blocked;
    bool retained = false;
    ~FileObservationFence() {
      if (effect && effect->applied() && !retained)
        blocked = true;
    }
  } file_observation{file_effect, file_effect_unretained_};
  RawOperationTrace trace{root};
  RawCaptureFailureScope operation_capture{trace.enabled()};
  std::optional<RawEventRef> parent;
  if (operation_trace_ && operation_trace_->reference().ordinal)
    parent = operation_trace_->reference();
  else if (provider_operation && provider_operation->parent &&
           provider_operation->parent->ordinal)
    parent = provider_operation->parent;
  trace.start(parent, generation_, operation_depth_, pumping_commands_,
              capacity_stopped_);
  auto *previous_trace = operation_trace_;
  operation_trace_ = &trace;
  struct RestoreOperation {
    RawOperationTrace *&selection;
    RawOperationTrace *previous;
    ~RestoreOperation() { selection = previous; }
  } restore_operation{operation_trace_, previous_trace};
  return trace.run([&]() -> Value {
    trace.stage(1);
    trace.name(name);
    poll_commands();
    std::string task_id;
    if (const auto *binding = input.find("task_id"); name == "exec" && binding) {
      task_id = binding->string();
      if (!task_id.empty() && !tasks_.state().item(task_id))
        throw Error{ErrorCode::invalid_range};
    }
    if (trace.callback(0, !pumping_commands_ && static_cast<bool>(cancelled),
                       [&] { return cancelled(); }))
      throw Error{ErrorCode::interrupted};
    trace.callback(1, static_cast<bool>(effect_policy),
                   [&] { effect_policy(name, input); });
    if (file_effect_unretained_)
      throw Error{ErrorCode::incomplete};
    if (capacity_stopped_ || operation_depth_ >= 16) {
      capacity_stopped_ = true;
      throw Error{ErrorCode::capacity};
    }
    if (root.protected_settlement()) {
      const std::uint64_t active = operation_depth_ + 1 + command_jobs_->debt();
      const auto refreshed =
          root.refresh_settlement({16 * 1024 + active * 8192, 16 + active * 16});
      if (!refreshed.has_value()) {
        if (refreshed.error().code == ErrorCode::capacity)
          capacity_stopped_ = true;
        throw refreshed.error();
      }
    }
    ++operation_depth_;
    struct Depth {
      std::size_t &value;
      ~Depth() { --value; }
    } depth{operation_depth_};
    const auto began = operation_completed || operation_outcome
                           ? std::chrono::steady_clock::now()
                           : std::chrono::steady_clock::time_point{};
    trace.callback(2, static_cast<bool>(operation_started),
                   [&] { operation_started(name); });
    trace.callback(3, static_cast<bool>(status), [&] {
      std::string description{name};
      for (const auto key : {"path", "command", "argv"}) {
        const auto *value = input.find(key);
        if (value) {
          description += " · " + unwrap(format_value(*value));
          break;
        }
      }
      status(description);
    });
    trace.stage(2);
    std::optional<RawProviderPhase> provider_result;
    if (provider_operation)
      provider_result.emplace(provider_link_credit);
    auto encode_original = [&](const Value &value, RawOperationOriginal role,
                               RawCapacityClaim *data,
                               std::optional<RawEventRef> provider = {}) {
      const ValueLimits limits{};
      const auto native_role = static_cast<std::uint8_t>(role);
      const std::array request{raw_native(native_role), raw_native(limits.bytes),
                               raw_native(limits.nodes), raw_native(limits.depth)};
      trace.event(2419, request);
      auto encoder_return = [&](RawOperationBranch branch, const Error *error,
                                const std::size_t *length) {
        std::array<ByteView, 4> fields{
            raw_native(native_role), raw_native(branch), {}, {}};
        std::size_t n = 2;
        if (error) {
          fields[n++] = raw_native(error->code);
          fields[n++] = raw_native(error->detail);
        }
        if (length)
          fields[n++] = raw_native(*length);
        trace.event(2418, std::span{fields}.first(n));
      };
      auto encoded = [&] {
        try {
          return unwrap(encode_packet(value));
        } catch (const Error &error) {
          encoder_return(RawOperationBranch::error, &error, nullptr);
          throw;
        } catch (const std::bad_alloc &) {
          encoder_return(RawOperationBranch::allocation, nullptr, nullptr);
          throw;
        } catch (const std::length_error &) {
          encoder_return(RawOperationBranch::length, nullptr, nullptr);
          throw;
        } catch (const std::exception &) {
          encoder_return(RawOperationBranch::standard, nullptr, nullptr);
          throw;
        } catch (...) {
          encoder_return(RawOperationBranch::nonstandard, nullptr, nullptr);
          throw;
        }
      }();
      const auto original = trace.original(role, encoded, data, provider);
      if (provider_operation && provider)
        provider_operation->result = original;
      trace.source(role, original);
      const auto length = encoded.size();
      encoder_return(RawOperationBranch::returned, nullptr, &length);
      return encoded;
    };
    const auto issue = [&]<class T>() {
      RawRegionPrepaidScope paid{trace.retained_bank()};
      return unwrap(root.issue<T>());
    };
    RawRegion admission{raw_regions::command_admission};
    trace.region({raw_lane_epoch(), admission.begin_ordinal()});
    const auto decision = issue.template operator()<DecisionId>();
    trace.identity(0, decision.bytes());
    const auto invocation = issue.template operator()<InvocationId>();
    trace.identity(1, invocation.bytes());
    const auto admitted_generation = generation_;
    trace.identity(3, admitted_generation.bytes());
    const auto attempt = issue.template operator()<OperationAttemptId>();
    trace.identity(2, attempt.bytes());
    const auto exec_id = name == "exec" ? hex_identity(attempt.bytes()) : std::string{};
    std::optional<RawCapacityClaim> input_data, result_data;
    if (trace.enabled())
      input_data.emplace(unwrap(raw_claim_data(49 + ValueLimits{}.bytes)));
    auto encoded_input = encode_original(input, RawOperationOriginal::input,
                                         input_data ? &*input_data : nullptr);
    input_data.reset();
    const ImmutableBytes bytes{std::move(encoded_input)};
    if (trace.enabled())
      result_data.emplace(unwrap(raw_claim_data(49 + ValueLimits{}.bytes)));
    const auto context = parse_id<ContextRevisionId>(context_.head());
    trace.identity(4, context.bytes());
    auto meta = Value::object(
        {{"operation", Value{std::string{name}}},
         {"input_binding", Value{"invocation-v1"}},
         {"input_encoding", Value{"bbm2"}},
         {"invocation", Value{hex_identity(invocation.bytes())}},
         {"revision", Value{context_.head()}},
         {"generation", Value{hex_identity(admitted_generation.bytes())}}});
    if (host_tools_ && host_tools_->find(name))
      meta.object().emplace_back("host_catalog", Value{host_tools_source_});
    if (!native_defaults.empty()) {
      Value::Array keys;
      for (const auto &key : native_defaults)
        keys.emplace_back(key);
      meta.object().emplace_back("native_defaults", Value{std::move(keys)});
    }
    if (!shaping.declared.empty())
      meta.object().emplace_back("declared_call_id", Value{shaping.declared});
    if (!shaping.refusal.empty())
      meta.object().emplace_back("call_id_refused", Value{shaping.refusal});
    const auto continuation_bytes = unwrap(encode_packet(meta));
    CommandTaskMap staged_tasks;
    CommandTaskMap::node_type task_node;
    if (!task_id.empty()) {
      staged_tasks.try_emplace(exec_id, task_activity, task_activity_native,
                               std::move(task_id), attempt, exec_id, std::string{name});
      task_node = staged_tasks.extract(exec_id);
    }
    struct TaskRun {
      CommandTaskActivity *activity;
      bool transferred = false;
      ~TaskRun() {
        if (activity && !transferred)
          activity->emit(3);
      }
    } task_run{task_node.empty() ? nullptr : &task_node.mapped()};
    if (task_run.activity) {
      task_run.activity->pending_node = &task_node;
      task_run.activity->transferred = &task_run.transferred;
    }
    // Fresh identities: one ordered batch, no authoritative partial admission.
    const std::array<RetainedEvent, 3> admitted{
        RetainedEvent{
            {},
            DecisionEvent{decision,
                          identity_.actor,
                          identity_.conversation,
                          identity_.workflow,
                          admitted_generation,
                          context,
                          {invocation},
                          {continuation_bytes.begin(), continuation_bytes.end()}}},
        RetainedEvent{
            {}, InvocationEvent{invocation, decision, admitted_generation, bytes}},
        RetainedEvent{
            {}, AttemptAdmissionEvent{attempt, invocation, decision, bytes, true}}};
    admission.linkage({raw_text(context_.head()), attempt.bytes()});
    trace.stage(3);
    const auto expected_admission = root.cursor();
    const std::uint8_t admission_kind = 0;
    const auto admission_count = admitted.size();
    const std::array admission_request{
        raw_native(admission_kind), ByteView{expected_admission.journal.bytes()},
        raw_native(expected_admission.sequence),
        raw_native(expected_admission.end_offset), raw_native(admission_count)};
    trace.event(2404, admission_request);
    std::optional<RawRetainedExec> exec_admission;
    exec_admission.emplace(root, trace.reference(),
                           name == "exec" ? RawRetainedExec::Kind::selected_exec
                                          : RawRetainedExec::Kind::adapter_receipt);
    try {
      const auto written = [&] {
        RawRegionPrepaidScope paid{trace.retained_bank()};
        return unwrap(exec_admission ? root.append_exec(expected_admission, admitted,
                                                        *exec_admission)
                                     : root.append(expected_admission, {}, admitted));
      }();
      const auto branch = RawOperationBranch::returned;
      const std::array fields{raw_native(admission_kind), raw_native(branch),
                              ByteView{written.journal.bytes()},
                              raw_native(written.sequence),
                              raw_native(written.end_offset)};
      trace.event(2405, fields);
    } catch (const Error &error) {
      const auto branch = RawOperationBranch::error;
      const std::array fields{raw_native(admission_kind), raw_native(branch),
                              raw_native(error.code), raw_native(error.detail)};
      trace.event(2405, fields);
      admission.error(error);
      admission.outcome(RawRegionOutcome::rejected);
      throw;
    } catch (const std::bad_alloc &) {
      const auto branch = RawOperationBranch::allocation;
      const std::array fields{raw_native(admission_kind), raw_native(branch)};
      trace.event(2405, fields);
      admission.outcome(RawRegionOutcome::exception);
      throw;
    } catch (const std::length_error &) {
      const auto branch = RawOperationBranch::length;
      const std::array fields{raw_native(admission_kind), raw_native(branch)};
      trace.event(2405, fields);
      admission.outcome(RawRegionOutcome::exception);
      throw;
    } catch (const std::exception &) {
      const auto branch = RawOperationBranch::standard;
      const std::array fields{raw_native(admission_kind), raw_native(branch)};
      trace.event(2405, fields);
      admission.outcome(RawRegionOutcome::exception);
      throw;
    } catch (...) {
      const auto branch = RawOperationBranch::nonstandard;
      const std::array fields{raw_native(admission_kind), raw_native(branch)};
      trace.event(2405, fields);
      admission.outcome(RawRegionOutcome::exception);
      throw;
    }
    admission.outcome(RawRegionOutcome::admitted);
    admission.finish();
    if (task_run.activity) {
      task_run.activity->bind({raw_lane_epoch(), admission.begin_ordinal()});
      task_run.activity->emit(0);
    }
    if (provider_operation) {
      provider_operation->owner = {
          attempt.bytes(), invocation.bytes(), admitted_generation.bytes(), {}};
      const RawAdapterContext attempt_context{&provider_operation->owner,
                                              provider_operation->parent, nullptr,
                                              &provider_operation->receipt};
      provider_operation->attempt_phase->start(3, &attempt_context);
      provider_operation->attempt_phase->stage(22);
    }
    Value result;
    std::string output;
    bool adapter_capacity = false, timed_out = false, persistent_command = false,
         command_refused = false, domain_refused = false;
    auto prepare = [&](Value adapter_result, const std::optional<Error> &effect_error,
                       bool presentation_fallback = false) {
      result = effect_error ? error_value(*effect_error) : std::move(adapter_result);
      if (effect_error && file_effect && file_effect->applied())
        result.object().emplace_back("effect_outcome", Value{"applied"});
      if (effect_error && !shaping.refusal.empty()) {
        result.object().emplace_back("reason", Value{shaping.refusal});
        result.object().emplace_back("call_id", Value{shaping.declared});
        result.object().emplace_back(
            "message",
            Value{shaping.refusal == "call_id_answered"
                      ? "An output already answers this call_id; the call was not run."
                      : "No model call with this call_id was received in this turn; "
                        "the call was not run."});
      }
      domain_refused = domain_admission && domain_admission->refusal() &&
                       effect_error && effect_error->code == ErrorCode::capacity &&
                       !operation_capture.error() && !root.raw_owner_blocked();
      if (name == "program_config" && effect_error && !domain_refused) {
        result.object().emplace_back(
            "message",
            Value{
                effect_error->code == ErrorCode::conflict
                    ? "Registration conflict: duplicate workflow name, alias, bare "
                      "name "
                      "or powerword, built-in command collision, or stale base "
                      "revision. "
                      "No candidate was staged."
                    : "Invalid program configuration: require modules/model/effort and "
                      "optional workflows/workflow_prefix. Workflow definitions "
                      "require "
                      "name, description, source (Lua body with args), aliases, bare "
                      "and "
                      "powerwords. No candidate was staged."});
      }
      if (name == "read_process_output" && effect_error &&
          effect_error->code == ErrorCode::unsupported && input.find("result_ref"))
        result.object().emplace_back(
            "message",
            Value{"This result_ref names a result with no text form within the "
                  "provider limits; it has no pages. Its original stays retained for "
                  "audit_inspect."});
      if (name == "read_process_output" && effect_error &&
          effect_error->code == ErrorCode::invalid_range) {
        result.object().emplace_back(
            "message",
            Value{
                "Provide exactly one of output_ref or result_ref (omit unused "
                "optional keys). Use optional range {mode: lines|bytes, start, end} "
                "(lines are 1-based inclusive; bytes 0-based half-open; end >= start) "
                "and do not mix range with legacy byte_start/byte_end. "
                "output_head_bytes must be <= output_max_bytes."});
        const auto *oref = input.find("output_ref");
        const auto *rref = input.find("result_ref");
        const bool use_result = rref &&
                                std::holds_alternative<std::string>(rref->value()) &&
                                !rref->string().empty();
        result.object().emplace_back(
            "example",
            Value::object(
                {{use_result ? "result_ref" : "output_ref",
                  use_result ? *rref
                  : (oref && std::holds_alternative<std::string>(oref->value()) &&
                     !oref->string().empty())
                      ? *oref
                      : Value{"<ref>"}},
                 {"range", Value::object({{"mode", Value{"lines"}},
                                          {"start", Value{Number{"1"}}},
                                          {"end", Value{Number{"80"}}}})}}));
      }
      if (name == "read_file" && effect_error &&
          effect_error->code == ErrorCode::invalid_range) {
        result.object().emplace_back(
            "message",
            Value{"Provide exactly one of path or snapshot. Use one range object "
                  "with mode lines or bytes and optional start/end; omit range for "
                  "the whole file. output_max_bytes must be a nonnegative integer. "
                  "Lines are one-based "
                  "inclusive, bytes zero-based half-open. Do not combine range "
                  "with legacy byte_/line_ fields. Endpoints must be nonnegative "
                  "integers, line start >=1, end >=start."});
        const auto *path = input.find("path");
        const auto *snapshot = input.find("snapshot");
        result.object().emplace_back(
            "example",
            Value::object({{snapshot ? "snapshot" : "path", snapshot ? *snapshot
                                                            : path   ? *path
                                                                     : Value{"file"}},
                           {"range", Value::object({{"mode", Value{"lines"}},
                                                    {"start", Value{Number{"1"}}},
                                                    {"end", Value{Number{"20"}}}})}}));
      }
      if ((name == "tasks_read" || name == "tasks_edit") && effect_error &&
          !domain_refused)
        result.object().emplace_back(
            "message",
            Value{
                "Require an object query or edit {op_id,ops}. add/move/archive/list "
                "need "
                "current list base; set/move/archive need the read item version. "
                "Exactly "
                "tasks and one level of subtasks. States "
                "queued/active/blocked/done/dropped. "
                "Read tasks_read for current IDs and versions. Batch limit64, page "
                "limit64; "
                "titles512 bytes, notes2048 bytes. No changes accepted for an invalid "
                "batch."});
      if (name == "lua" && effect_error && runtime_ && !runtime_->error.empty())
        result.object().emplace_back("lua_error",
                                     Value{std::exchange(runtime_->error, {})});

      adapter_capacity = domain_refused || (name == "process" && effect_error &&
                                            effect_error->code == ErrorCode::capacity);
      command_refused = command_start && effect_error &&
                        effect_error->code == ErrorCode::capacity &&
                        !command_start->worker_started &&
                        command_start->refusal != CommandStartStatus::Refusal::none;
      if (command_refused) {
        const bool live =
            command_start->refusal == CommandStartStatus::Refusal::live_limit;
        adapter_capacity = true;
        result.object().emplace_back("resource",
                                     Value{live ? "live_commands" : "command_records"});
        result.object().emplace_back("effect_outcome", Value{"not_started"});
        result.object().emplace_back("attempt", Value{exec_id});
        result.object().emplace_back(
            "count",
            Value{Number{live ? command_start->live : command_start->resident}});
        result.object().emplace_back(
            "limit",
            Value{Number{live ? command_start->max_live : command_start->max_records}});
        result.object().emplace_back(
            "message",
            Value{live ? "Live command limit reached; this command was not started. "
                         "Inspect process read or /jobs; wait for existing commands "
                         "or explicitly stop one before choosing further work."
                       : "Resident command record limit reached; this command was "
                         "not started. Inspect process read or /jobs; settle pending "
                         "output/controls or explicitly archive an eligible completed "
                         "job before choosing further work."});
      }
      if (domain_refused) {
        const auto &refusal = *domain_admission->refusal();
        result.object().emplace_back("resource",
                                     Value{admission_resource_name(refusal.resource)});
        result.object().emplace_back("effect_outcome", Value{"not_started"});
        result.object().emplace_back("attempt", Value{hex_identity(attempt.bytes())});
        if (refusal.count)
          result.object().emplace_back("count", Value{Number{*refusal.count}});
        if (refusal.limit)
          result.object().emplace_back("limit", Value{Number{*refusal.limit}});
        result.object().emplace_back(
            "message", Value{"Resource owner refused this request before publication; "
                             "prior accepted work is unchanged. Inspect the named "
                             "resource and choose further work. No automatic retry."});
      }
      timed_out = (effect_error && effect_error->code == ErrorCode::io &&
                   effect_error->detail == ETIMEDOUT) ||
                  (name == "exec" && result.find("timed_out") &&
                   field(result, "timed_out") == Value{true});
      persistent_command = name == "exec" && command_jobs_->contains(exec_id);
      if (name == "exec" && !command_refused && !result.find("output_ref")) {
        result.object().emplace_back("output_ref",
                                     Value{hex_identity(attempt.bytes())});
        if (timed_out) {
          result.object().emplace_back("timed_out", Value{true});
          result.object().emplace_back("effect_outcome", Value{"unknown"});
        }
      }
      auto encode = [&] {
        auto encoded = encode_original(
            result,
            presentation_fallback ? RawOperationOriginal::fallback
                                  : RawOperationOriginal::primary,
            !presentation_fallback && result_data ? &*result_data : nullptr,
            provider_result ? std::optional{provider_result->reference()}
                            : std::nullopt);
        result_data.reset();
        output.assign(reinterpret_cast<const char *>(encoded.data()), encoded.size());
      };
      if (provider_result) {
        provider_result->run([&] {
          const RawAdapterContext source_context{&provider_operation->owner,
                                                 std::nullopt, nullptr,
                                                 &provider_operation->receipt};
          provider_result->start(9, &source_context);
          provider_result->stage(24);
          if (provider_operation->receipt.response)
            provider_result->link(*provider_operation->receipt.response);
          encode();
        });
      } else
        encode();
    };
    struct Boundary final : EffectBoundary {
      const std::function<Value(OperationAttemptId, InvocationId,
                                DefinitionGenerationId, CommandTaskActivity *,
                                RawRetainedExec *)> &fn;
      decltype(prepare) &prepare_result;
      RawOperationTrace &trace;
      InvocationId invocation;
      DefinitionGenerationId generation;
      CommandTaskActivity *activity;
      RawRetainedExec *raw_exec;
      Value result;
      std::optional<Error> error, presentation_error;
      const FileEffectObservation *file_effect;
      const RawCaptureFailureScope &capture;
      RetainedState &root;
      std::exception_ptr deferred;
      std::optional<RawRegionPrepaidScope> receipt_scope;
      bool dispatched = false;
      Boundary(decltype(fn) body_fn, decltype(prepare) &preparation,
               RawOperationTrace &owner, InvocationId actual_invocation,
               DefinitionGenerationId actual_generation, CommandTaskActivity *task,
               RawRetainedExec *actual_exec, const FileEffectObservation *effect,
               const RawCaptureFailureScope &capture_scope, RetainedState &retained)
          : fn(body_fn), prepare_result(preparation), trace(owner),
            invocation(actual_invocation), generation(actual_generation),
            activity(task), raw_exec(actual_exec), file_effect(effect),
            capture(capture_scope), root(retained) {}
      Result<void> dispatch(const EffectIntent &intent) override {
        receipt_scope.reset();
        if (raw_exec)
          raw_exec->suspend();
        trace.stage(4);
        const auto input_bytes = intent.input.size();
        const std::array request{
            ByteView{intent.environment.bytes()}, ByteView{intent.actor.bytes()},
            ByteView{intent.invocation.bytes()}, ByteView{intent.attempt.bytes()},
            raw_native(input_bytes)};
        trace.event(2406, request);
        dispatched = true;
        auto returned = [&](RawOperationBranch branch,
                            const Error *native_error = nullptr) {
          const bool failed = native_error != nullptr;
          std::array<ByteView, 4> fields{
              raw_native(branch), raw_native(failed), {}, {}};
          std::size_t n = 2;
          if (native_error) {
            fields[n++] = raw_native(native_error->code);
            fields[n++] = raw_native(native_error->detail);
          }
          trace.event(2407, std::span{fields}.first(n));
        };
        RawOperationBranch actual_branch = RawOperationBranch::returned;
        std::optional<Error> native_error;
        try {
          result = fn(intent.attempt, invocation, generation, activity, raw_exec);
        } catch (const Error &e) {
          error = e;
          native_error = e;
          actual_branch = RawOperationBranch::error;
        } catch (const std::bad_alloc &) {
          error = Error{ErrorCode::allocation};
          actual_branch = RawOperationBranch::allocation;
        } catch (const std::length_error &) {
          error = Error{ErrorCode::external_unknown};
          actual_branch = RawOperationBranch::length;
        } catch (const std::exception &) {
          error = Error{ErrorCode::external_unknown};
          actual_branch = RawOperationBranch::standard;
        } catch (...) {
          error = Error{ErrorCode::external_unknown};
          deferred = std::current_exception();
          actual_branch = RawOperationBranch::nonstandard;
        }
        returned(actual_branch, native_error ? &*native_error : nullptr);
        if (raw_exec)
          raw_exec->resume();
        trace.stage(5);
        if (!deferred) {
          auto recover_allocation = [&] {
            if (!file_effect || !file_effect->applied() || capture.error() ||
                root.raw_owner_blocked())
              return;
            // One bounded presentation attempt; the adapter is never called again.
            // Keep its actual receipt separate from this preparation failure.
            presentation_error = Error{ErrorCode::allocation};
            try {
              prepare_result(Value{}, error ? error : presentation_error, true);
              deferred = nullptr;
            } catch (...) {
              // Preserve the first preparation failure; admission will fence below.
            }
          };
          try {
            prepare_result(std::move(result), error);
          } catch (const std::bad_alloc &) {
            deferred = std::current_exception();
            recover_allocation();
          } catch (const Error &failure) {
            deferred = std::current_exception();
            if (failure.code == ErrorCode::allocation)
              recover_allocation();
          } catch (...) {
            deferred = std::current_exception();
          }
        }
        // The real adapter receipt preserves the actual effect Result even if the
        // existing result preparation failed; no post-effect DATA admission occurs.
        receipt_scope.emplace(trace.retained_bank());
        return error ? Result<void>::failure(*error) : Result<void>::success();
      }
    } boundary{body,
               prepare,
               trace,
               invocation,
               admitted_generation,
               task_run.activity,
               exec_admission ? &*exec_admission : nullptr,
               file_effect,
               operation_capture,
               root};
    auto settle = [&](const RetainedEvent &event, bool settlement, bool fallback) {
      const auto &observation = std::get<AttemptObservationEvent>(event.body);
      const auto observation_bytes = observation.observation.size();
      const std::array request{raw_native(settlement),
                               raw_native(fallback),
                               ByteView{attempt.bytes()},
                               raw_native(observation.phase),
                               raw_native(observation.disposition),
                               raw_native(observation_bytes)};
      trace.event(2413, request);
      const auto recorded = [&] {
        RawRegionPrepaidScope paid{trace.retained_bank()};
        if (exec_admission)
          exec_admission->enter_terminal(trace.reference());
        return settlement ? root.submit_settlement(event) : root.submit(event);
      }();
      if (recorded.has_value()) {
        const auto branch = RawOperationBranch::returned;
        const auto &actual = recorded.value();
        const std::array fields{raw_native(branch), raw_native(actual.existing),
                                ByteView{actual.record.journal.bytes()},
                                raw_native(actual.record.sequence),
                                raw_native(actual.evidence)};
        trace.event(2414, fields);
      } else {
        const auto branch = RawOperationBranch::error;
        const std::array fields{raw_native(branch), raw_native(recorded.error().code),
                                raw_native(recorded.error().detail)};
        trace.event(2414, fields);
      }
      return recorded;
    };
    auto interrupted_terminal = [&](std::string_view message) {
      const auto bytes = std::as_bytes(std::span{message.data(), message.size()});
      const RetainedEvent event{{},
                                AttemptObservationEvent{attempt,
                                                        AttemptPhase::terminal,
                                                        AttemptDisposition::unknown,
                                                        {bytes.begin(), bytes.end()}}};
      (void)unwrap(settle(event, true, false));
    };
    const auto report = [&] {
      struct EndExecScope {
        RawRetainedExec *loan;
        ~EndExecScope() {
          if (loan)
            loan->leave();
        }
      } end{exec_admission ? &*exec_admission : nullptr};
      if (exec_admission && exec_admission->full_exec())
        exec_admission->enter(trace.reference(), RawRetainedOrigin::Input::ordinary);
      struct ClearReceiptScope {
        Boundary &owner;
        ~ClearReceiptScope() { owner.receipt_scope.reset(); }
      } clear{boundary};
      boundary.receipt_scope.emplace(trace.retained_bank());
      const std::array dispatch_request{ByteView{attempt.bytes()}};
      trace.event(2420, dispatch_request);
      const auto returned = [&](RawOperationBranch branch,
                                const Error *error = nullptr) {
        const bool failed = error != nullptr;
        std::array<ByteView, 4> fields{raw_native(branch), raw_native(failed), {}, {}};
        std::size_t count = 2;
        if (error) {
          fields[count++] = raw_native(error->code);
          fields[count++] = raw_native(error->detail);
        }
        trace.event(2421, std::span{fields}.first(count));
      };
      const auto dispatched = [&] {
        try {
          return root.dispatch(attempt, boundary,
                               exec_admission ? &*exec_admission : nullptr);
        } catch (const Error &error) {
          returned(RawOperationBranch::error, &error);
          throw;
        } catch (const std::bad_alloc &) {
          returned(RawOperationBranch::allocation);
          throw;
        } catch (const std::length_error &) {
          returned(RawOperationBranch::length);
          throw;
        } catch (const std::exception &) {
          returned(RawOperationBranch::standard);
          throw;
        } catch (...) {
          returned(RawOperationBranch::nonstandard);
          throw;
        }
      }();
      returned(RawOperationBranch::returned,
               dispatched.has_value() ? nullptr : &dispatched.error());
      if (!dispatched.has_value() && name == "exec" && !boundary.dispatched &&
          dispatched.error().code == ErrorCode::interrupted) {
        interrupted_terminal(
            "exec interrupted before adapter dispatch; no effect replayed");
      }
      auto actual = unwrap(dispatched);
      const bool effect_ok = actual.effect.has_value(),
                 recording_ok = actual.recording.has_value();
      std::array<ByteView, 7> fields{raw_native(actual.dispatched),
                                     raw_native(effect_ok),
                                     raw_native(recording_ok),
                                     {},
                                     {},
                                     {},
                                     {}};
      std::size_t n = 3;
      if (!effect_ok) {
        fields[n++] = raw_native(actual.effect.error().code);
        fields[n++] = raw_native(actual.effect.error().detail);
      }
      if (!recording_ok) {
        fields[n++] = raw_native(actual.recording.error().code);
        fields[n++] = raw_native(actual.recording.error().detail);
      }
      trace.event(2408, std::span{fields}.first(n));
      return actual;
    }();
    trace.stage(6);
    unwrap(report.recording);
    if (boundary.deferred) {
      if (file_effect && file_effect->applied())
        capacity_stopped_ = true;
      std::rethrow_exception(boundary.deferred);
    }
    if (!boundary.error && boundary.presentation_error)
      boundary.error = boundary.presentation_error;
    if (!report.dispatched)
      throw Error{ErrorCode::conflict};
    if (name == "exec" && boundary.error &&
        boundary.error->code == ErrorCode::interrupted &&
        !command_jobs_->contains(exec_id)) {
      interrupted_terminal("exec adapter interrupted before command registration; "
                           "outcome unknown; no replay");
      throw *boundary.error;
    }
    trace.stage(7);
    auto retain = [&](std::uint8_t kind, OriginalCapture capture) {
      const auto identity = issue.template operator()<ApplicationRecordId>();
      const auto expected = root.cursor();
      const std::array request{raw_native(kind), ByteView{identity.bytes()},
                               ByteView{expected.journal.bytes()},
                               raw_native(expected.sequence),
                               raw_native(expected.end_offset)};
      trace.event(2410, request);
      std::optional<SourceReference> source;
      try {
        RawRegionPrepaidScope paid{trace.retained_bank()};
        source = log_.original(identity, std::move(capture));
      } catch (const Error &error) {
        const auto branch = RawOperationBranch::error;
        const std::array fields{raw_native(kind), raw_native(branch),
                                raw_native(error.code), raw_native(error.detail)};
        trace.event(2411, fields);
        throw;
      } catch (const std::bad_alloc &) {
        const auto branch = RawOperationBranch::allocation;
        const std::array fields{raw_native(kind), raw_native(branch)};
        trace.event(2411, fields);
        throw;
      } catch (const std::length_error &) {
        const auto branch = RawOperationBranch::length;
        const std::array fields{raw_native(kind), raw_native(branch)};
        trace.event(2411, fields);
        throw;
      } catch (const std::exception &) {
        const auto branch = RawOperationBranch::standard;
        const std::array fields{raw_native(kind), raw_native(branch)};
        trace.event(2411, fields);
        throw;
      } catch (...) {
        const auto branch = RawOperationBranch::nonstandard;
        const std::array fields{raw_native(kind), raw_native(branch)};
        trace.event(2411, fields);
        throw;
      }
      const auto branch = RawOperationBranch::returned;
      if (!source)
        throw Error{ErrorCode::incomplete};
      const std::array fields{raw_native(kind), raw_native(branch),
                              ByteView{source->journal.bytes()},
                              raw_native(source->sequence)};
      trace.event(2411, fields);
      return identity;
    };
    std::string result_id;
    std::size_t result_record = 0;
    // A failure shaped to text keeps its status in its original's metadata, which
    // the failed selector reads by result_ref (T1).
    const bool failed_result = shape && failed_tool_output(result);
    try {
      auto result_metadata =
          Value::object({{"attempt", Value{hex_identity(attempt.bytes())}},
                         {"source_encoding", Value{"bbm2"}},
                         {"operation", Value{std::string{name}}}});
      if (failed_result)
        result_metadata.object().emplace_back("failed", Value{true});
      const auto identity =
          retain(0, {"operation.result", output, std::move(result_metadata)});
      result_id = hex_identity(identity.bytes());
      result_record = root.fact_count() - 1;
      file_observation.retained = true;
    } catch (const Error &e) {
      if (e.code != ErrorCode::capacity)
        throw;
      capacity_stopped_ = true;
      unretained_bytes_ += output.size();
      boundary.error = e;
      adapter_capacity = false;
      command_refused = false;
      domain_refused = false;
      if (command_jobs_->active()) {
        command_failure_ = e;
        const auto registry = command_jobs_->read(Value::object({}));
        for (const auto &job : field(registry, "jobs").array())
          if (string_field(job, "state") != "completed")
            command_jobs_->capture_failed(string_field(job, "job_id"));
        command_jobs_->shutdown();
      }
      result = error_value(e);
      if (file_effect && file_effect->applied())
        result.object().emplace_back("effect_outcome", Value{"applied"});
      auto fallback = encode_original(result, RawOperationOriginal::fallback, nullptr);
      output.assign(reinterpret_cast<const char *>(fallback.data()), fallback.size());
    }
    if (boundary.error && boundary.error->code == ErrorCode::capacity &&
        !adapter_capacity) {
      capacity_stopped_ = true;
      RetainedState::MaintenanceScope maintenance{root};
      const std::string_view message =
          file_effect && file_effect->applied()
              ? "file replacement applied; result capture failed; no replay; earlier "
                "originals retained"
              : "effect outcome unknown; no replay; earlier originals retained, "
                "rejected "
                "bytes not retained";
      const auto original = trace.original(RawOperationOriginal::capacity_message,
                                           raw_text(message), nullptr);
      trace.source(RawOperationOriginal::capacity_message, original);
      (void)retain(
          1, {"capacity.stop", message,
              Value::object({{"attempt", Value{hex_identity(attempt.bytes())}},
                             {"unretained_bytes", Value{Number{unretained_bytes_}}}})});
    }
    // Shaped once where the result becomes visible to the model (T1), after its whole
    // original is retained; the settlement records the shape applied.
    std::optional<ShapedResult> shaped;
    if (shape && !result_id.empty()) {
      const auto *text = std::get_if<std::string>(&result.value());
      const auto inner = text ? shaped_texts_.find(*text) : shaped_texts_.end();
      if (inner != shaped_texts_.end()) {
        // Itself one shaped result passed through whole: not cut again.
        shaped = ShapedResult{
            result, Value::object({{"pass_through", Value{inner->second}},
                                   {"text_bytes", Value{Number{text->size()}}}})};
      } else {
        shaped = shape_result(result, *shape, result_id);
        if (const auto *cut = std::get_if<std::string>(&shaped->presented.value());
            cut && shaped->summary.find("omitted"))
          shaped_texts_.insert_or_assign(*cut, result_id);
      }
      if (failed_result)
        shaped->summary.object().emplace_back("failed", Value{true});
    }
    // The result original is already retained. Settlement carries its locator,
    // not another complete response. On capture refusal retain the bounded error.
    auto settled = Value::object({{"result_id", Value{result_id}},
                                  {"result_record", Value{Number{result_record}}}});
    if (shaped)
      settled.object().emplace_back("shape", shaped->summary);
    if (shaped && !shaping.call_id.empty())
      settled.object().emplace_back("call_id", Value{shaping.call_id});
    const auto observed = unwrap(encode_packet(result_id.empty() ? result : settled));
    auto disposition =
        boundary.error ? AttemptDisposition::failure : AttemptDisposition::success;
    if (boundary.error && !adapter_capacity &&
        (boundary.error->code == ErrorCode::capacity || name == "provider" ||
         name == "exec" || name == "beads" || name == "colleague" ||
         name == "decision_model" || (host_tools_ && host_tools_->find(name))) &&
        (boundary.error->code == ErrorCode::capacity ||
         boundary.error->code == ErrorCode::interrupted ||
         boundary.error->code == ErrorCode::io ||
         boundary.error->code == ErrorCode::incomplete ||
         boundary.error->code == ErrorCode::allocation ||
         boundary.error->code == ErrorCode::external_unknown ||
         boundary.error->code == ErrorCode::provider_transport))
      disposition = AttemptDisposition::unknown;
    if (boundary.error && name == "beads" && beads_.mutation_may_have_started())
      disposition = AttemptDisposition::unknown;
    if (!boundary.error && name == "exec" && result.find("exit_code") &&
        field(result, "exit_code").number().text() != "0")
      disposition = AttemptDisposition::failure;
    if (!boundary.error && persistent_command && result.find("effect_outcome") &&
        string_field(result, "effect_outcome") == "unknown")
      disposition = AttemptDisposition::unknown;
    if (!boundary.error && name == "beads") {
      const auto state = string_field(result, "status");
      disposition = state == "unknown" ? AttemptDisposition::unknown
                    : (state == "ok" || state == "configured" || state == "cached")
                        ? AttemptDisposition::success
                        : AttemptDisposition::failure;
    }
    if (!boundary.error && name == "colleague") {
      const auto state = string_field(result, "status");
      const auto remote = string_field(result, "remote_disposition");
      disposition = remote == "unknown"    ? AttemptDisposition::unknown
                    : state == "completed" ? AttemptDisposition::success
                                           : AttemptDisposition::failure;
    }
    if (!boundary.error && host_tools_ && host_tools_->find(name)) {
      const auto &outcome = string_field(result, "outcome");
      disposition = outcome == "unknown"   ? AttemptDisposition::unknown
                    : outcome == "success" ? AttemptDisposition::success
                                           : AttemptDisposition::failure;
    }
    trace.disposition(disposition);
    const bool has_error = boundary.error.has_value();
    std::array<ByteView, 7> disposition_fields{raw_native(disposition),
                                               raw_native(timed_out),
                                               raw_native(persistent_command),
                                               raw_native(adapter_capacity),
                                               raw_native(has_error),
                                               {},
                                               {}};
    std::size_t disposition_count = 5;
    if (boundary.error) {
      disposition_fields[disposition_count++] = raw_native(boundary.error->code);
      disposition_fields[disposition_count++] = raw_native(boundary.error->detail);
    }
    trace.event(2412, std::span{disposition_fields}.first(disposition_count));
    trace.stage(8);

    RetainedEvent terminal{{},
                           AttemptObservationEvent{attempt,
                                                   AttemptPhase::terminal,
                                                   disposition,
                                                   {observed.begin(), observed.end()}}};
    if (!persistent_command) {
      struct EndTerminalScope {
        RawRetainedExec *loan;
        ~EndTerminalScope() {
          if (loan)
            loan->leave();
        }
      } end{exec_admission ? &*exec_admission : nullptr};
      auto recorded = settle(terminal, boundary.error.has_value(), false);
      if (!recorded.has_value() && recorded.error().code == ErrorCode::capacity) {
        capacity_stopped_ = true;
        adapter_capacity = false;
        command_refused = false;
        domain_refused = false;
        boundary.error = recorded.error();
        result = error_value(*boundary.error);
        if (file_effect && file_effect->applied())
          result.object().emplace_back("effect_outcome", Value{"applied"});
        const std::string bounded =
            file_effect && file_effect->applied()
                ? "capacity stop after dispatch; file replacement applied; no replay"
                : "capacity stop after dispatch; outcome unknown; no replay";
        const auto bounded_raw =
            std::as_bytes(std::span{bounded.data(), bounded.size()});
        disposition = AttemptDisposition::unknown;
        trace.disposition(disposition);
        recorded =
            settle({{},
                    AttemptObservationEvent{attempt,
                                            AttemptPhase::terminal,
                                            disposition,
                                            {bounded_raw.begin(), bounded_raw.end()}}},
                   true, true);
      }
      (void)unwrap(std::move(recorded));
    }
    if (task_run.activity && !task_run.transferred) {
      auto branch = disposition == AttemptDisposition::unknown   ? std::uint8_t{3}
                    : disposition == AttemptDisposition::failure ? std::uint8_t{2}
                                                                 : std::uint8_t{1};
      const Value *task_exit = nullptr;
      if (name == "exec" && !boundary.error && branch == 2)
        task_exit = result.find("exit_code");
      task_run.activity->emit(branch, task_exit);
    }
    const auto preview_lines = [](std::string_view text, char prefix) {
      std::string out;
      std::size_t pos = 0, emitted = 0, total = 0;
      while (pos < text.size()) {
        const auto lf = text.find('\n', pos);
        const auto end = lf == std::string_view::npos ? text.size() : lf;
        ++total;
        if (emitted < 3) {
          auto line = text.substr(pos, end - pos);
          if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
          const bool clipped = line.size() > 76;
          if (clipped) {
            std::size_t cut = 76;
            while (cut > 0 && (static_cast<unsigned char>(line[cut]) & 0xc0U) == 0x80U)
              --cut;
            line = line.substr(0, cut);
          }
          out += prefix;
          out += ' ';
          out.append(line);
          if (clipped)
            out += "...";
          out += '\n';
          ++emitted;
        }
        if (lf == std::string_view::npos)
          break;
        pos = lf + 1;
      }
      if (total > emitted)
        out += "  (+" + std::to_string(total - emitted) + " more lines)\n";
      return out;
    };
    const auto count_lines = [](std::string_view text) {
      if (text.empty())
        return std::size_t{0};
      auto n = static_cast<std::size_t>(std::count(text.begin(), text.end(), '\n'));
      return text.back() == '\n' ? n : n + 1;
    };
    std::string file_preview;
    if (!boundary.error && process_output) {
      if (name == "read_file") {
        if (const auto *content = result.find("content");
            content && std::holds_alternative<std::string>(content->value())) {
          const auto &text = content->string();
          file_preview = "[read " + std::to_string(count_lines(text)) + " lines · " +
                         std::to_string(text.size()) + " B]\n";
        }
      } else if (name == "write_file") {
        if (const auto *content = input.find("content");
            content && std::holds_alternative<std::string>(content->value())) {
          const auto &text = content->string();
          file_preview = "[wrote " + std::to_string(count_lines(text)) + " lines · " +
                         std::to_string(text.size()) + " B]\n";
        }
      } else if (name == "edit_file") {
        const auto *old_v = input.find("old");
        const auto *new_v = input.find("new");
        if (old_v && new_v && std::holds_alternative<std::string>(old_v->value()) &&
            std::holds_alternative<std::string>(new_v->value())) {
          file_preview =
              preview_lines(old_v->string(), '-') + preview_lines(new_v->string(), '+');
        }
      }
    }
    trace.stage(9);
    trace.callback(
        6,
        static_cast<bool>(process_output) &&
            ((boundary.error && name != "provider") || !file_preview.empty()),
        [&] {
          if (boundary.error && name != "provider") {
            process_output("\n[" + std::string{name} + ": " +
                           error_name(boundary.error->code) + "]" +
                           ((command_refused || domain_refused)
                                ? " " + string_field(result, "message")
                            : file_effect && file_effect->applied()
                                ? " file replacement applied; no replay"
                                : std::string{}) +
                           "\n");
          } else {
            process_output(file_preview);
          }
        });
    if (operation_completed || operation_outcome) {
      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - began)
                               .count();
      const auto outcome =
          (command_refused || domain_refused) ? "refused; not started"
          : boundary.error && file_effect && file_effect->applied()
              ? "file replacement applied; result failed"
          : persistent_command && !boundary.error && !result.find("exit_code")
              ? "backgrounded"
          : timed_out && name == "exec"                ? "timed out; outcome unknown"
          : disposition == AttemptDisposition::success ? "completed"
          : disposition == AttemptDisposition::unknown ? "stopped; outcome unknown"
          : boundary.error && boundary.error->code == ErrorCode::interrupted
              ? "interrupted (recorded failure)"
              : "failed";
      const auto completion =
          std::string{name} + " " + outcome + " · " + std::to_string(elapsed) + "ms";
      trace.callback(4, static_cast<bool>(operation_outcome),
                     [&] { operation_outcome(completion, disposition); });
      trace.callback(5, static_cast<bool>(operation_completed),
                     [&] { operation_completed(completion); });
    }
    if (command_failure_ && boundary.error &&
        boundary.error->code == ErrorCode::capacity) {
      try {
        poll_commands();
      } catch (const Error &error) {
        if (error.code != ErrorCode::capacity)
          throw;
      }
    }
    if (boundary.error &&
        ((boundary.error->code == ErrorCode::capacity && !adapter_capacity) ||
         boundary.error->code == ErrorCode::interrupted ||
         (name == "provider" || name == "workflow_execute") ||
         root.state() != JournalWriterState::live))
      throw *boundary.error;
    if (name == "beads") {
      const auto *stopped = result.find("interrupted");
      if (stopped && std::get<bool>(stopped->value()))
        throw Error{ErrorCode::interrupted};
    }
    if (shaped)
      return std::move(shaped->presented);
    return result;
  });
}

Value CodingEngine::execute_workflow(WorkflowContinuation &invocation,
                                     bool continuation) {
  try {
    const RawProgramContext origin{invocation.selection, generation_.bytes()};
    RawProgramCall trace{3820, 3821, &origin,
                         std::array{ByteView{generation_.bytes()},
                                    raw_native(workflow_depth_),
                                    raw_native(workflow_invocations_)},
                         2 * sizeof(unsigned)};
    invocation.parked.finish(0, nullptr, trace.reference());
    auto end = [&](RawOperationBranch branch, const Error *error = nullptr) {
      trace.finish(
          branch, error,
          std::array{raw_native(workflow_depth_), raw_native(workflow_invocations_)});
    };
    try {
      auto guard = trace.control(48);
      auto association = trace.control(72 + invocation.revision.size());
      auto identities = trace.control(88);
      if (workflow_depth_ >= 8) {
        trace.event(
            3824,
            std::array{raw_native(workflow_depth_), raw_native(workflow_invocations_)},
            guard);
        throw Error{ErrorCode::capacity};
      }
      ++workflow_invocations_;
      trace.event(
          3824,
          std::array{raw_native(workflow_depth_), raw_native(workflow_invocations_)},
          guard);
      if (workflow_invocations_ > 64)
        throw Error{ErrorCode::capacity};
      // A drained continuation's result enters context as a developer item, outside
      // any tool call: its own operation shapes it (design §9).
      OperationShaping shaping;
      if (continuation)
        shaping.shape = invocation.shape.value_or(ResultShape{});
      auto result = operation(
          "workflow_execute", invocation.arguments,
          [&](OperationAttemptId attempt, InvocationId invocation_id,
              DefinitionGenerationId generation, CommandTaskActivity *,
              RawRetainedExec *) {
            trace.event(3822,
                        std::array{ByteView{attempt.bytes()},
                                   ByteView{invocation_id.bytes()},
                                   ByteView{generation.bytes()}},
                        identities);
            const auto operation_ref =
                operation_trace_ ? operation_trace_->reference() : RawEventRef{};
            const auto revision_size = invocation.revision.size();
            trace.event(3823,
                        std::array{ByteView{operation_ref.lane},
                                   raw_native(operation_ref.ordinal),
                                   raw_native(revision_size),
                                   raw_text(invocation.revision)},
                        association);
            const auto metadata = Value::object(
                {{"name", field(invocation.definition, "name")},
                 {"revision", Value{invocation.revision}},
                 {"definition", invocation.definition},
                 {"invocation", invocation.arguments},
                 {"generation", Value{hex_identity(generation_.bytes())}},
                 {"attempt", Value{hex_identity(attempt.bytes())}},
                 {"selection_attempt", Value{invocation.selection_attempt}}});
            log_.original({"workflow.source",
                           string_field(invocation.definition, "source"), metadata});
            log_.record(ApplicationChannel::program, metadata);
            ++workflow_depth_;
            struct Depth {
              unsigned &n;
              ~Depth() { --n; }
            } depth{workflow_depth_};
            Runtime child{*this};
            const auto wrapper_origin = trace.context();
            return child.invoke_tool({.definition = invocation.definition,
                                      .arguments = invocation.arguments,
                                      .origin = &wrapper_origin});
          },
          nullptr, nullptr, nullptr, nullptr, std::move(shaping));
      end(RawOperationBranch::returned);
      return result;
    } catch (const Error &error) {
      end(RawOperationBranch::error, &error);
      throw;
    } catch (const std::bad_alloc &) {
      end(RawOperationBranch::allocation);
      throw;
    } catch (const std::length_error &) {
      end(RawOperationBranch::length);
      throw;
    } catch (const std::exception &) {
      end(RawOperationBranch::standard);
      throw;
    } catch (...) {
      end(RawOperationBranch::nonstandard);
      throw;
    }
  } catch (const Error &e) {
    invocation.parked.finish(0, &e);
    workflow_failure_ = e;
    throw;
  } catch (...) {
    invocation.parked.finish(0);
    throw;
  }
}
void CodingEngine::drain_workflows() {
  if (draining_workflows_ || workflow_continuations_.empty())
    return;
  const RawProgramContext origin{std::nullopt, {}};
  const auto count = workflow_continuations_.size();
  RawProgramCall trace{3825, 3826, &origin,
                       std::array{raw_native(draining_workflows_), raw_native(count)}};
  trace.run([&] {
    validate_protocol(context_.items());
    draining_workflows_ = true;
    struct Drain {
      bool &flag;
      ~Drain() { flag = false; }
    } drain{draining_workflows_};
    while (!workflow_continuations_.empty()) {
      if (restart_note_)
        throw Error{ErrorCode::busy};
      if (cancelled && cancelled())
        throw Error{ErrorCode::interrupted};
      auto next = std::move(workflow_continuations_.front());
      workflow_continuations_.erase(workflow_continuations_.begin());
      const auto result = execute_workflow(next, true);
      // The same text a tool output's provider receives, so result_ref offsets agree.
      context_.append(
          {Value::object(
              {{"role", Value{"developer"}},
               {"content",
                Value{"Registered workflow " + string_field(next.definition, "name") +
                      " completed in this turn: " + result_text(result)}}})},
          "workflow-continuation");
    }
  });
}

Value CodingEngine::stats() const {
  auto result = context_.stats();
  const auto journal = log_.root().journal_usage();
  const auto maintenance_error = log_.root().maintenance_error();
  result.object().emplace_back(
      "maintenance_error", maintenance_error
                               ? Value{std::string{error_name(maintenance_error->code)}}
                               : Value{});
  result.object().emplace_back("resident_tail_records",
                               Value{Number{log_.root().tail_facts().size()}});
  auto number = [](std::uint64_t n) { return Value{Number{n}}; };
  result.object().emplace_back(
      "audit",
      Value::object(
          {{"scope", Value{"physical observation; not admission permission or "
                           "reserved headroom"}},
           {"journal", Value{hex_identity(journal.prefix.journal.bytes())}},
           {"prefix_end", number(journal.prefix.end_offset)},
           {"observed_extent",
            journal.observed_extent ? number(*journal.observed_extent) : Value{}},
           {"max_file_bytes", number(journal.limit.max_file_bytes)},
           {"remaining_bytes",
            journal.remaining_bytes() ? number(*journal.remaining_bytes()) : Value{}},
           {"max_records", number(journal.limit.max_records)},
           {"indexed_records", number(journal.indexed_records)},
           {"remaining_records", number(journal.remaining_records())},
           {"writer_state", number(static_cast<unsigned>(journal.state))},
           {"approaching", Value{journal.approaching()}},
           {"extent_error",
            journal.extent_error
                ? Value::object(
                      {{"code",
                        Value{std::string{error_name(journal.extent_error->code)}}},
                       {"detail", Value{Number{journal.extent_error->detail}}}})
                : Value{}}}));
  result.object().emplace_back("last_request_bytes", last_request_bytes_);
  result.object().emplace_back("usage", usage_);
  result.object().emplace_back("upstream_epoch", number(upstream_epoch_));
  result.object().emplace_back("pending_compactions",
                               number(pending_compactions_.size()));
  Value::Object session_usage{
      {"requests", number(telemetry_.requests)},
      {"input_tokens", number(telemetry_.input_tokens)},
      {"output_tokens", number(telemetry_.output_tokens)},
      {"cached_tokens", number(telemetry_.cached_tokens)},
      {"cache_write_tokens", number(telemetry_.cache_write_tokens)},
      {"reasoning_tokens", number(telemetry_.reasoning_tokens)},
      {"last_duration_ms", number(telemetry_.last_duration_ms)},
      {"last_ttft_ms", number(telemetry_.last_ttft_ms)},
      {"context_window_tokens", telemetry_.context_window_tokens
                                    ? number(*telemetry_.context_window_tokens)
                                    : Value{}}};
  if (telemetry_.session_cost_usd && std::isfinite(*telemetry_.session_cost_usd))
    session_usage.emplace_back("session_cost_usd",
                               Value{Number{*telemetry_.session_cost_usd}});
  result.object().emplace_back("session_usage",
                               Value::object(std::move(session_usage)));
  result.object().emplace_back("uncontained_exec_recovery",
                               Value{uncontained_exec_recovery_});
  result.object().emplace_back(
      "request_scope", Value{"last request in this process; null if unavailable"});
  return result;
}
void CodingEngine::validate_session_switch(const RawAdapterContext *context) const {
  const std::uint8_t method = 3;
  RawSessionCall call{4420, 4421, context,
                      std::array{raw_native(method), ByteView{generation_.bytes()}}};
  call.run([&] {
    if (raw_restart_predicate(
            call, 2, [&] { return participants_->active(); }, 4422) ||
        raw_restart_predicate(call, 3, [&] { return command_jobs_->active(); }, 4422))
      throw Error{ErrorCode::busy};
  });
}
void CodingEngine::validate_restart(const RawAdapterContext *context) const {
  const std::uint8_t method = 4;
  RawSessionCall call{4420, 4421, context,
                      std::array{raw_native(method), ByteView{generation_.bytes()}}};
  call.run([&] {
    if (raw_restart_predicate(
            call, 4, [&] { return uncontained_exec_recovery_; }, 4422))
      throw Error{ErrorCode::external_unknown};
    const auto parent = call.context();
    validate_session_switch(&parent);
    validate_protocol(context_.items());
  });
}
std::optional<std::string>
CodingEngine::take_restart_note(const RawAdapterContext *context) {
  const std::uint8_t method = 2;
  RawSessionCall call{4420, 4421, context,
                      std::array{raw_native(method), ByteView{generation_.bytes()}}};
  return call.run([&] {
    if (raw_restart_predicate(call, 1, [&] { return restart_note_.has_value(); }, 4422))
      (void)raw_restart_source(call, 1, *restart_note_);
    std::optional<std::string> result;
    raw_restart_mutation(
        call, 1, [&] { result = std::exchange(restart_note_, std::nullopt); }, 4423);
    return result;
  });
}
void CodingEngine::effort(std::string value) {
  if (value != "low" && value != "medium" && value != "high" && value != "xhigh" &&
      value != "max")
    throw Error{ErrorCode::invalid_range};
  effort_ = std::move(value);
}
void CodingEngine::set_provider(CodingProvider &next) {
  if (turn_running_)
    throw Error{ErrorCode::busy};
  provider_ = &next;
  last_provider_identity_.clear();
  last_provider_request_at_.reset();
  ++upstream_epoch_;
}
std::string CodingEngine::definition_model() const {
  const auto &configured = string_field(program_config_, "model");
  return configured.empty() ? model_ : configured;
}

void CodingEngine::present(const Value &item) {
  std::string text;
  for (const auto &part : field(item, "content").array())
    if (string_field(part, "type") == "output_text")
      text += string_field(part, "text");
  const auto *id = item.find("id");
  auto found = previewed_.find(id ? id->string() : "");
  if (found != previewed_.end()) {
    if (!text.starts_with(found->second)) {
      if (notice || display)
        (notice ? notice
                : display)("\n[Final response differs from streamed preview]\n");
    } else
      text.erase(0, found->second.size());
    previewed_.erase(found);
  }
  if (!text.empty()) {
    log_.original({"display", text, Value{}});
    if (display)
      display(text);
  }
}
Error CodingEngine::claim_backstop(const RawAdapterContext *raw_context) {
  RawSessionCall claim{4710, 4711, raw_context, {}, 9};
  return claim.run([&] {
    auto predicate = [&](std::uint8_t kind, auto &&evaluate) {
      auto credit = claim.control(42);
      const bool value = evaluate();
      (void)claim.event(
          4703,
          std::array{detail::raw_native_field(kind), detail::raw_native_field(value)},
          credit);
      return value;
    };
    if (predicate(21, [&] { return turn_running_; }) ||
        predicate(22, [&] { return operation_depth_ != 0; }) ||
        predicate(23, [&] { return !failed_turn_; }) ||
        predicate(24, [&] { return backstop_claimed_; }) ||
        predicate(25, [&] { return failed_turn_->code == ErrorCode::interrupted; }) ||
        predicate(26, [&] { return cancelled && cancelled(); }) ||
        predicate(27, [&] { return uncontained_exec_recovery_; }) ||
        predicate(28, [&] { return !detail::locally_quiescent(); }) ||
        predicate(29, [&] { return log_.root().state() != JournalWriterState::live; }))
      throw Error{ErrorCode::conflict};
    auto mutation = claim.control(41);
    backstop_claimed_ = true;
    const std::uint8_t kind = 1;
    (void)claim.event(4706, std::array{detail::raw_native_field(kind)}, mutation);
    claim.finish(RawOperationBranch::returned, nullptr,
                 std::array{detail::raw_native_field(failed_turn_->code),
                            detail::raw_native_field(failed_turn_->detail)});
    return *failed_turn_;
  });
}

Value CodingEngine::operator_call(std::string_view name, const Value &arguments) {
  // Quote only the operation name; arguments transfer as native values.
  auto literal = [](std::string_view value) {
    std::string out = "\"";
    for (const char ch : value) {
      const auto c = static_cast<unsigned char>(ch);
      out += "\\";
      out += static_cast<char>('0' + c / 100);
      out += static_cast<char>('0' + (c / 10) % 10);
      out += static_cast<char>('0' + c % 10);
    }
    return out + "\"";
  };
  const auto program = "return blackbird.call(" + literal(name) + ",_native_args)";
  operator_arguments_ = arguments;
  struct OperatorScope {
    bool &active;
    bool previous;
    ~OperatorScope() { active = previous; }
  } scope{operator_call_, operator_call_};
  operator_call_ = true;
  turn({"", program});
  return workflow_result_;
}
bool CodingEngine::operator_turn(std::string_view prompt, std::string_view fallback) {
  const RawProgramContext origin{{}, generation_.bytes()};
  RawProgramCall trace{6, &origin};
  return trace.run([&] {
    if (prompt.empty())
      return false;
    const auto selection_origin = trace.context();
    const auto selected = workflows_->select(prompt, &selection_origin);
    if (!selected) {
      if (prompt.starts_with("/"))
        return false;
      turn({prompt, fallback});
      return true;
    }
    const auto invocation =
        Value::object({{"name", field(selected->definition, "name")},
                       {"arguments", Value{selected->arguments}},
                       {"prompt", Value{std::string{prompt}}},
                       {"trigger", Value{selected->trigger}},
                       {"origin", Value{"operator"}}});
    operator_arguments_ = invocation;
    const auto program = "return blackbird.call('workflow_invoke',_native_args)";
    // The operator's own invocation is its outermost call: its result stays exact.
    // The workflow's own calls return whole results; only calls that answer a model
    // call are shaped (T1).
    struct OperatorScope {
      bool &active;
      bool previous;
      ~OperatorScope() { active = previous; }
    } scope{operator_call_, operator_call_};
    operator_call_ = true;
    turn({prompt, program});
    return true;
  });
}
void CodingEngine::turn(TurnInput input) {
  if (backstop_claimed_ || turn_running_)
    throw Error{ErrorCode::conflict};
  if (file_effect_unretained_)
    throw Error{ErrorCode::incomplete};
  const auto is_null = [](const Value &value) noexcept {
    return std::holds_alternative<std::nullptr_t>(value.value());
  };
  const auto clear_value = [](Value &value) noexcept {
    const auto discarded = std::move(value);
  };
  const auto clear_pending = [&]() noexcept {
    pending_program_trace_.finish(2);
    pending_tools_trace_.finish(2);
    pending_workflows_.reset();
    pending_hooks_.reset();
    clear_value(pending_program_config_);
    pending_program_revision_.clear();
    clear_value(pending_lua_tools_);
    pending_tools_revision_.clear();
  };
  turn_running_ = true;
  struct Running {
    CodingEngine &engine;
    ~Running() {
      engine.turn_running_ = false;
      engine.model_calls_.clear();
      engine.answered_calls_.clear();
      engine.declared_turn_ = false;
      engine.shaped_texts_.clear();
      engine.cached_result_ref_.clear();
      engine.cached_result_text_ = std::string{};
      for (auto &continuation : engine.workflow_continuations_)
        continuation.parked.finish(1);
      engine.workflow_continuations_.clear();
      engine.operator_arguments_.reset();
      if (!engine.command_jobs_->debt())
        engine.settlement_.reset();
    }
  } running{*this};

  auto &root = log_.root();
  try {
    const auto rollback = [&](const Error *error) {
      pending_compactions_.clear();
      clear_pending();
      restart_note_.reset();
      if (error &&
          (error->code == ErrorCode::interrupted ||
           error->code == ErrorCode::capacity) &&
          root.state() == JournalWriterState::live) {
        RetainedState::MaintenanceScope maintenance{root};
        (void)context_.close_open_exchanges(error->code == ErrorCode::interrupted);
      }
    };
    try {
      failed_turn_.reset();
      pending_compactions_.clear();
      clear_value(workflow_result_);
      workflow_continuations_.clear();
      workflow_invocations_ = 0;
      workflow_failure_.reset();
      clear_pending();
      restart_note_.reset();
      capacity_stopped_ = false;
      unretained_bytes_ = 0;

      // Reserve a small fixed headroom so an out-of-space or interrupted turn can
      // still record its terminal observation and stop linkage without closing the log.
      {
        const std::uint64_t active = 1 + command_jobs_->debt();
        const JournalCapacity floor{16 * 1024 + active * 8192, 16 + active * 16};
        if (settlement_) {
          (void)root.refresh_settlement(floor);
        } else if (auto guard = root.protect_settlement(floor); guard.has_value()) {
          settlement_ = std::move(guard).value();
        }
      }

      // Close any dangling unanswered tool calls left over from an earlier crash/abort.
      if (context_.has_open_exchanges())
        (void)context_.close_open_exchanges(false);

      // Retain governing program source only when it changes (avoids repeating the
      // exact same turn.lua into the audit journal on every single turn).
      if (input.program != last_retained_program_ || !root_source_.has_value()) {
        generation_ = unwrap(root.issue<DefinitionGenerationId>());
        root_source_ = log_.retain_program(input.program, generation_);
        root_source_length_ = input.program.size();
        last_retained_program_ = std::string{input.program};
      }

      if (!input.prompt.empty())
        context_.append(
            {Value::object({{"role", Value{"user"}},
                            {"content", Value{std::string{input.prompt}}}})},
            "operator", BlockKind::instruction);

      if (!operator_call_ && hooks_ && !hooks_->definitions().empty()) {
        const HookMatchSample sample{.event = HookEvent::turn_start,
                                     .tool = {},
                                     .prompt = std::string{input.prompt}};
        const auto payload =
            Value::object({{"event", Value{"turn_start"}},
                           {"prompt", Value{std::string{input.prompt}}},
                           {"live_blocks", Value{Number{context_.blocks().size()}}},
                           {"total_bytes", Value{Number{context_.total_bytes()}}}});
        (void)run_hooks(sample, payload);
      }

      runtime_ = std::make_unique<Runtime>(*this);
      workflow_result_ = runtime_->eval(
          input.program, operator_arguments_ ? &*operator_arguments_ : nullptr);
      operator_arguments_.reset();
      drain_workflows();

      if (workflow_failure_)
        throw *workflow_failure_;
      if (capacity_stopped_)
        throw Error{ErrorCode::capacity};
      if (cancelled && cancelled())
        throw Error{ErrorCode::interrupted};
      if (restart_note_)
        validate_protocol(context_.items());

      // Flush any deferred context compactions cleanly at the turn boundary.
      (void)flush_pending_compactions("turn end");

      if (!operator_call_ && hooks_ && !hooks_->definitions().empty()) {
        const HookMatchSample sample{.event = HookEvent::turn_end,
                                     .tool = {},
                                     .prompt = std::string{input.prompt}};
        const auto payload =
            Value::object({{"event", Value{"turn_end"}},
                           {"prompt", Value{std::string{input.prompt}}},
                           {"live_blocks", Value{Number{context_.blocks().size()}}},
                           {"total_bytes", Value{Number{context_.total_bytes()}}},
                           {"upstream_epoch", Value{Number{upstream_epoch_}}}});
        (void)run_hooks(sample, payload);
      }

      // Activate any pending Lua program config or tool definitions cleanly at turn
      // end.
      const bool activate_program = !is_null(pending_program_config_);
      const bool activate_tools = !is_null(pending_lua_tools_);
      if (activate_program || activate_tools) {
        const auto boundary_program = Value::object(
            {{"label", Value{"workflow-config-effective-v1"}},
             {"program_config",
              activate_program ? pending_program_config_ : program_config_},
             {"program_revision",
              Value{activate_program ? pending_program_revision_ : program_revision_}},
             {"tools", activate_tools ? pending_lua_tools_ : lua_tools_},
             {"tools_revision",
              Value{activate_tools ? pending_tools_revision_ : tools_revision_}},
             {"activation", Value{"turn-boundary"}}});
        (void)log_.record(ApplicationChannel::program, boundary_program);
        if (activate_program) {
          program_config_.swap(pending_program_config_);
          program_revision_.swap(pending_program_revision_);
          workflows_.swap(pending_workflows_);
          hooks_.swap(pending_hooks_);
          pending_program_trace_.finish(0);
        }
        if (activate_tools) {
          lua_tools_.swap(pending_lua_tools_);
          tools_revision_.swap(pending_tools_revision_);
          pending_tools_trace_.finish(0);
        }
        clear_pending();
        if (activate_program && hooks_changed)
          hooks_changed();
      }
    } catch (const Error &error) {
      rollback(&error);
      throw;
    } catch (...) {
      rollback(nullptr);
      throw;
    }
  } catch (const Error &error) {
    failed_turn_ = error;
    throw;
  } catch (const std::bad_alloc &) {
    failed_turn_ = Error{ErrorCode::allocation};
    throw;
  } catch (...) {
    failed_turn_ = Error{ErrorCode::external_unknown};
    throw;
  }
}

} // namespace blackbird
