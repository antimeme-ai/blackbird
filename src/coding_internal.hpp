#pragma once

#include "blackbird/coding.hpp"
#include "blackbird/raw_operation.hpp"
#include "blackbird/raw_runtime.hpp"
#include <charconv>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace blackbird {
namespace coding_detail {

template <class T> ByteView raw_native(const T &value) noexcept {
  return std::as_bytes(std::span{&value, std::size_t{1}});
}

inline ByteView raw_text(std::string_view value) noexcept {
  return std::as_bytes(std::span{value.data(), value.size()});
}

inline RawProgramContext program_origin(const RawOperationTrace *operation,
                                        DefinitionGenerationId generation) noexcept {
  return {operation ? std::optional{operation->reference()} : std::nullopt,
          generation.bytes()};
}

template <class T> T parse_id(std::string_view s) {
  if (s.size() != 32)
    throw Error{ErrorCode::invalid_identity};
  IdentityBytes out{};
  for (std::size_t i = 0; i < 16; ++i) {
    unsigned n = 0;
    const auto r = std::from_chars(s.data() + 2 * i, s.data() + 2 * i + 2, n, 16);
    if (r.ec != std::errc{} || r.ptr != s.data() + 2 * i + 2)
      throw Error{ErrorCode::invalid_identity};
    out[i] = static_cast<std::byte>(n);
  }
  return unwrap(T::from_bytes(out));
}

Value error_value(Error e);
void validate_protocol(const Value::Array &items,
                       std::optional<RawEventRef> parent = std::nullopt);
bool failed_tool_output(const Value &result) noexcept;

} // namespace coding_detail

struct CodingEngine::CommandTaskActivity {
  std::function<void(const Value &)> &observer;
  std::function<void(const Value &, RawTaskPresentation)> &native_observer;
  std::string id, attempt_text, operation;
  OperationAttemptId attempt;
  RawEventRef source_{};
  CommandTaskMap::node_type *pending_node = nullptr;
  bool *transferred = nullptr;
  bool bound = false, ended = false;
  CommandTaskActivity(
      std::function<void(const Value &)> &callback,
      std::function<void(const Value &, RawTaskPresentation)> &native_callback,
      std::string task, OperationAttemptId actual_attempt, std::string encoded_attempt,
      std::string operation_name)
      : observer(callback), native_observer(native_callback), id(std::move(task)),
        attempt_text(std::move(encoded_attempt)), operation(std::move(operation_name)),
        attempt(actual_attempt) {}
  CommandTaskActivity(const CommandTaskActivity &) = delete;
  CommandTaskActivity &operator=(const CommandTaskActivity &) = delete;
  ~CommandTaskActivity() {
    if (bound && !ended)
      emit(3);
  }
  void bind(RawEventRef operation_request) noexcept {
    source_ = operation_request;
    bound = true;
  }
  void emit(std::uint8_t branch, const Value *exit = nullptr) noexcept {
    if (!bound || ended)
      return;
    if (branch != 0)
      ended = true;
    if (!native_observer && !observer)
      return;
    try {
      std::string phase{branch == 0   ? "running"
                        : branch == 1 ? "finished"
                        : branch == 2 ? "failed"
                                      : "outcome unknown"};
      if (exit)
        phase += " (exit " + exit->number().text() + ")";
      const auto event = Value::object({{"task_id", Value{id}},
                                        {"attempt", Value{attempt_text}},
                                        {"operation", Value{operation}},
                                        {"phase", Value{std::move(phase)}}});
      if (native_observer)
        native_observer(
            event,
            RawTaskPresentation{
                source_.ordinal ? std::optional{source_} : std::nullopt, {}, {}});
      else
        observer(event);
    } catch (...) {
    }
  }
};

struct CodingEngine::Runtime {
  enum class SourceKind : std::uint8_t {
    root = 1,
    tool,
    tool_api,
    print,
    module,
    validation
  };
  struct ToolInvocation {
    const Value &definition;
    const Value &arguments;
    const RawProgramContext *origin = nullptr;
  };
  struct Impl;
  std::unique_ptr<Impl> impl;
  std::string error;

  explicit Runtime(CodingEngine &e);
  Runtime(const Runtime &) = delete;
  Runtime &operator=(const Runtime &) = delete;
  ~Runtime();

  bool valid_module_source(std::string_view source);
  bool valid_tool_source(std::string_view source);
  Value invoke_tool(ToolInvocation invocation);
  Value eval(std::string_view source, const Value *arguments = nullptr,
             SourceKind kind = SourceKind::root);
};

} // namespace blackbird
