#include "blackbird/cpu_arc_distiller.hpp"

#include "blackbird/json.hpp"

#include <cmath>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird;
using namespace blackbird::arc;
namespace fs = std::filesystem;

void require(bool cond, std::string_view msg,
             std::source_location loc = std::source_location::current()) {
  if (!cond) {
    throw std::runtime_error(std::string{loc.file_name()} + ":" +
                             std::to_string(loc.line()) + ": " + std::string{msg});
  }
}

template <class T> T make_id(unsigned char n) {
  IdentityBytes b{};
  b[0] = std::byte{n};
  return unwrap(T::from_bytes(b));
}

struct TempDir {
  fs::path root;
  TempDir() {
    std::string tmpl =
        (fs::temp_directory_path() / "bb-cpu-arc-distiller-test-XXXXXX").string();
    char *created = ::mkdtemp(tmpl.data());
    require(created != nullptr, "mkdtemp failed");
    root = fs::canonical(created);
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(root, ec);
  }
};

double get_number_field(const Value &obj, std::string_view key) {
  const Value *v = obj.find(key);
  require(v != nullptr, "missing numeric field: " + std::string{key});
  const auto *n = std::get_if<Number>(&v->value());
  require(n != nullptr, "field is not a number: " + std::string{key});
  if (const auto *d = std::get_if<double>(&n->storage())) {
    return *d;
  }
  if (const auto *i = std::get_if<std::int64_t>(&n->storage())) {
    return static_cast<double>(*i);
  }
  throw std::runtime_error("unexpected number storage for " + std::string{key});
}

// ---------------------------------------------------------------------------
// 1. Error Names, ContextStore Lossless Extraction, JSONL Bounds & Clustering
// ---------------------------------------------------------------------------

void test_context_extraction_jsonl_and_clustering() {
  require(arc_distiller_error_name(ArcDistillerError::invalid_trace) == "invalid_trace",
          "invalid_trace name");
  require(arc_distiller_error_name(ArcDistillerError::extraction_robustness_failed) ==
              "extraction_robustness_failed",
          "extraction_robustness_failed name");
  require(arc_phase_status_name(ArcPhaseStatus::succeeded) == "succeeded",
          "phase status name");

  TempDir tmp{};
  const JournalHeader hdr{make_id<EnvironmentId>(11),
                          make_id<AuditStreamId>(22),
                          3,
                          {1024 * 1024, 4 * 1024 * 1024},
                          std::nullopt};
  const JournalCapacity cap{64 * 1024 * 1024, 8192};

  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(tmp.root.string()))),
                            "audit", hdr, cap));
  AuditLog log{*root};
  ContextStore ctx{log};

  // System instruction (should not be emitted as a user turn).
  (void)ctx.append(
      {Value::object({{"role", Value{"system"}},
                      {"content", Value{"You are a scientific solver."}}})},
      "system");

  // Turn 1: user instruction + completed exchange with reasoning, tool call/output, and
  // assistant answer.
  const auto b_user1 = ctx.append(
      {Value::object(
          {{"role", Value{"user"}},
           {"content", Value{"Calculate ideal gas pressure for 10.0 mol ethane in 4.86 "
                             "dm^3 at 27 C"}}})},
      "operator");
  (void)ctx.append(
      {Value::object({{"type", Value{"reasoning"}},
                      {"text", Value{"Convert 27 C to 300 K and compute P = nRT/V."}}}),
       Value::object({{"type", Value{"function_call"}},
                      {"call_id", Value{"call-1"}},
                      {"name", Value{"calc_pressure"}},
                      {"arguments", Value{"{\"n\":10.0,\"V\":4.86,\"T\":300.0}"}}})},
      "provider.turn1");
  (void)ctx.append({Value::object({{"type", Value{"function_call_output"}},
                                   {"call_id", Value{"call-1"}},
                                   {"output", Value{"5132.10"}}})},
                   "tool.turn1");
  (void)ctx.append(
      {Value::object({{"role", Value{"assistant"}},
                      {"content", Value{"The pressure is 5132.10 kPa."}}})},
      "provider.turn1.final");

  // Turn 2: equirational query with different parameters + completed exchange.
  (void)ctx.append(
      {Value::object(
          {{"role", Value{"user"}},
           {"content",
            Value{"Calculate ideal gas pressure for 20.0 mol methane in 9.72 "
                  "dm^3 at 55 C"}}})},
      "operator");
  (void)ctx.append(
      {Value::object({{"type", Value{"reasoning"}},
                      {"text", Value{"Convert 55 C to 328 K and apply P = nRT/V."}}}),
       Value::object({{"role", Value{"assistant"}},
                      {"content", Value{"The pressure is 5611.09 kPa."}}})},
      "provider.turn2");

  // Turn 3: INCOMPLETE open exchange (unanswered tool call) -> MUST be skipped!
  (void)ctx.append(
      {Value::object({{"role", Value{"user"}},
                      {"content", Value{"Check pending status on node 9"}}})},
      "operator");
  (void)ctx.append({Value::object({{"type", Value{"function_call"}},
                                   {"call_id", Value{"call-open"}},
                                   {"name", Value{"status_check"}},
                                   {"arguments", Value{"{}"}}})},
                   "provider.turn3");

  // Snapshot ContextStore state BEFORE extraction to prove ZERO mutation!
  const std::string head_before = ctx.head();
  const std::size_t blocks_before = ctx.blocks().size();
  const std::uint64_t bytes_before = ctx.total_bytes();
  const bool open_before = ctx.has_open_exchanges();

  const auto traces = extract_distillable_traces(ctx);

  // Verify originals & ContextStore completely untouched!
  require(ctx.head() == head_before, "ContextStore head must remain untouched");
  require(ctx.blocks().size() == blocks_before, "block count must remain untouched");
  require(ctx.total_bytes() == bytes_before, "total bytes must remain untouched");
  require(ctx.has_open_exchanges() == open_before, "open flag must remain untouched");

  require(traces.size() == 2U,
          "must extract exactly 2 completed turns (skip open turn)");
  require(traces[0].block_id == b_user1, "turn 1 block_id matches instruction block");
  require(traces[0].user_query.find("10.0 mol ethane") != std::string::npos,
          "turn 1 user_query");
  require(traces[0].final_answer == "The pressure is 5132.10 kPa.",
          "turn 1 final_answer");
  require(traces[0].tools_used.size() == 1U &&
              traces[0].tools_used[0] == "calc_pressure",
          "turn 1 extracted tool name");
  require(traces[0].source_transcript.find("[reasoning]") != std::string::npos &&
              traces[0].source_transcript.find("[tool_call:calc_pressure]") !=
                  std::string::npos &&
              traces[0].source_transcript.find("[tool_output] 5132.10") !=
                  std::string::npos,
          "turn 1 lossless transcript");
  require(traces[0].provenance_hash.size() == 64U, "deterministic SHA-256 hash");
  require(traces[0].provenance_hash ==
              extract_distillable_traces(ctx)[0].provenance_hash,
          "provenance_hash must be deterministic");

  // Clustering equirational queries!
  std::vector<ArcSourceTrace> cluster_input = traces;
  cluster_input[0].source_cost_usd = 0.08;
  cluster_input[1].source_cost_usd = 0.09;
  ArcSourceTrace unrelated{};
  unrelated.trace_id = "unrelated-1";
  unrelated.user_query = "Summarize quarterly revenue report for Europe";
  unrelated.source_transcript = "Summary ready.";
  unrelated.final_answer = "Revenue grew 12%.";
  unrelated.source_cost_usd = 0.03;
  cluster_input.push_back(unrelated);

  const auto clusters = cluster_recurring_traces(cluster_input, 0.45);
  require(clusters.size() == 2U, "expected 2 clusters (gas law pair + unrelated)");
  require(clusters[0].occurrence_count == 2U,
          "top cluster must have 2 equirational turns");
  require(std::fabs(clusters[0].total_source_cost_usd - 0.17) < 1e-9,
          "cluster cost aggregation");
  require(clusters[0].canonical_template.find("<num>") != std::string::npos,
          "template normalizes numbers to <num>");

  // JSONL extraction + strict size bound enforcement.
  const std::string jsonl =
      R"({"trace_id":"j1","user_query":"Convert 27 C to K","source_transcript":"27+273=300","final_answer":"300","tools_used":["unit_calc"],"source_cost_usd":0.05})"
      "\n"
      R"({"trace_id":"j2","messages":[{"role":"user","content":"Convert 100 C to K"},{"type":"function_call","name":"unit_calc","arguments":"{}"},{"role":"assistant","content":"373"}]})"
      "\n";
  const auto j_res = extract_distillable_traces_from_jsonl(jsonl);
  require(j_res.has_value() && j_res.value().size() == 2U, "jsonl extracted 2 traces");
  require(j_res.value()[0].provenance_hash.size() == 64U, "jsonl hash populated");
  require(j_res.value()[1].tools_used.size() == 1U &&
              j_res.value()[1].tools_used[0] == "unit_calc",
          "jsonl message-array tool extraction");

  const auto over_budget = extract_distillable_traces_from_jsonl(jsonl, 16U);
  require(!over_budget.has_value() && arc_distiller_error_of(over_budget.error()) ==
                                          ArcDistillerError::budget_exceeded,
          "oversized jsonl must fail with budget_exceeded");

  const auto bad_json = extract_distillable_traces_from_jsonl("{not valid json}\n");
  require(!bad_json.has_value() && arc_distiller_error_of(bad_json.error()) ==
                                       ArcDistillerError::parse_failed,
          "malformed jsonl must fail with parse_failed");
}

// ---------------------------------------------------------------------------
// 2. Full 5-Phase Distillation of 2-Node DAG (Retry + Critique + E2E + Compile)
//    + Registry Reuse on 2nd Related Trace
// ---------------------------------------------------------------------------

void test_five_phase_distillation_retry_compile_and_reuse() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  ArcRegistry &reg = reg_res.value();

  ArcSourceTrace trace1{};
  trace1.trace_id = "scibench-gas-1";
  trace1.user_query =
      "Calculate the pressure exerted by 10.0 mol of ethane in 4.86 dm^3 at 27 C";
  trace1.source_transcript =
      "Step 1: Convert 27 C to Kelvin -> 27 + 273 = 300 K. "
      "Step 2: Apply P = n * R * T / V = 10.0 * 8.314 * 300 / 4.86 = 5132.10 kPa.";
  trace1.final_answer = "5132.10";
  trace1.source_cost_usd = 0.12;

  int helper_attempts = 0;
  int root_attempts = 0;
  bool saw_narration_critique = false;
  bool saw_judge_critique = false;

  ArcDistillerCallbacks cbs{};
  cbs.builder = [&](std::string_view prompt,
                    std::string_view phase) -> Result<std::string> {
    if (phase == "phase1_io_isolation") {
      return Result<std::string>::success(R"({
        "user_input": "Calculate the pressure exerted by 10.0 mol of ethane in 4.86 dm^3 at 27 C",
        "expected_output": "5132.10"
      })");
    }
    if (phase == "phase2_decomposition") {
      return Result<std::string>::success(R"({
        "steps": [
          {
            "id": "s1",
            "description": "Convert temperature in Celsius to Kelvin",
            "inputs": ["temperature in Celsius"],
            "reusable": true
          },
          {
            "id": "s2",
            "description": "Compute ideal gas pressure in kPa using n, V, and Kelvin temperature",
            "inputs": ["molar amount", "volume in dm^3", "temperature in Celsius"],
            "reusable": false
          }
        ]
      })");
    }
    if (phase == "phase3_param_recognition") {
      return Result<std::string>::success(R"({
        "generic_template": "Calculate the pressure exerted by <molar_amount> mol of <gas> in <volume> dm^3 at <temp_c> C",
        "params": [
          {
            "name": "molar_amount",
            "description": "the molar amount of gas in mol",
            "d_type": "float",
            "example": "10.0",
            "validity_range": "> 0",
            "original_value": 10.0
          },
          {
            "name": "volume",
            "description": "the container volume in dm^3",
            "d_type": "float",
            "example": "4.86",
            "validity_range": "> 0",
            "original_value": 4.86
          },
          {
            "name": "temp_c",
            "description": "the temperature in Celsius",
            "d_type": "float",
            "example": "27",
            "validity_range": "> -273.15",
            "original_value": 27.0
          }
        ]
      })");
    }
    if (phase == "phase4_planning") {
      // Intentionally place root before dependency in JSON array to test topological
      // sort!
      return Result<std::string>::success(R"({
        "nodes": [
          {
            "id": "compute_gas_pressure_kpa",
            "description": "Calculate ideal gas pressure in kPa given molar amount, container volume, and Celsius temperature",
            "depends_on": ["convert_celsius_to_kelvin"],
            "return_keys": ["the calculated pressure in kPa"],
            "is_root": true
          },
          {
            "id": "convert_celsius_to_kelvin",
            "description": "Convert a temperature in Celsius to Kelvin",
            "depends_on": [],
            "params": [
              {
                "name": "temp_c",
                "description": "the temperature in Celsius",
                "d_type": "float",
                "example": "27.0",
                "required": true
              }
            ],
            "return_keys": ["the temperature in Kelvin"],
            "expected_output": "300.0",
            "is_root": false
          }
        ]
      })");
    }
    if (phase == "phase5_implement") {
      if (prompt.find("\"id\":\"convert_celsius_to_kelvin\"") !=
          std::string_view::npos) {
        ++helper_attempts;
        if (helper_attempts == 1) {
          // Attempt 1: valid Lua, but ZERO arc.narrate calls -> fails
          // narration_commensurate check!
          return Result<std::string>::success(R"({
            "lua_source": "function semantic_function(ctx)\n  local c = arc.load(ctx, \"the temperature in Celsius\", \"float\")\n  return { [\"the temperature in Kelvin\"] = c + 273.0 }\nend"
          })");
        }
        // Attempt 2: receives narration critique and succeeds!
        if (prompt.find("narration check failed") != std::string_view::npos) {
          saw_narration_critique = true;
        }
        return Result<std::string>::success(R"({
          "lua_source": "function semantic_function(ctx)\n  local c = arc.load(ctx, \"the temperature in Celsius\", \"float\")\n  local k = c + 273.0\n  arc.narrate(ctx, string.format(\"Converted %.1f C to %.1f K\", c, k))\n  return { [\"the temperature in Kelvin\"] = k }\nend"
        })");
      }

      if (prompt.find("\"id\":\"compute_gas_pressure_kpa\"") !=
          std::string_view::npos) {
        ++root_attempts;
        if (root_attempts == 1) {
          // Attempt 1: logic bug (multiplies instead of dividing by V) -> judge
          // rejects!
          return Result<std::string>::success(R"({
            "lua_source": "function semantic_function(ctx)\n  local n = arc.load(ctx, \"the molar amount of gas in mol\", \"float\")\n  local v = arc.load(ctx, \"the container volume in dm^3\", \"float\")\n  local c = arc.load(ctx, \"the temperature in Celsius\", \"float\")\n  local tr = arc.do_(ctx, \"Convert a temperature in Celsius to Kelvin\", { [\"the temperature in Celsius\"] = c })\n  local k = arc.load(tr, \"the temperature in Kelvin\", \"float\")\n  local p = n * 8.314 * k * v\n  arc.narrate(ctx, string.format(\"Wrong formula P = %.2f\", p))\n  return { [\"the calculated pressure in kPa\"] = p }\nend"
          })");
        }
        // Attempt 2: receives judge critique and fixes formula!
        if (prompt.find("judge rejected candidate") != std::string_view::npos) {
          saw_judge_critique = true;
        }
        return Result<std::string>::success(R"({
          "lua_source": "function semantic_function(ctx)\n  local n = arc.load(ctx, \"the molar amount of gas in mol\", \"float\")\n  local v = arc.load(ctx, \"the container volume in dm^3\", \"float\")\n  local c = arc.load(ctx, \"the temperature in Celsius\", \"float\")\n  local tr = arc.do_(ctx, \"Convert a temperature in Celsius to Kelvin\", { [\"the temperature in Celsius\"] = c })\n  local k = arc.load(tr, \"the temperature in Kelvin\", \"float\")\n  local p = n * 8.314 * k / v\n  arc.narrate(ctx, string.format(\"Computed P = n*R*T/V = %.2f kPa\", p))\n  return { [\"the calculated pressure in kPa\"] = p }\nend"
        })");
      }
    }
    return Result<std::string>::failure(Error{ErrorCode::unsupported});
  };

  cbs.target_lm = [](std::string_view prompt,
                     std::string_view purpose) -> Result<std::string> {
    if (purpose == "extract_params") {
      if (prompt.find("20.0 mol") != std::string_view::npos) {
        return Result<std::string>::success(R"({
          "the molar amount of gas in mol": 20.0,
          "the container volume in dm^3": 4.86,
          "the temperature in Celsius": 27.0
        })");
      }
      return Result<std::string>::success(R"({
        "the molar amount of gas in mol": 10.0,
        "the container volume in dm^3": 4.86,
        "the temperature in Celsius": 27.0
      })");
    }
    return Result<std::string>::success("ok");
  };

  // Use deterministic built-in judge (cbs.judge unset)!
  ArcDistillOptions opts{};
  opts.granularity = ArcGranularity::medium;
  opts.max_node_retries = 3U;
  opts.extraction_round_trips = 3U;
  opts.auto_compile = true;
  opts.require_narration_commensurate = true;
  opts.builder_cost_usd = 0.45;
  opts.numeric_tolerance = 1e-2;

  ArcDistiller distiller{};
  const auto res = distiller.distill(reg, trace1, cbs, opts);
  require(res.has_value(),
          "5-phase distillation must succeed: " + distiller.last_report().diagnostic);
  const auto &rep = res.value();

  require(rep.succeeded, "report.succeeded");
  require(rep.topological_order.size() == 2U &&
              rep.topological_order[0] == "convert_celsius_to_kelvin" &&
              rep.topological_order[1] == "compute_gas_pressure_kpa",
          "bottom-up topological order must put helper before root");
  require(helper_attempts == 2 && saw_narration_critique,
          "helper must fail attempt 1 on narration and receive structured critique on "
          "attempt 2");
  require(
      root_attempts == 2 && saw_judge_critique,
      "root must fail attempt 1 on judge and receive structured critique on attempt 2");
  require(rep.total_retries == 2U, "expected 2 total retries");
  require(rep.stage1_correctness_passed, "Stage 1 correctness passed");
  require(rep.stage2_trials_run == 3U && rep.stage2_trials_passed == 3U &&
              std::fabs(rep.extraction_pass_rate - 1.0) < 1e-9,
          "Stage 2 all 3/3 extraction round-trips passed");
  require(rep.compiled, "auto_compile compiled the DAG");
  require(rep.registered_function_ids.size() == 2U, "2 new functions registered");
  require(rep.registered_entry_ids.size() == 2U,
          "both generic_template and original user_input registered as entry points");

  // Verify compiled zero-search execution on a parametric perturbation (20.0 mol)!
  ArcRuntimeCallbacks rt_cbs{};
  rt_cbs.lm = cbs.target_lm;
  const auto served = reg.serve(
      "Calculate the pressure exerted by 20.0 mol of methane in 4.86 dm^3 at 27 C",
      Value::object({}), rt_cbs);
  require(served.has_value(), "serve compiled distilled network");
  require(served.value().cache_hit && !served.value().fell_back_to_source, "cache hit");
  require(served.value().used_compiled, "must execute statically compiled Lua module");
  require(served.value().search_calls == 0U && served.value().do_calls == 0U,
          "compiled execution performs 0 FTS5 searches and 0 dynamic do_ calls");
  const double p_kpa =
      get_number_field(served.value().output, "the calculated pressure in kPa");
  require(std::fabs(p_kpa - 10264.20) < 0.1,
          "parametric variant 20.0 mol -> ~10264.20 kPa");

  // Verify cost accounting persisted on root function.
  const auto root_rec = reg.get_function("compute_gas_pressure_kpa");
  require(root_rec.has_value(), "root function exists");
  require(std::fabs(root_rec.value().total_source_cost_usd - 0.12) < 1e-9,
          "source cost persisted");
  require(std::fabs(root_rec.value().total_builder_cost_usd - 0.45) < 1e-9,
          "builder cost persisted");

  // -------------------------------------------------------------------------
  // Distill a 2nd related trace -> detects & REUSES `convert_celsius_to_kelvin`!
  // -------------------------------------------------------------------------
  ArcSourceTrace trace2{};
  trace2.trace_id = "scibench-kinetic-2";
  trace2.user_query = "Compute average kinetic energy scale R*T at 100 C";
  trace2.source_transcript = "100 C = 373 K; R*T = 8.314 * 373 = 3101.122 J/mol";
  trace2.final_answer = "3101.122";
  trace2.source_cost_usd = 0.08;

  bool builder_saw_reuse_candidate = false;
  ArcDistillerCallbacks cbs2{};
  cbs2.builder = [&](std::string_view prompt,
                     std::string_view phase) -> Result<std::string> {
    if (phase == "phase1_io_isolation") {
      return Result<std::string>::success(R"({
        "user_input": "Compute average kinetic energy scale R*T at 100 C",
        "expected_output": "3101.122"
      })");
    }
    if (phase == "phase2_decomposition") {
      return Result<std::string>::success(R"({
        "steps": [
          {"id": "k1", "description": "Convert a temperature in Celsius to Kelvin", "inputs": ["temp_c"], "reusable": true},
          {"id": "k2", "description": "Multiply gas constant R by Kelvin temperature", "inputs": ["temp_c"], "reusable": false}
        ]
      })");
    }
    if (phase == "phase3_param_recognition") {
      return Result<std::string>::success(R"({
        "generic_template": "Compute average kinetic energy scale R*T at <temp_c> C",
        "params": [
          {"name": "temp_c", "description": "the temperature in Celsius", "d_type": "float", "example": "100", "validity_range": "> -273.15", "original_value": 100.0}
        ]
      })");
    }
    if (phase == "phase4_planning") {
      return Result<std::string>::success(R"({
        "nodes": [
          {
            "id": "temp_helper_node",
            "description": "Convert a temperature in Celsius to Kelvin",
            "depends_on": [],
            "params": [{"name": "temp_c", "description": "the temperature in Celsius", "d_type": "float", "example": "100.0", "required": true}],
            "return_keys": ["the temperature in Kelvin"],
            "expected_output": "373.0",
            "is_root": false
          },
          {
            "id": "compute_rt_energy",
            "description": "Compute thermal energy scale R*T from Celsius temperature",
            "depends_on": ["temp_helper_node"],
            "return_keys": ["thermal energy R*T in J/mol"],
            "is_root": true
          }
        ]
      })");
    }
    if (phase == "phase5_implement") {
      if (prompt.find("\"id\":\"temp_helper_node\"") != std::string_view::npos) {
        if (prompt.find("convert_celsius_to_kelvin") != std::string_view::npos) {
          builder_saw_reuse_candidate = true;
        }
        return Result<std::string>::success(R"({
          "reuse_function_id": "convert_celsius_to_kelvin"
        })");
      }
      return Result<std::string>::success(R"({
        "lua_source": "function semantic_function(ctx)\n  local c = arc.load(ctx, \"the temperature in Celsius\", \"float\")\n  local tr = arc.do_(ctx, \"Convert a temperature in Celsius to Kelvin\", { [\"the temperature in Celsius\"] = c })\n  local k = arc.load(tr, \"the temperature in Kelvin\", \"float\")\n  local rt = 8.314 * k\n  arc.narrate(ctx, string.format(\"R*T = 8.314 * %.1f = %.3f\", k, rt))\n  return { [\"thermal energy R*T in J/mol\"] = rt }\nend"
      })");
    }
    return Result<std::string>::failure(Error{ErrorCode::unsupported});
  };
  cbs2.target_lm = [](std::string_view /*prompt*/,
                      std::string_view /*purpose*/) -> Result<std::string> {
    return Result<std::string>::success(R"({"the temperature in Celsius": 100.0})");
  };

  const auto res2 = distiller.distill(reg, trace2, cbs2, opts);
  require(res2.has_value(), "2nd distillation with reuse must succeed: " +
                                distiller.last_report().diagnostic);
  require(builder_saw_reuse_candidate,
          "distiller must pass matching registry reuse_candidates into builder prompt");
  require(res2.value().reused_function_ids.size() == 1U &&
              res2.value().reused_function_ids[0] == "convert_celsius_to_kelvin",
          "must report convert_celsius_to_kelvin as reused");
  require(res2.value().registered_function_ids.size() == 1U &&
              res2.value().registered_function_ids[0] == "compute_rt_energy",
          "must register only the new root (no duplicate helper)");
  require(res2.value().compiled, "2nd network must auto-compile cleanly");
  const auto fns_after = reg.list_functions();
  require(fns_after.has_value() && fns_after.value().size() == 3U,
          "registry must hold exactly 3 functions total (1 shared helper + 2 roots)");
}

// ---------------------------------------------------------------------------
// 3. Clean Rollback & Zero Registry Pollution on Cycle / Retries / Stage 2 Fail
// ---------------------------------------------------------------------------

void test_clean_rollback_and_zero_pollution() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  ArcRegistry &reg = reg_res.value();

  ArcSourceTrace trace{};
  trace.trace_id = "fail-trace";
  trace.user_query = "Compute square of 7";
  trace.source_transcript = "7 * 7 = 49";
  trace.final_answer = "49";

  // Case A: Cyclic DAG in Phase 4 -> rejected before any writes!
  {
    ArcDistillerCallbacks cbs{};
    cbs.builder = [](std::string_view /*prompt*/,
                     std::string_view phase) -> Result<std::string> {
      if (phase == "phase1_io_isolation") {
        return Result<std::string>::success(
            R"({"user_input":"Compute square of 7","expected_output":"49"})");
      }
      if (phase == "phase2_decomposition") {
        return Result<std::string>::success(
            R"({"steps":[{"id":"s1","description":"Square number","inputs":["x"],"reusable":false}]})");
      }
      if (phase == "phase3_param_recognition") {
        return Result<std::string>::success(
            R"({"generic_template":"Compute square of <x>","params":[{"name":"x","description":"input number","d_type":"float","example":"7","original_value":7}]})");
      }
      if (phase == "phase4_planning") {
        return Result<std::string>::success(R"({
          "nodes": [
            {"id": "node_a", "description": "A", "depends_on": ["node_b"], "is_root": true},
            {"id": "node_b", "description": "B", "depends_on": ["node_a"], "is_root": false}
          ]
        })");
      }
      return Result<std::string>::failure(Error{ErrorCode::unsupported});
    };
    cbs.target_lm = [](std::string_view, std::string_view) {
      return Result<std::string>::success(R"({"input number": 7})");
    };
    ArcDistiller d{};
    const auto r = d.distill(reg, trace, cbs);
    require(!r.has_value() && arc_distiller_error_of(r.error()) ==
                                  ArcDistillerError::validation_failed,
            "cyclic DAG must fail with validation_failed");
    require(reg.stats().value().function_count == 0U, "zero pollution after cycle");
  }

  // Case B: All retries exhausted on root AFTER helper succeeded -> helper MUST NOT
  // pollute persistent registry!
  {
    ArcDistillerCallbacks cbs{};
    cbs.builder = [](std::string_view prompt,
                     std::string_view phase) -> Result<std::string> {
      if (phase == "phase1_io_isolation") {
        return Result<std::string>::success(
            R"({"user_input":"Compute square of 7","expected_output":"49"})");
      }
      if (phase == "phase2_decomposition") {
        return Result<std::string>::success(
            R"({"steps":[{"id":"s1","description":"helper","inputs":["x"],"reusable":true},{"id":"s2","description":"root","inputs":["x"],"reusable":false}]})");
      }
      if (phase == "phase3_param_recognition") {
        return Result<std::string>::success(
            R"({"generic_template":"Compute square of <x>","params":[{"name":"x","description":"input number","d_type":"float","example":"7","original_value":7}]})");
      }
      if (phase == "phase4_planning") {
        return Result<std::string>::success(R"({
          "nodes": [
            {"id": "helper_ok", "description": "Echo input number", "depends_on": [], "params": [{"name":"x","description":"input number","d_type":"float","example":"7"}], "return_keys": ["echoed"], "expected_output": "7", "is_root": false},
            {"id": "root_broken", "description": "Square number", "depends_on": ["helper_ok"], "return_keys": ["square"], "is_root": true}
          ]
        })");
      }
      if (phase == "phase5_implement") {
        if (prompt.find("\"id\":\"helper_ok\"") != std::string_view::npos) {
          return Result<std::string>::success(R"({
            "lua_source": "function semantic_function(ctx)\n  local x = arc.load(ctx, \"input number\", \"float\")\n  arc.narrate(ctx, \"Echoing \" .. tostring(x))\n  return { [\"echoed\"] = x }\nend"
          })");
        }
        // Always emits broken syntax!
        return Result<std::string>::success(
            R"({"lua_source": "function semantic_function(ctx) return +++ end"})");
      }
      return Result<std::string>::failure(Error{ErrorCode::unsupported});
    };
    cbs.target_lm = [](std::string_view, std::string_view) {
      return Result<std::string>::success(R"({"input number": 7})");
    };

    ArcDistillOptions opts{};
    opts.max_node_retries = 2U;
    ArcDistiller d{};
    const auto r = d.distill(reg, trace, cbs, opts);
    require(!r.has_value() &&
                arc_distiller_error_of(r.error()) == ArcDistillerError::phase_failed,
            "exhausted retries must fail with phase_failed");
    const auto st = reg.stats();
    require(st.has_value() && st.value().function_count == 0U &&
                st.value().entry_point_count == 0U,
            "helper_ok must NOT pollute persistent registry when root fails");
  }

  // Case C: Stage 1 passes, but Stage 2 extraction robustness fails on trial 2/3 ->
  // ZERO persistent registry pollution!
  {
    int extract_call = 0;
    ArcDistillerCallbacks cbs{};
    cbs.builder = [](std::string_view /*prompt*/,
                     std::string_view phase) -> Result<std::string> {
      if (phase == "phase1_io_isolation") {
        return Result<std::string>::success(
            R"({"user_input":"Compute square of 7","expected_output":"49"})");
      }
      if (phase == "phase2_decomposition") {
        return Result<std::string>::success(
            R"({"steps":[{"id":"s1","description":"Square number","inputs":["x"],"reusable":false}]})");
      }
      if (phase == "phase3_param_recognition") {
        return Result<std::string>::success(
            R"({"generic_template":"Compute square of <x>","params":[{"name":"x","description":"input number","d_type":"float","example":"7","original_value":7}]})");
      }
      if (phase == "phase4_planning") {
        return Result<std::string>::success(R"({
          "nodes": [
            {"id": "square_root", "description": "Square number", "depends_on": [], "return_keys": ["square"], "is_root": true}
          ]
        })");
      }
      return Result<std::string>::success(R"({
        "lua_source": "function semantic_function(ctx)\n  local x = arc.load(ctx, \"input number\", \"float\")\n  arc.narrate(ctx, \"Squaring \" .. tostring(x))\n  return { [\"square\"] = x * x }\nend"
      })");
    };
    cbs.target_lm = [&](std::string_view, std::string_view) -> Result<std::string> {
      ++extract_call;
      if (extract_call == 2) {
        // Flaky extraction returns wrong value 8 -> 64 != 49!
        return Result<std::string>::success(R"({"input number": 8})");
      }
      return Result<std::string>::success(R"({"input number": 7})");
    };

    ArcDistillOptions opts{};
    opts.extraction_round_trips = 3U;
    ArcDistiller d{};
    const auto r = d.distill(reg, trace, cbs, opts);
    require(!r.has_value() && arc_distiller_error_of(r.error()) ==
                                  ArcDistillerError::extraction_robustness_failed,
            "flaky Stage 2 extraction must fail with extraction_robustness_failed");
    require(d.last_report().stage1_correctness_passed, "Stage 1 passed");
    require(d.last_report().stage2_trials_run == 3U &&
                d.last_report().stage2_trials_passed == 2U,
            "Stage 2 recorded 2/3 trials");
    const auto st = reg.stats();
    require(st.has_value() && st.value().function_count == 0U &&
                st.value().entry_point_count == 0U,
            "ZERO registry pollution after Stage 2 failure");
  }
}

// ---------------------------------------------------------------------------
// 4. ArcTurnGate (Figure 1): Bounded Miss Queue -> Cluster -> Distill -> Hit!
// ---------------------------------------------------------------------------

void test_turn_gate_figure1_end_to_end() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  ArcRegistry &reg = reg_res.value();

  ArcTurnGateConfig cfg{};
  cfg.enabled = true;
  cfg.max_queued_misses = 3U; // Small bound to verify FIFO eviction!
  cfg.auto_distill_threshold = 2U;
  cfg.cluster_min_similarity = 0.45;
  ArcTurnGate gate{reg, cfg};

  ArcRuntimeCallbacks rt_cbs{};
  rt_cbs.source_fallback = [](std::string_view req) -> Result<Value> {
    if (req.find("100") != std::string_view::npos) {
      return Result<Value>::success(Value{"212.0"});
    }
    if (req.find("0") != std::string_view::npos) {
      return Result<Value>::success(Value{"32.0"});
    }
    return Result<Value>::success(Value{"68.0"});
  };
  rt_cbs.lm = [](std::string_view prompt,
                 std::string_view purpose) -> Result<std::string> {
    if (purpose == "extract_params") {
      if (prompt.find("25") != std::string_view::npos) {
        return Result<std::string>::success(R"({"temperature in Celsius": 25.0})");
      }
      return Result<std::string>::success(R"({"temperature in Celsius": 100.0})");
    }
    return Result<std::string>::success("ok");
  };

  // Turn 1: Unrelated miss (will later be evicted when max_queued_misses=3 overflows).
  const auto m0 =
      gate.handle_turn("Draft launch memo for project Orion", Value::object({}), rt_cbs,
                       ArcTurnCostEstimate{0.05, 0.002});
  require(m0.has_value() && m0.value().fell_back_to_source && !m0.value().cache_hit,
          "turn 1 cache miss fallback");

  // Turns 2 & 3: Two recurring Celsius-to-Fahrenheit misses -> cross threshold!
  const auto m1 = gate.handle_turn("Convert 100 C to Fahrenheit", Value::object({}),
                                   rt_cbs, ArcTurnCostEstimate{0.10, 0.002});
  require(m1.has_value() && m1.value().fell_back_to_source, "turn 2 miss");
  const auto m2 = gate.handle_turn("Convert 0 C to Fahrenheit", Value::object({}),
                                   rt_cbs, ArcTurnCostEstimate{0.10, 0.002});
  require(m2.has_value() && m2.value().fell_back_to_source, "turn 3 miss");

  // Turn 4: One more miss -> verifies bounded queue evicts oldest (size stays 3!).
  const auto m3 = gate.handle_turn("Convert 20 C to Fahrenheit", Value::object({}),
                                   rt_cbs, ArcTurnCostEstimate{0.10, 0.002});
  require(m3.has_value() && m3.value().fell_back_to_source, "turn 4 miss");

  const auto tel_before = gate.telemetry();
  require(tel_before.total_turns == 4U && tel_before.cache_misses == 4U &&
              tel_before.cache_hits == 0U,
          "telemetry before distillation");
  require(tel_before.queued_miss_count == 3U,
          "bounded miss queue must evict oldest at max_queued_misses=3");

  const auto ready = gate.pending_candidates();
  require(ready.size() == 1U && ready[0].occurrence_count == 3U,
          "recurring Celsius-to-Fahrenheit cluster ready for distillation");

  // Distill the top cluster's representative trace via ArcDistiller!
  const auto queued = gate.queued_misses();
  ArcSourceTrace rep_trace{};
  for (const auto &q : queued) {
    if (q.trace_id == ready[0].representative_trace_id) {
      rep_trace = q;
      break;
    }
  }
  require(!rep_trace.user_query.empty(), "found representative miss trace");

  ArcDistillerCallbacks d_cbs{};
  d_cbs.builder = [](std::string_view /*prompt*/,
                     std::string_view phase) -> Result<std::string> {
    if (phase == "phase1_io_isolation") {
      return Result<std::string>::success(R"({
        "user_input": "Convert 100 C to Fahrenheit",
        "expected_output": "212.0"
      })");
    }
    if (phase == "phase2_decomposition") {
      return Result<std::string>::success(R"({
        "steps": [{"id": "c2f", "description": "Convert Celsius to Fahrenheit", "inputs": ["celsius"], "reusable": true}]
      })");
    }
    if (phase == "phase3_param_recognition") {
      return Result<std::string>::success(R"({
        "generic_template": "Convert <celsius> C to Fahrenheit",
        "params": [{"name": "celsius", "description": "temperature in Celsius", "d_type": "float", "example": "100", "original_value": 100.0}]
      })");
    }
    if (phase == "phase4_planning") {
      return Result<std::string>::success(R"({
        "nodes": [{"id": "celsius_to_fahrenheit", "description": "Convert temperature from Celsius to Fahrenheit", "depends_on": [], "return_keys": ["temperature in Fahrenheit"], "is_root": true}]
      })");
    }
    return Result<std::string>::success(R"({
      "lua_source": "function semantic_function(ctx)\n  local c = arc.load(ctx, \"temperature in Celsius\", \"float\")\n  local f = c * 9.0 / 5.0 + 32.0\n  arc.narrate(ctx, string.format(\"%.1f C * 9/5 + 32 = %.1f F\", c, f))\n  return { [\"temperature in Fahrenheit\"] = f }\nend"
    })");
  };
  d_cbs.target_lm = rt_cbs.lm;
  d_cbs.judge = [](std::string_view expected, const Value &actual,
                   std::string_view /*note*/) -> Result<ArcJudgeVerdict> {
    const double f = get_number_field(actual, "temperature in Fahrenheit");
    const bool ok = std::fabs(f - 212.0) < 1e-3 && expected == "212.0";
    return Result<ArcJudgeVerdict>::success(
        ArcJudgeVerdict{ok, ok ? "exact match" : "mismatch"});
  };

  ArcDistiller distiller{};
  const auto d_res = distiller.distill(reg, rep_trace, d_cbs);
  require(d_res.has_value() && d_res.value().compiled,
          "distill from gate cluster succeeded and auto-compiled");
  require(gate.consume_cluster(ready[0]) == 3U, "consume distilled cluster misses");
  require(gate.pending_candidates().empty(), "no pending candidates after consume");

  // Turn 5: New equirational query ("Convert 25 C to Fahrenheit") -> COMPILED CACHE
  // HIT!
  const auto hit = gate.handle_turn("Convert 25 C to Fahrenheit", Value::object({}),
                                    rt_cbs, ArcTurnCostEstimate{0.10, 0.002});
  require(hit.has_value(), "turn 5 must succeed");
  require(hit.value().cache_hit && !hit.value().fell_back_to_source,
          "turn 5 must be a cache hit");
  require(hit.value().used_compiled, "turn 5 must use compiled zero-search module");
  require(hit.value().search_calls == 0U && hit.value().do_calls == 0U,
          "compiled cache hit performs 0 FTS5 searches");
  require(std::fabs(get_number_field(hit.value().output, "temperature in Fahrenheit") -
                    77.0) < 1e-6,
          "25 C == 77.0 F");

  const auto tel_after = gate.telemetry();
  require(tel_after.total_turns == 5U && tel_after.cache_hits == 1U &&
              tel_after.cache_misses == 4U,
          "telemetry counts updated");
  require(std::fabs(tel_after.hit_rate - 0.2) < 1e-9, "hit_rate == 1/5");
  require(std::fabs(tel_after.estimated_saved_usd - 0.098) < 1e-9,
          "saved_usd == 0.10 - 0.002");
  require(tel_after.cost_savings_multiplier > 1.2,
          "cost_savings_multiplier reflects savings");

  // Turn 6: Runtime error in a cached function triggers seamless source_fallback and
  // increments error_fallbacks!
  ArcFunctionRecord broken_fn{};
  broken_fn.id = "always_fail_fn";
  broken_fn.description = "Trigger deliberate runtime error for fallback test";
  broken_fn.is_root = true;
  broken_fn.entry_templates = {"Trigger deliberate runtime error for fallback test"};
  broken_fn.lua_source = R"LUA(
function semantic_function(ctx)
  arc.narrate(ctx, "About to fail")
  error("deliberate runtime failure")
end
)LUA";
  require(reg.register_function(broken_fn).has_value(), "register broken_fn");
  const auto fb_err =
      gate.handle_turn("Trigger deliberate runtime error for fallback test",
                       Value::object({}), rt_cbs, ArcTurnCostEstimate{0.05, 0.001});
  require(fb_err.has_value() && fb_err.value().fell_back_to_source &&
              fb_err.value().cache_hit,
          "runtime error falls back seamlessly to source");
  require(gate.telemetry().error_fallbacks == 1U, "error_fallbacks incremented");

  // Turn 7: Gate disabled bypasses cache directly to source_fallback.
  ArcTurnGateConfig disabled_cfg = gate.config();
  disabled_cfg.enabled = false;
  gate.set_config(disabled_cfg);
  const auto bypassed =
      gate.handle_turn("Convert 25 C to Fahrenheit", Value::object({}), rt_cbs,
                       ArcTurnCostEstimate{0.10, 0.002});
  require(bypassed.has_value() && bypassed.value().fell_back_to_source &&
              bypassed.value().fallback_reason == "gate_disabled",
          "disabled gate bypasses cache");
}

// ---------------------------------------------------------------------------
// 5. Regression Tests: JSONL 64-bit block_id + Overflow, Compile Rollback
//    Isolation (Overwrite & Reused Root), and Non-Finite Cost/Similarity Guards
// ---------------------------------------------------------------------------

void test_regression_ubsan_rollback_and_nonfinite_guards() {
  // 5A. JSONL block_id: huge float (1e30) must NOT trigger UBSan float-cast-overflow,
  //     and 64-bit integer > 2^53 (9007199254740993) must preserve exact precision!
  const std::string jsonl_edge =
      R"({"trace_id":"t-overflow","user_query":"q1","source_transcript":"tr1","final_answer":"a1","block_id":1e30})"
      "\n"
      R"({"trace_id":"t-exact64","user_query":"q2","source_transcript":"tr2","final_answer":"a2","block_id":9007199254740993})"
      "\n"
      R"({"trace_id":"t-neg","user_query":"q3","source_transcript":"tr3","final_answer":"a3","block_id":-5})"
      "\n";
  const auto parsed = extract_distillable_traces_from_jsonl(jsonl_edge);
  require(parsed.has_value() && parsed.value().size() == 3U,
          "jsonl edge block_id lines parsed cleanly");
  require(parsed.value()[0].block_id == 0U,
          "out-of-range float block_id ignored safely without UB");
  require(parsed.value()[1].block_id == 9007199254740993ULL,
          "64-bit block_id > 2^53 preserved without double precision loss");
  require(parsed.value()[2].block_id == 0U, "negative block_id ignored safely");

  // 5B. Compile failure after overwriting preexisting function OR reusing root:
  //     persistent registry MUST remain 100% untouched (no overwritten code, no leaked
  //     entry points)!
  {
    auto reg_res = ArcRegistry::open_in_memory();
    require(reg_res.has_value(), "open_in_memory");
    ArcRegistry &reg = reg_res.value();

    ArcFunctionRecord shared_orig{};
    shared_orig.id = "shared_helper";
    shared_orig.description = "Original untouched shared helper";
    shared_orig.params = {ArcParamSpec{"x", "input x", "float", "7", true}};
    shared_orig.return_keys = {"val"};
    shared_orig.lua_source = R"LUA(
function semantic_function(ctx)
  local x = arc.load(ctx, "input x", "float")
  arc.narrate(ctx, "Original shared helper")
  return { ["val"] = x }
end
)LUA";
    require(reg.register_function(shared_orig).has_value(), "register shared_orig");

    // Case 1: Plan overwrites `shared_helper` and adds a root whose arc.do_ uses a
    // non-literal query variable -> passes dynamic Phase 5 + E2E, fails auto_compile!
    ArcSourceTrace tr{};
    tr.trace_id = "overwrite-compile-fail";
    tr.user_query = "Compute dynamic lookup of 7";
    tr.source_transcript = "lookup(7) = 7";
    tr.final_answer = "7";

    ArcDistillerCallbacks cbs{};
    cbs.builder = [](std::string_view prompt,
                     std::string_view phase) -> Result<std::string> {
      if (phase == "phase1_io_isolation") {
        return Result<std::string>::success(
            R"({"user_input":"Compute dynamic lookup of 7","expected_output":"7"})");
      }
      if (phase == "phase2_decomposition") {
        return Result<std::string>::success(
            R"({"steps":[{"id":"s1","description":"helper","inputs":["x"],"reusable":true},{"id":"s2","description":"root","inputs":["x"],"reusable":false}]})");
      }
      if (phase == "phase3_param_recognition") {
        return Result<std::string>::success(
            R"({"generic_template":"Compute dynamic lookup of <x>","params":[{"name":"x","description":"input x","d_type":"float","example":"7","original_value":7}]})");
      }
      if (phase == "phase4_planning") {
        return Result<std::string>::success(R"({
          "nodes": [
            {"id": "shared_helper", "description": "MUTATED helper description", "depends_on": [], "params": [{"name":"x","description":"input x","d_type":"float","example":"7"}], "return_keys": ["val"], "expected_output": "7", "is_root": false},
            {"id": "dyn_root", "description": "Dynamic dispatch root", "depends_on": ["shared_helper"], "return_keys": ["val"], "is_root": true}
          ]
        })");
      }
      if (prompt.find("\"id\":\"shared_helper\"") != std::string_view::npos) {
        return Result<std::string>::success(R"({
          "lua_source": "function semantic_function(ctx)\n  local x = arc.load(ctx, \"input x\", \"float\")\n  arc.narrate(ctx, \"MUTATED helper body\")\n  return { [\"val\"] = x }\nend"
        })");
      }
      // Non-literal query in arc.do_ passes dynamic invoke_function, fails static
      // compile!
      return Result<std::string>::success(R"({
        "lua_source": "function semantic_function(ctx)\n  local x = arc.load(ctx, \"input x\", \"float\")\n  local q = \"MUTATED helper description\"\n  local r = arc.do_(ctx, q, { [\"input x\"] = x })\n  arc.narrate(ctx, \"Dynamic dispatch\")\n  return r\nend"
      })");
    };
    cbs.target_lm = [](std::string_view, std::string_view) {
      return Result<std::string>::success(R"({"input x": 7})");
    };

    ArcDistillOptions opts{};
    opts.auto_compile = true;
    opts.extraction_round_trips = 1U;
    ArcDistiller d{};
    const auto fail_r = d.distill(reg, tr, cbs, opts);
    require(!fail_r.has_value() && arc_distiller_error_of(fail_r.error()) ==
                                       ArcDistillerError::compile_failed,
            "dynamic arc.do_ must fail auto_compile with compile_failed");

    const auto after_shared = reg.get_function("shared_helper");
    require(after_shared.has_value(), "shared_helper still exists");
    require(
        after_shared.value().description == shared_orig.description &&
            after_shared.value().lua_source == shared_orig.lua_source,
        "preexisting shared_helper must NOT be overwritten when auto_compile fails");
    require(!reg.get_function("dyn_root").has_value(),
            "dyn_root must not be committed");
    require(reg.stats().value().entry_point_count == 0U,
            "zero entry points leaked on compile_failed");

    // Case 2: Reused preexisting root function that cannot statically compile ->
    // ZERO leaked entry points!
    ArcFunctionRecord uncompilable_root{};
    uncompilable_root.id = "preexisting_dyn_root";
    uncompilable_root.description = "Preexisting dynamic root";
    uncompilable_root.is_root = true;
    uncompilable_root.params = {ArcParamSpec{"x", "input x", "float", "7", true}};
    uncompilable_root.return_keys = {"val"};
    uncompilable_root.lua_source = R"LUA(
function semantic_function(ctx)
  local x = arc.load(ctx, "input x", "float")
  local q = "Original untouched shared helper"
  local r = arc.do_(ctx, q, { ["input x"] = x })
  arc.narrate(ctx, "Dynamic call")
  return r
end
)LUA";
    require(reg.register_function(uncompilable_root).has_value(),
            "register preexisting_dyn_root");
    const std::size_t entries_before = reg.stats().value().entry_point_count;

    ArcDistillerCallbacks cbs_reuse{};
    cbs_reuse.builder = [](std::string_view /*prompt*/,
                           std::string_view phase) -> Result<std::string> {
      if (phase == "phase1_io_isolation") {
        return Result<std::string>::success(
            R"({"user_input":"Compute dynamic lookup of 7","expected_output":"7"})");
      }
      if (phase == "phase2_decomposition") {
        return Result<std::string>::success(
            R"({"steps":[{"id":"s1","description":"root","inputs":["x"],"reusable":true}]})");
      }
      if (phase == "phase3_param_recognition") {
        return Result<std::string>::success(
            R"({"generic_template":"Compute dynamic lookup of <x>","params":[{"name":"x","description":"input x","d_type":"float","example":"7","original_value":7}]})");
      }
      if (phase == "phase4_planning") {
        return Result<std::string>::success(R"({
          "nodes": [
            {"id": "new_root_alias", "description": "Preexisting dynamic root", "depends_on": [], "return_keys": ["val"], "is_root": true}
          ]
        })");
      }
      return Result<std::string>::success(
          R"({"reuse_function_id": "preexisting_dyn_root"})");
    };
    cbs_reuse.target_lm = cbs.target_lm;

    const auto fail_reuse = d.distill(reg, tr, cbs_reuse, opts);
    require(!fail_reuse.has_value() && arc_distiller_error_of(fail_reuse.error()) ==
                                           ArcDistillerError::compile_failed,
            "reused uncompilable root must fail with compile_failed");
    require(reg.stats().value().entry_point_count == entries_before,
            "ZERO entry points leaked when reused root fails auto_compile");
  }

  // 5C. Non-finite (+Inf / NaN) cost & similarity guards in cluster_recurring_traces
  //     and ArcTurnGate!
  {
    const double kInf = std::numeric_limits<double>::infinity();
    const double kNan = std::numeric_limits<double>::quiet_NaN();

    std::vector<ArcSourceTrace> bad_cost_traces(3U);
    bad_cost_traces[0].trace_id = "c1";
    bad_cost_traces[0].user_query = "Compute pressure for 10 mol gas";
    bad_cost_traces[0].source_cost_usd = kInf;
    bad_cost_traces[1].trace_id = "c2";
    bad_cost_traces[1].user_query = "Compute pressure for 20 mol gas";
    bad_cost_traces[1].source_cost_usd = kNan;
    bad_cost_traces[2].trace_id = "c3";
    bad_cost_traces[2].user_query = "Summarize unrelated sales memo";
    bad_cost_traces[2].source_cost_usd = -1.0;

    const auto clusters = cluster_recurring_traces(bad_cost_traces, kNan);
    require(clusters.size() == 2U && clusters[0].occurrence_count == 2U,
            "NaN min_similarity falls back cleanly to 0.45");
    for (const auto &cl : clusters) {
      require(std::isfinite(cl.total_source_cost_usd) &&
                  cl.total_source_cost_usd == 0.0,
              "non-finite/negative trace costs sanitized to 0.0");
    }

    auto reg_res = ArcRegistry::open_in_memory();
    require(reg_res.has_value(), "open_in_memory");
    ArcTurnGate gate{reg_res.value()};
    ArcRuntimeCallbacks rt{};
    rt.source_fallback = [](std::string_view) {
      return Result<Value>::success(Value{"ok"});
    };
    const auto r1 = gate.handle_turn("query one", Value::object({}), rt,
                                     ArcTurnCostEstimate{kInf, kNan});
    require(r1.has_value(), "handle_turn with Inf/NaN costs succeeds");
    const auto r2 = gate.handle_turn("query two", Value::object({}), rt,
                                     ArcTurnCostEstimate{kNan, -kInf});
    require(r2.has_value(), "handle_turn with NaN/-Inf costs succeeds");
    const auto tel = gate.telemetry();
    require(std::isfinite(tel.total_source_cost_usd) &&
                std::isfinite(tel.total_actual_cost_usd) &&
                std::isfinite(tel.estimated_saved_usd) &&
                std::isfinite(tel.cost_savings_multiplier),
            "gate telemetry must remain strictly finite under Inf/NaN costs");
    require(tel.total_source_cost_usd == 0.0 && tel.total_actual_cost_usd == 0.0 &&
                tel.estimated_saved_usd == 0.0 && tel.cost_savings_multiplier == 1.0,
            "non-finite costs sanitized cleanly to 0.0 / multiplier 1.0");
  }
}

} // namespace

int main() {
  try {
    test_context_extraction_jsonl_and_clustering();
    test_five_phase_distillation_retry_compile_and_reuse();
    test_clean_rollback_and_zero_pollution();
    test_turn_gate_figure1_end_to_end();
    test_regression_ubsan_rollback_and_nonfinite_guards();
    std::cout << "cpu_arc_distiller_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "cpu_arc_distiller_test FAILED: " << ex.what() << "\n";
    return 1;
  }
}
