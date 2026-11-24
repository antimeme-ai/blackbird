#include "blackbird/cpu_arc.hpp"

#include "blackbird/json.hpp"

#include <cmath>
#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <source_location>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
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

struct TempDir {
  fs::path root;
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "bb-cpu-arc-test-XXXXXX").string();
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
  throw std::runtime_error("unexpected Number storage for " + std::string{key});
}

int count_open_fds() {
  int count = 0;
  for (int fd = 0; fd < 256; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1) {
      ++count;
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// 1. Capabilities, Error Names, Static Analysis & Ideal Gas Law (Fig. 5 / 7 / 8)
// ---------------------------------------------------------------------------

ArcLmCallback make_ideal_gas_lm() {
  return [](std::string_view prompt, std::string_view purpose) -> Result<std::string> {
    if (purpose == "extract") {
      // Extract the first numeric literal from the text after "text:\n"
      const auto pos = prompt.find("text:\n");
      const std::string_view tail =
          pos != std::string_view::npos ? prompt.substr(pos + 6U) : prompt;
      std::string num;
      bool started = false;
      for (const char ch : tail) {
        if ((ch >= '0' && ch <= '9') || ch == '.' || (!started && ch == '-')) {
          num.push_back(ch);
          started = true;
        } else if (started) {
          break;
        }
      }
      require(!num.empty(),
              "mock extract failed to find number in: " + std::string{tail});
      return Result<std::string>::success(num);
    }
    if (purpose == "lm") {
      if (prompt.find("temperature unit") != std::string_view::npos) {
        if (prompt.find("C") != std::string_view::npos) {
          return Result<std::string>::success("C");
        }
        return Result<std::string>::success("K");
      }
      return Result<std::string>::success("ok");
    }
    if (purpose == "smart_convert") {
      if (prompt.find("forty-two") != std::string_view::npos) {
        return Result<std::string>::success("42");
      }
      return Result<std::string>::success("0");
    }
    if (purpose == "extract_params") {
      // Parse simple "X mol ... in Y dm^3 at Z C" pattern for IS2 test
      if (prompt.find("20.0 mol") != std::string_view::npos) {
        return Result<std::string>::success(R"({
          "the molar amount of gas": "20.0 mol",
          "the container volume": "4.86 dm^3",
          "the temperature with unit": "27 C",
          "the common name of the gas": "methane",
          "the gas model or assumption to use": "perfect gas"
        })");
      }
      return Result<std::string>::success(R"({
        "the molar amount of gas": "10.0 mol",
        "the container volume": "4.86 dm^3",
        "the temperature with unit": "27 C",
        "the common name of the gas": "ethane",
        "the gas model or assumption to use": "perfect gas"
      })");
    }
    return Result<std::string>::success("ok");
  };
}

void register_ideal_gas_network(ArcRegistry &reg) {
  // Leaf 1: convert_temperature
  ArcFunctionRecord temp_fn{};
  temp_fn.id = "convert_temperature";
  temp_fn.description = "Convert a temperature value from Celsius or Kelvin to Kelvin "
                        "given a temperature "
                        "string with unit";
  temp_fn.params = {
      ArcParamSpec{"temp_with_unit", "the temperature value with unit", "str", "27 C",
                   true},
  };
  temp_fn.return_keys = {"the temperature in Kelvin"};
  temp_fn.granularity = ArcGranularity::fine;
  temp_fn.provenance_trace_hash = compute_trace_hash("scibench-ideal-gas-temp");
  temp_fn.lua_source = R"LUA(
function semantic_function(ctx)
  local temp_str = arc.load(ctx, "the temperature value with unit", "str")
  arc.narrate(ctx, "Received temperature specification: " .. temp_str)
  local temp_value = arc.extract(ctx, temp_str, "the numeric temperature value", "float")
  arc.narrate(ctx, string.format("Extracted numeric temperature value: %.1f", temp_value))
  local unit = arc.lm(ctx, "What is the temperature unit in '" .. temp_str .. "'? Reply C or K")
  arc.narrate(ctx, "Detected temperature unit: " .. unit)
  local temp_k = temp_value
  if string.find(string.upper(unit), "C") ~= nil then
    temp_k = temp_value + 273.0
    arc.narrate(ctx, string.format("%.1f C + 273 = %.1f K", temp_value, temp_k))
  end
  return {
    ["the temperature in Kelvin"] = temp_k
  }
end
)LUA";
  require(reg.register_function(temp_fn).has_value(), "register convert_temperature");

  // Leaf 2: convert_pressure (pure arithmetic, zero LM calls!)
  ArcFunctionRecord pres_fn{};
  pres_fn.id = "convert_pressure";
  pres_fn.description =
      "Convert a pressure value from kPa to multiple common units including MPa, bar, "
      "and atm";
  pres_fn.params = {
      ArcParamSpec{"pressure_kpa", "the pressure value in kilopascals (kPa)", "float",
                   "5132.10", true},
  };
  pres_fn.return_keys = {
      "the pressure in kPa",
      "the pressure in MPa",
      "the pressure in bar",
      "the pressure in atm",
  };
  pres_fn.granularity = ArcGranularity::fine;
  pres_fn.lua_source = R"LUA(
function semantic_function(ctx)
  local kpa = arc.load(ctx, "the pressure value in kilopascals (kPa)", "float")
  local mpa = kpa / 1000.0
  local bar = kpa / 100.0
  local atm = kpa / 101.325
  arc.narrate(ctx, string.format("%.2f kPa / 1000 = %.2f MPa", kpa, mpa))
  return {
    ["the pressure in kPa"] = kpa,
    ["the pressure in MPa"] = mpa,
    ["the pressure in bar"] = bar,
    ["the pressure in atm"] = atm
  }
end
)LUA";
  require(reg.register_function(pres_fn).has_value(), "register convert_pressure");

  // Root: compute_ideal_gas_pressure
  ArcFunctionRecord root_fn{};
  root_fn.id = "compute_ideal_gas_pressure";
  root_fn.description =
      "Calculate the pressure exerted by an ideal or perfect gas given molar amount, "
      "volume, and temperature";
  root_fn.is_root = true;
  root_fn.params = {
      ArcParamSpec{"molar_amount", "the molar amount of gas", "str", "10.0 mol", true},
      ArcParamSpec{"volume", "the container volume", "str", "4.86 dm^3", true},
      ArcParamSpec{"temperature", "the temperature with unit", "str", "27 C", true},
      ArcParamSpec{"gas_name", "the common name of the gas", "str", "ethane", true},
      ArcParamSpec{"gas_model", "the gas model or assumption to use", "str",
                   "perfect gas", true},
  };
  root_fn.return_keys = {
      "the calculated pressure in kPa",
      "the calculated pressure in MPa",
      "the calculated pressure in bar",
      "the calculated pressure in atm",
  };
  root_fn.entry_templates = {
      "Calculate the pressure exerted by molar amount of gas in volume at temperature "
      "using the perfect gas law",
      "Compute ideal gas pressure for moles of ethane confined in container volume at "
      "Celsius temperature",
  };
  root_fn.lua_source = R"LUA(
function semantic_function(ctx)
  local molar_str = arc.load(ctx, "the molar amount of gas", "str")
  local volume_str = arc.load(ctx, "the container volume", "str")
  local temp_str = arc.load(ctx, "the temperature with unit", "str")
  local gas_name = arc.load(ctx, "the common name of the gas", "str")
  local gas_model = arc.load(ctx, "the gas model or assumption to use", "str")

  arc.narrate(ctx, "Calculating pressure for " .. gas_name .. " using the " .. gas_model .. " law")
  local n = arc.extract(ctx, molar_str, "the numeric molar amount", "float")
  local V = arc.extract(ctx, volume_str, "the numeric volume value", "float")

  local temp_result = arc.do_(ctx,
    "Convert a temperature value from Celsius or Kelvin to Kelvin given a temperature string with unit",
    { ["the temperature value with unit"] = temp_str })
  local T = arc.load(temp_result, "the temperature in Kelvin", "float")

  local R = 8.314
  local pressure_kpa = n * R * T / V
  arc.narrate(ctx, string.format("P = %.2f kPa", pressure_kpa))

  local pres_result = arc.do_(ctx,
    "Convert a pressure value from kPa to multiple common units including MPa, bar, and atm",
    { ["the pressure value in kilopascals (kPa)"] = pressure_kpa })
  local pressure_mpa = arc.load(pres_result, "the pressure in MPa", "float")
  local pressure_bar = arc.load(pres_result, "the pressure in bar", "float")
  local pressure_atm = arc.load(pres_result, "the pressure in atm", "float")

  return {
    ["the calculated pressure in kPa"] = pressure_kpa,
    ["the calculated pressure in MPa"] = pressure_mpa,
    ["the calculated pressure in bar"] = pressure_bar,
    ["the calculated pressure in atm"] = pressure_atm
  }
end
)LUA";
  require(reg.register_function(root_fn).has_value(),
          "register compute_ideal_gas_pressure");
}

void test_capabilities_and_ideal_gas_law_dynamic_vs_compiled() {
  const auto caps = probe_cpu_arc_capabilities();
  require(caps.available, "CPU-ARC must be available");
  require(caps.lua_version == "5.5.1", "expected pinned Lua 5.5.1");
  require(caps.sqlite_version.starts_with("3.54"), "expected vendored SQLite 3.54.x");
  require(caps.supports_fts5 && caps.supports_wal && caps.supports_nofollow,
          "expected FTS5, WAL, NOFOLLOW");
  require(arc_error_name(ArcError::compile_cycle_detected) == "compile_cycle_detected",
          "error name check");
  require(compute_trace_hash("abc").size() == 64U, "SHA-256 hex length must be 64");

  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  auto &reg = reg_res.value();
  register_ideal_gas_network(reg);

  // Verify static analysis detects do_, load, and commensurate narration.
  const auto root_rec = reg.get_function("compute_ideal_gas_pressure");
  require(root_rec.has_value(), "get root function");
  const auto ana = analyze_lua_source(root_rec.value().lua_source);
  require(ana.has_value() && ana.value().syntax_valid &&
              ana.value().defines_semantic_function,
          "root static analysis valid");
  require(ana.value().do_calls.size() == 2U, "expected 2 arc.do_ sites");
  require(ana.value().load_calls.size() == 9U, "expected 9 arc.load sites");
  require(ana.value().narration_commensurate, "expected commensurate narration");

  Value::Object payloads;
  payloads.emplace_back("the molar amount of gas", Value{"10.0 mol"});
  payloads.emplace_back("the container volume", Value{"4.86 dm^3"});
  payloads.emplace_back("the temperature with unit", Value{"27 C"});
  payloads.emplace_back("the common name of the gas", Value{"ethane"});
  payloads.emplace_back("the gas model or assumption to use", Value{"perfect gas"});
  const Value payload_val = Value::object(std::move(payloads));

  ArcRuntimeCallbacks cbs{};
  cbs.lm = make_ideal_gas_lm();

  // Dynamic execution
  const auto dyn_res =
      reg.invoke_function("compute_ideal_gas_pressure", payload_val, cbs);
  require(dyn_res.has_value(), "dynamic Ideal Gas Law execution must succeed");
  const auto &dyn = dyn_res.value();
  require(!dyn.used_compiled, "dynamic run must report used_compiled=false");
  require(dyn.do_calls == 2U, "dynamic run must perform 2 do_ calls");
  require(dyn.search_calls == 2U, "dynamic run must perform 2 registry searches");
  require(dyn.lm_calls == 4U,
          "expected 4 LM calls (n, V, temp_value extract + unit lm)");
  const double kpa = get_number_field(dyn.output, "the calculated pressure in kPa");
  const double mpa = get_number_field(dyn.output, "the calculated pressure in MPa");
  const double bar = get_number_field(dyn.output, "the calculated pressure in bar");
  const double atm = get_number_field(dyn.output, "the calculated pressure in atm");
  require(std::fabs(kpa - 5132.0987) < 0.05, "kPa must be ~5132.10");
  require(std::fabs(mpa - 5.1321) < 0.01, "MPa must be ~5.13");
  require(std::fabs(bar - 51.321) < 0.05, "bar must be ~51.32");
  require(std::fabs(atm - 50.65) < 0.05, "atm must be ~50.65");

  // Figure 8 indented narration trace: root lines depth 0, sub-function lines depth 1
  // ("  ")
  require(dyn.narration_trace.find("Calculating pressure for ethane") !=
              std::string::npos,
          "root narration missing");
  require(dyn.narration_trace.find("\n  Received temperature specification: 27 C") !=
              std::string::npos,
          "indented child narration missing");

  // Static DAG Compilation (Section 2.2.3 & Fig. 7)
  const auto comp_res = reg.compile_network("compute_ideal_gas_pressure", true);
  require(comp_res.has_value(), "compile_network must succeed");
  const auto &mod = comp_res.value();
  require(mod.included_function_ids.size() == 3U, "expected 3 compiled functions");
  require(mod.resolved_do_sites == 2U, "expected 2 statically resolved do_ sites");
  require(mod.resolved_load_sites >= 11U,
          "expected >= 11 statically resolved load sites");

  // Compiled execution: ZERO FTS5/registry searches, identical numerical outputs!
  const auto fast_res =
      reg.invoke_compiled("compute_ideal_gas_pressure", payload_val, cbs);
  require(fast_res.has_value(), "invoke_compiled must succeed");
  const auto &fast = fast_res.value();
  require(fast.used_compiled, "compiled run must report used_compiled=true");
  require(fast.search_calls == 0U,
          "compiled execution MUST perform 0 registry searches");
  require(fast.load_search_calls == 0U,
          "compiled execution MUST perform 0 dynamic load searches");
  require(fast.do_calls == 0U, "compiled execution MUST bypass dynamic arc.do_");
  require(std::fabs(get_number_field(fast.output, "the calculated pressure in kPa") -
                    kpa) < 1e-9,
          "compiled kPa must match dynamic kPa exactly");
  require(std::fabs(get_number_field(fast.output, "the calculated pressure in MPa") -
                    mpa) < 1e-9,
          "compiled MPa must match dynamic MPa exactly");
}

// ---------------------------------------------------------------------------
// 2. Vertex Rotation Example (Fig. 2) + Layered Context Isolation + smart_convert +
// Tool Taint
// ---------------------------------------------------------------------------

void test_vertex_rotation_layered_scoping_and_primitives() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  auto &reg = reg_res.value();

  // Sub-function: compute difference set D(B) mod n.
  // Also tests that child layer shadows parent's `shadow_key` without mutating parent!
  ArcFunctionRecord diff_fn{};
  diff_fn.id = "compute_difference_set";
  diff_fn.description =
      "Compute the difference set D(B) for the vertex subset B with modulus n";
  diff_fn.params = {
      ArcParamSpec{"B", "the set of vertices B", "list", "[0, 2]", true},
      ArcParamSpec{"n", "the modulus n for modular arithmetic", "int", "6", true},
      ArcParamSpec{"tag", "scope marker tag", "str", "child", false},
  };
  diff_fn.return_keys = {"the difference set D(B)", "child observed tag"};
  diff_fn.lua_source = R"LUA(
function semantic_function(ctx)
  local B = arc.load(ctx, "the set of vertices B", "list")
  local n = arc.load(ctx, "the modulus n for modular arithmetic", "int")
  local tag = arc.load(ctx, "scope marker tag", "str")
  local seen = {}
  local diff = {}
  for i = 1, #B do
    for j = 1, #B do
      local d = ((B[i] - B[j]) % n + n) % n
      if not seen[d] then
        seen[d] = true
        diff[#diff + 1] = d
      end
    end
  end
  table.sort(diff)
  arc.narrate(ctx, "Computed difference set of size " .. tostring(#diff))
  return {
    ["the difference set D(B)"] = diff,
    ["child observed tag"] = tag
  }
end
)LUA";
  require(reg.register_function(diff_fn).has_value(),
          "register compute_difference_set");

  // Root: Vertex Rotation (Fig. 2)
  ArcFunctionRecord rot_fn{};
  rot_fn.id = "check_vertex_rotation";
  rot_fn.description =
      "Check if a valid rotation exists that maps blue vertices on an n-gon to red "
      "positions";
  rot_fn.is_root = true;
  rot_fn.params = {
      ArcParamSpec{"B", "the blue vertex set B", "list", "[0, 2]", true},
      ArcParamSpec{"n", "the vertex count n", "int", "6", true},
      ArcParamSpec{"tag", "scope marker tag", "str", "parent", false},
  };
  rot_fn.return_keys = {
      "valid rotation exists", "valid k values", "parent tag after child", "child tag",
      "smart converted",       "tool echo",
  };
  rot_fn.lua_source = R"LUA(
function semantic_function(ctx)
  arc.narrate(ctx, "Checking if a valid rotation exists that maps blue vertices to red positions")
  local vertex_set = arc.load(ctx, "the blue vertex set B", "list")
  local modulus = arc.load(ctx, "the vertex count n", "int")

  local diff_result = arc.do_(ctx,
    "Compute the difference set D(B) for the vertex subset B with modulus n",
    {
      ["the set of vertices B"] = vertex_set,
      ["the modulus n for modular arithmetic"] = modulus,
      ["scope marker tag"] = "child_shadow_value"
    })

  -- Fig. 2 line 20: semantic load directly on returned dictionary table!
  local diff_list = arc.load(diff_result, "difference set", "list")
  local child_tag = arc.load(diff_result, "child observed tag", "str")
  -- Verify parent layer was NOT mutated by child shadowing!
  local parent_tag_after = arc.load(ctx, "scope marker tag", "str")

  local in_diff = {}
  for i = 1, #diff_list do
    in_diff[diff_list[i]] = true
  end

  local valid_k = {}
  for k = 0, modulus - 1 do
    if not in_diff[k] then
      valid_k[#valid_k + 1] = k
    end
  end

  -- Exercise arc.smart_convert (LM JSON fallback) and arc.invoke_tool (with Brakes taint)
  local sc = arc.smart_convert(ctx, "forty-two", "int")
  local tool_res = arc.invoke_tool(ctx, "echo_tool", { count = #valid_k })

  arc.narrate(ctx, "Valid rotation count: " .. tostring(#valid_k))
  return {
    ["valid rotation exists"] = (#valid_k > 0),
    ["valid k values"] = valid_k,
    ["parent tag after child"] = parent_tag_after,
    ["child tag"] = child_tag,
    ["smart converted"] = sc,
    ["tool echo"] = tool_res.echoed
  }
end
)LUA";
  require(reg.register_function(rot_fn).has_value(), "register check_vertex_rotation");

  Value::Array b_arr;
  b_arr.emplace_back(Number{std::int64_t{0}});
  b_arr.emplace_back(Number{std::int64_t{2}});
  Value::Object payloads;
  payloads.emplace_back("the blue vertex set B", Value{std::move(b_arr)});
  payloads.emplace_back("the vertex count n", Value{Number{std::int64_t{6}}});
  payloads.emplace_back("scope marker tag", Value{"parent_original_value"});

  brakes::TurnTaintState taint_state{};
  require(!taint_state.is_tainted(), "turn taint starts untainted");

  ArcRuntimeCallbacks cbs{};
  cbs.lm = make_ideal_gas_lm();
  cbs.tool = [](std::string_view name, const Value &args) -> Result<Value> {
    require(name == "echo_tool", "expected echo_tool");
    const Value *cnt = args.find("count");
    require(cnt != nullptr, "expected count arg");
    Value::Object resp;
    resp.emplace_back("echoed", *cnt);
    return Result<Value>::success(Value::object(std::move(resp)));
  };
  cbs.turn_taint = &taint_state;

  const auto res = reg.invoke_function("check_vertex_rotation",
                                       Value::object(std::move(payloads)), cbs);
  require(res.has_value(), "vertex rotation execution must succeed");
  const auto &out = res.value().output;

  const Value *exists = out.find("valid rotation exists");
  require(exists != nullptr && std::get<bool>(exists->value()),
          "valid rotation must exist for B={0,2}, n=6");

  // D({0,2}) mod 6 = {0, 2, 4}, so valid k = {1, 3, 5}!
  const Value *ks = out.find("valid k values");
  require(ks != nullptr, "missing valid k values");
  const auto &k_arr = std::get<Value::Array>(ks->value());
  require(k_arr.size() == 3U, "expected 3 valid rotations {1, 3, 5}");
  require(std::get<std::int64_t>(std::get<Number>(k_arr[0].value()).storage()) == 1 &&
              std::get<std::int64_t>(std::get<Number>(k_arr[1].value()).storage()) ==
                  3 &&
              std::get<std::int64_t>(std::get<Number>(k_arr[2].value()).storage()) == 5,
          "expected valid rotations [1, 3, 5]");

  // Layered scoping check
  const Value *ptag = out.find("parent tag after child");
  const Value *ctag = out.find("child tag");
  require(ptag != nullptr &&
              std::get<std::string>(ptag->value()) == "parent_original_value",
          "parent context layer must NOT be mutated by child shadowing");
  require(ctag != nullptr &&
              std::get<std::string>(ctag->value()) == "child_shadow_value",
          "child context layer must shadow parent cleanly");

  // smart_convert + Brakes tool taint propagation
  require(get_number_field(out, "smart converted") == 42.0,
          "smart_convert returned 42");
  require(get_number_field(out, "tool echo") == 3.0, "tool returned echoed count 3");
  require(taint_state.is_tainted() && res.value().turn_tainted,
          "arc.invoke_tool MUST propagate Brakes TurnTaintState");
}

// ---------------------------------------------------------------------------
// 3. Gated serve() (Fig. 1: Hit, IS2 Param Extraction, Miss Fallback, Error Fallback)
// ---------------------------------------------------------------------------

void test_gated_serve_and_fallback() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  auto &reg = reg_res.value();
  register_ideal_gas_network(reg);

  bool source_called = false;
  ArcRuntimeCallbacks cbs{};
  cbs.lm = make_ideal_gas_lm();
  cbs.source_fallback = [&](std::string_view req) -> Result<Value> {
    source_called = true;
    Value::Object obj;
    obj.emplace_back("source_answer", Value{"fallback_for:" + std::string{req}});
    return Result<Value>::success(Value::object(std::move(obj)));
  };

  // Case A: Cache hit + IS2 automatic parameter extraction via target LM!
  {
    const auto res = reg.serve(
        "Calculate the pressure exerted by 10.0 mol of ethane in 4.86 dm^3 at 27 C "
        "using the perfect gas law",
        Value::object({}), cbs);
    require(res.has_value(), "serve cache hit must succeed");
    require(res.value().cache_hit && !res.value().fell_back_to_source,
            "expected clean cache hit");
    require(!source_called, "source model S must NOT be invoked on cache hit");
    require(std::fabs(
                get_number_field(res.value().output, "the calculated pressure in kPa") -
                5132.10) < 0.1,
            "serve IS2+IS3 result must match ~5132.10 kPa");
  }

  // Case B: Cache miss -> automatic fallback to source model S!
  {
    source_called = false;
    const auto res = reg.serve(
        "Explain the Byzantine generals consensus theorem in distributed systems",
        Value::object({}), cbs);
    require(res.has_value(), "cache miss with source_fallback must succeed");
    require(!res.value().cache_hit && res.value().fell_back_to_source && source_called,
            "cache miss must fall back to source S");
    require(res.value().fallback_reason == "cache_miss",
            "expected fallback_reason=cache_miss");
  }

  // Case C: Runtime error during cache hit -> automatic fallback to source model S!
  {
    ArcFunctionRecord broken_fn{};
    broken_fn.id = "broken_solver";
    broken_fn.description = "Solve quantum chromodynamics lattice gauge integral";
    broken_fn.is_root = true;
    broken_fn.entry_templates = {"Solve quantum chromodynamics lattice gauge integral"};
    broken_fn.lua_source = R"LUA(
function semantic_function(ctx)
  local missing = arc.load(ctx, "nonexistent_required_tensor", "float")
  return { result = missing }
end
)LUA";
    require(reg.register_function(broken_fn).has_value(), "register broken_solver");

    source_called = false;
    const auto res = reg.serve("Solve quantum chromodynamics lattice gauge integral",
                               Value::object({}), cbs);
    require(res.has_value(),
            "runtime error with source_fallback must never lose request");
    require(res.value().cache_hit && res.value().fell_back_to_source && source_called,
            "runtime error must fall back to source S");
    require(res.value().fallback_reason == "load_not_found",
            "expected fallback_reason=load_not_found");

    const auto st = reg.stats();
    require(st.has_value(), "registry stats");
    require(st.value().total_successes >= 1U && st.value().total_failures >= 1U &&
                st.value().total_fallbacks >= 1U,
            "stats must track hits, failures, and fallbacks");
  }
}

// ---------------------------------------------------------------------------
// 4. Static Compiler Cycle Detection & Perturbation Verification (Section 3.1/3.2)
// ---------------------------------------------------------------------------

void test_compiler_cycle_detection_and_perturbation_verification() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  auto &reg = reg_res.value();

  // Register a 2-node cycle A -> B -> A and confirm compile_cycle_detected!
  ArcFunctionRecord fn_a{};
  fn_a.id = "cycle_alpha";
  fn_a.description = "Alpha cyclic solver step";
  fn_a.lua_source = R"LUA(
function semantic_function(ctx)
  return arc.do_(ctx, "Beta cyclic solver step", {})
end
)LUA";
  ArcFunctionRecord fn_b{};
  fn_b.id = "cycle_beta";
  fn_b.description = "Beta cyclic solver step";
  fn_b.lua_source = R"LUA(
function semantic_function(ctx)
  return arc.do_(ctx, "Alpha cyclic solver step", {})
end
)LUA";
  require(reg.register_function(fn_a).has_value(), "register cycle_alpha");
  require(reg.register_function(fn_b).has_value(), "register cycle_beta");

  const auto cyc_comp = reg.compile_network("cycle_alpha", false);
  require(!cyc_comp.has_value() &&
              arc_error_of(cyc_comp.error()) == ArcError::compile_cycle_detected,
          "compiler MUST detect recursion cycles with compile_cycle_detected");

  // Also verify runtime recursion guard catches A -> B -> A!
  ArcExecutionLimits rec_limits{};
  rec_limits.max_call_depth = 4U;
  const auto rec_run =
      reg.invoke_function("cycle_alpha", Value::object({}), {}, rec_limits);
  require(!rec_run.has_value() &&
              arc_error_of(rec_run.error()) == ArcError::recursion_limit_exceeded,
          "infinite arc.do_ recursion MUST fail with recursion_limit_exceeded");

  // Perturbation verification across golden, phrasal, parametric, combined modes!
  register_ideal_gas_network(reg);
  require(reg.compile_network("compute_ideal_gas_pressure", true).has_value(),
          "compile ideal gas network for verification");

  struct GasInputs {
    std::string_view mol;
    std::string_view vol;
    std::string_view temp;
  };
  auto make_payload = [](GasInputs in) {
    Value::Object obj;
    obj.emplace_back("the molar amount of gas", Value{std::string{in.mol}});
    obj.emplace_back("the container volume", Value{std::string{in.vol}});
    obj.emplace_back("the temperature with unit", Value{std::string{in.temp}});
    obj.emplace_back("the common name of the gas", Value{"ethane"});
    obj.emplace_back("the gas model or assumption to use", Value{"perfect gas"});
    return Value::object(std::move(obj));
  };

  std::vector<ArcVerificationCase> cases;
  cases.push_back(ArcVerificationCase{
      "golden_1",
      ArcPerturbationMode::golden,
      "Calculate the pressure exerted by 10.0 mol of ethane in 4.86 dm^3 at 27 C using "
      "the perfect gas law",
      make_payload(GasInputs{"10.0 mol", "4.86 dm^3", "27 C"}),
      Value{Number{5132.10}},
      "the calculated pressure in kPa",
      1e-3,
      0.0434,
      0.0005,
  });
  cases.push_back(ArcVerificationCase{
      "phrasal_1",
      ArcPerturbationMode::phrasal,
      "Determine ideal gas pressure for ethane gas given molar amount volume and "
      "temperature under perfect gas law",
      make_payload(GasInputs{"10.0 mol", "4.86 dm^3", "27 C"}),
      Value{Number{5132.10}},
      "the calculated pressure in kPa",
      1e-3,
      0.0434,
      0.0005,
  });
  cases.push_back(ArcVerificationCase{
      "parametric_1",
      ArcPerturbationMode::parametric,
      "Calculate the pressure exerted by 20.0 mol of gas in 4.86 dm^3 at 27 C using "
      "the "
      "perfect gas law",
      make_payload(GasInputs{"20.0 mol", "4.86 dm^3", "27 C"}),
      Value{Number{10264.20}},
      "the calculated pressure in kPa",
      1e-3,
      0.0434,
      0.0005,
  });
  cases.push_back(ArcVerificationCase{
      "combined_1",
      ArcPerturbationMode::combined,
      "Compute ideal gas pressure for 20.0 mol of methane confined in 4.86 dm^3 volume "
      "at 27 C temperature",
      Value::object({}), // forces IS2 LM parameter extraction!
      Value{Number{10264.20}},
      "the calculated pressure in kPa",
      1e-3,
      0.0434,
      0.0005,
  });

  ArcRuntimeCallbacks cbs{};
  cbs.lm = make_ideal_gas_lm();
  const auto rep_res = reg.verify_candidate(cases, cbs);
  require(rep_res.has_value(), "verify_candidate must succeed");
  const auto &rep = rep_res.value();
  require(rep.total_cases == 4U && rep.passed_cases == 4U,
          "all 4 perturbation modes must pass");
  require(rep.golden.pass_rate == 1.0 && rep.phrasal.pass_rate == 1.0 &&
              rep.parametric.pass_rate == 1.0 && rep.combined.pass_rate == 1.0,
          "each perturbation mode pass_rate must be 1.0");
  require(rep.savings_multiplier > 80.0 && rep.cost_ratio < 0.02,
          "cost ratio & savings multiplier must reflect SciBench 86x savings");
}

// ---------------------------------------------------------------------------
// 5. Adversarial Sandbox Escape Tests
// ---------------------------------------------------------------------------

void test_adversarial_sandbox_escapes() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  auto &reg = reg_res.value();

  struct AdversarialCase {
    std::string_view id;
    std::string_view lua_src;
    ArcError expected_err = ArcError::sandbox_violation;
    ArcExecutionLimits limits{};
  };

  auto register_and_run = [&](const AdversarialCase &tc) {
    ArcFunctionRecord rec{};
    rec.id = std::string{tc.id};
    rec.description = "Adversarial test " + std::string{tc.id};
    rec.lua_source = std::string{tc.lua_src};
    const auto rreg = reg.register_function(rec);
    if (!rreg.has_value()) {
      require(arc_error_of(rreg.error()) == tc.expected_err,
              "register_function error mismatch for " + std::string{tc.id} + ": got " +
                  std::string{arc_error_name(arc_error_of(rreg.error()))});
      return;
    }
    const auto rrun = reg.invoke_function(tc.id, Value::object({}), {}, tc.limits);
    require(!rrun.has_value(), "adversarial script MUST fail: " + std::string{tc.id});
    require(arc_error_of(rrun.error()) == tc.expected_err,
            "runtime error mismatch for " + std::string{tc.id} + ": got " +
                std::string{arc_error_name(arc_error_of(rrun.error()))} +
                ", expected " + std::string{arc_error_name(tc.expected_err)});
  };

  register_and_run({"esc_os",
                    "function semantic_function(ctx) os.execute('id') return {} end",
                    ArcError::sandbox_violation});
  register_and_run(
      {"esc_io",
       "function semantic_function(ctx) io.open('/etc/passwd', 'r') return {} end",
       ArcError::sandbox_violation});
  register_and_run(
      {"esc_debug",
       "function semantic_function(ctx) return { x = debug.getinfo(1) } end",
       ArcError::sandbox_violation});
  register_and_run(
      {"esc_load",
       "function semantic_function(ctx) return { x = load('return 1')() } end",
       ArcError::sandbox_violation});
  register_and_run(
      {"esc_string_dump",
       "function semantic_function(ctx) return { x = string.dump(function() end) } end",
       ArcError::sandbox_violation});
  register_and_run(
      {"esc_ctx_mt_set",
       "function semantic_function(ctx) setmetatable(ctx, {}) return {} end",
       ArcError::sandbox_violation});
  register_and_run({"esc_ctx_mutate",
                    "function semantic_function(ctx) ctx.hack = 1 return {} end",
                    ArcError::sandbox_violation});

  // Binary Lua bytecode chunk (\x1bLua...) rejected at registration & execution!
  const std::string bytecode = std::string{"\x1bLua"} + std::string(16U, '\0');
  register_and_run({"esc_bytecode", bytecode, ArcError::sandbox_violation});

  // Infinite loop caught by instruction hook (even if wrapped in pcall!)
  ArcExecutionLimits insn_limits{};
  insn_limits.max_lua_instructions = 20000U;
  insn_limits.timeout_ms = 5000U;
  register_and_run({"esc_inf_loop",
                    "function semantic_function(ctx) pcall(function() while true do "
                    "end end) return {} end",
                    ArcError::instruction_limit_exceeded, insn_limits});

  // Wall-clock timeout hook
  ArcExecutionLimits time_limits{};
  time_limits.max_lua_instructions = 1000000000ULL;
  time_limits.timeout_ms = 30U;
  register_and_run({"esc_timeout",
                    "function semantic_function(ctx) local x = 0 while true do x = x + "
                    "1 end return {} end",
                    ArcError::timeout, time_limits});

  // Memory bomb caught by custom lua_Alloc cap!
  ArcExecutionLimits mem_limits{};
  mem_limits.max_lua_memory_bytes = 512U * 1024U; // 512 KiB cap
  mem_limits.max_lua_instructions = 5000000U;
  register_and_run({"esc_mem_bomb",
                    "function semantic_function(ctx) "
                    "local s = 'aaaaaaaaaa' "
                    "for i = 1, 30 do s = s .. s end "
                    "return { len = #s } end",
                    ArcError::memory_limit_exceeded, mem_limits});
}

// ---------------------------------------------------------------------------
// 6. Persistence Across Reopen + Symlink Rejection + 0600 Perms + Dense Embedder
// ---------------------------------------------------------------------------

void test_persistence_security_and_dense_embeddings() {
  TempDir tmp;
  const fs::path db_path = tmp.root / "nested_arc" / "cache.db";

  // Custom deterministic 2D embedder testing hybrid dense cosine similarity!
  auto embedder = [](std::string_view text) -> Result<std::vector<float>> {
    if (text.find("orbital") != std::string_view::npos ||
        text.find("rocket") != std::string_view::npos) {
      return Result<std::vector<float>>::success({1.0F, 0.0F});
    }
    return Result<std::vector<float>>::success({0.0F, 1.0F});
  };

  {
    ArcRegistryConfig cfg{};
    cfg.embed_callback = embedder;
    auto reg_res = ArcRegistry::open(db_path, cfg);
    require(reg_res.has_value(), "open persistent ArcRegistry");
    auto &reg = reg_res.value();

    // Verify 0700 parent dir and 0600 DB file permissions!
    struct stat dir_st{};
    require(::lstat(db_path.parent_path().c_str(), &dir_st) == 0 &&
                (dir_st.st_mode & 0777) == 0700,
            "parent directory must have 0700 permissions");
    struct stat db_st{};
    require(::lstat(db_path.c_str(), &db_st) == 0 && (db_st.st_mode & 0777) == 0600,
            "DB file must have 0600 permissions");

    ArcFunctionRecord fn{};
    fn.id = "delta_v_calc";
    fn.description = "Compute rocket orbital transfer delta-v";
    fn.is_root = true;
    fn.entry_templates = {"Compute rocket orbital transfer delta-v"};
    fn.lua_source = R"LUA(
function semantic_function(ctx)
  local isp = arc.load(ctx, "specific impulse", "float")
  return { ["exhaust velocity"] = isp * 9.80665 }
end
)LUA";
    require(reg.register_function(fn).has_value(), "register delta_v_calc");
    require(
        reg.record_cost("delta_v_calc", ArcCostSample{0.05, 0.50, 0.001}).has_value(),
        "record_cost");
    require(reg.compile_network("delta_v_calc", true).has_value(),
            "compile delta_v_calc");
  }

  // Reopen from disk and confirm function, compiled_lua, cost, and dense search
  // persist!
  {
    ArcRegistryConfig cfg{};
    cfg.embed_callback = embedder;
    auto reg_res = ArcRegistry::open(db_path, cfg);
    require(reg_res.has_value(), "reopen persistent ArcRegistry");
    auto &reg = reg_res.value();

    const auto got = reg.get_function("delta_v_calc");
    require(got.has_value(), "persisted function must survive reopen");
    require(got.value().compiled_lua.has_value() && !got.value().compiled_lua->empty(),
            "compiled_lua must survive reopen");
    require(std::fabs(got.value().total_source_cost_usd - 0.05) < 1e-9,
            "cost accumulator must survive reopen");

    const auto matches = reg.search_functions("orbital trajectory", 5U);
    require(matches.has_value() && !matches.value().empty() &&
                matches.value()[0].function_id == "delta_v_calc" &&
                matches.value()[0].dense_score > 0.99,
            "dense embedding cosine similarity must survive reopen");

    const auto listed = reg.list_functions();
    require(listed.has_value() && listed.value().size() == 1U, "list_functions size 1");
    require(reg.remove_function("delta_v_calc").has_value(), "remove_function");
    require(reg.list_functions().value().empty(), "registry empty after remove");
  }

  // Symlink DB path MUST be rejected with ArcError::insecure_path!
  {
    const fs::path symlink_db = tmp.root / "symlink_cache.db";
    fs::create_symlink(db_path, symlink_db);
    const auto sym_res = ArcRegistry::open(symlink_db);
    require(!sym_res.has_value() &&
                arc_error_of(sym_res.error()) == ArcError::insecure_path,
            "ArcRegistry::open MUST reject symlink DB path");
  }

  // Invalid ID validation
  {
    auto reg = ArcRegistry::open_in_memory().value();
    ArcFunctionRecord bad{};
    bad.id = "../escape";
    bad.lua_source = "function semantic_function(ctx) return {} end";
    const auto r = reg.register_function(bad);
    require(!r.has_value() && arc_error_of(r.error()) == ArcError::invalid_id,
            "invalid function ID MUST be rejected");
  }
}

// ---------------------------------------------------------------------------
// 7. Regression Tests for OOM Safety (zero longjmp RAII leaks) & Compiler Edge Cases
// ---------------------------------------------------------------------------

void test_oom_longjmp_safety_and_compiler_edge_cases() {
  auto reg_res = ArcRegistry::open_in_memory();
  require(reg_res.has_value(), "open_in_memory");
  auto &reg = reg_res.value();

  // Regression A: Repeated OOM during arc.load pushing a 512 KB string under 256 KB cap
  // (must fail cleanly with memory_limit_exceeded and zero C++ RAII heap leaks!)
  {
    ArcFunctionRecord big_fn{};
    big_fn.id = "load_big_blob";
    big_fn.description = "Load a large blob from context";
    big_fn.lua_source = R"LUA(
function semantic_function(ctx)
  local s = arc.load(ctx, "huge payload blob", "str")
  return { size = #s }
end
)LUA";
    require(reg.register_function(big_fn).has_value(), "register load_big_blob");

    Value::Object payloads;
    payloads.emplace_back("huge payload blob", Value{std::string(512U * 1024U, 'X')});
    const Value payload_val = Value::object(std::move(payloads));

    ArcExecutionLimits tight{};
    tight.max_lua_memory_bytes = 256U * 1024U;
    for (int i = 0; i < 20; ++i) {
      const auto r = reg.invoke_function("load_big_blob", payload_val, {}, tight);
      require(!r.has_value() &&
                  arc_error_of(r.error()) == ArcError::memory_limit_exceeded,
              "arc.load OOM must return memory_limit_exceeded cleanly");
    }
  }

  // Regression B: OOM inside arc.do_ callee setup must unwind cleanly!
  {
    ArcFunctionRecord child{};
    child.id = "oom_child";
    child.description = "Allocate large string inside child callee";
    child.lua_source = R"LUA(
function semantic_function(ctx)
  local s = string.rep("A", 1024)
  for i = 1, 20 do s = s .. s end
  return { len = #s }
end
)LUA";
    ArcFunctionRecord parent{};
    parent.id = "oom_parent";
    parent.description = "Delegate to child that hits Lua OOM";
    parent.lua_source = R"LUA(
function semantic_function(ctx)
  return arc.do_(ctx, "Allocate large string inside child callee", {})
end
)LUA";
    require(reg.register_function(child).has_value(), "register oom_child");
    require(reg.register_function(parent).has_value(), "register oom_parent");

    ArcExecutionLimits tight{};
    tight.max_lua_memory_bytes = 256U * 1024U;
    const auto r = reg.invoke_function("oom_parent", Value::object({}), {}, tight);
    require(!r.has_value() &&
                arc_error_of(r.error()) == ArcError::memory_limit_exceeded,
            "arc.do_ child OOM must return memory_limit_exceeded cleanly");
  }

  // Regression C: Nested arc.do_ + arc.load + `semantic_function = function(c)` +
  // non-"ctx" parameter name + narration depth/function_id parity!
  {
    ArcFunctionRecord dbl{};
    dbl.id = "double_number";
    dbl.description = "double the integer number n";
    dbl.params = {ArcParamSpec{"n", "number to double", "int", "21", true}};
    dbl.return_keys = {"doubled"};
    dbl.lua_source = R"LUA(
semantic_function = function(c)
  local v = arc.load(c, "number to double", "int")
  arc.narrate(c, "hello from child")
  return { ["doubled"] = v * 2 }
end
)LUA";

    ArcFunctionRecord caller{};
    caller.id = "nested_caller";
    caller.description = "call double with nested arc.load inside arc.do_ payloads";
    caller.params = {ArcParamSpec{"x", "input integer x", "int", "21", true}};
    caller.return_keys = {"doubled"};
    caller.lua_source = R"LUA(
semantic_function = function(my_ctx)
  arc.narrate(my_ctx, "hello from parent")
  local res = arc.do_(my_ctx, "double the integer number n", {
    ["number to double"] = arc.load(my_ctx, "input integer x", "int")
  })
  return { ["doubled"] = arc.load(res, "doubled", "int") }
end
)LUA";
    require(reg.register_function(dbl).has_value(), "register double_number");
    require(reg.register_function(caller).has_value(), "register nested_caller");

    Value::Object payloads;
    payloads.emplace_back("input integer x", Value{Number{std::int64_t{21}}});
    const Value pv = Value::object(std::move(payloads));

    const auto dyn = reg.invoke_function("nested_caller", pv);
    require(dyn.has_value(), "dynamic nested_caller must succeed");
    require(get_number_field(dyn.value().output, "doubled") == 42.0,
            "dynamic nested_caller doubled must be 42");

    const auto mod = reg.compile_network("nested_caller", false);
    require(mod.has_value(),
            "compile_network must handle nested calls & assignment form");
    const auto cmp = reg.invoke_compiled_module(mod.value(), pv);
    require(cmp.has_value(), "invoke_compiled_module must succeed");
    require(cmp.value().search_calls == 0U && cmp.value().load_search_calls == 0U,
            "compiled nested_caller must do 0 searches");
    require(get_number_field(cmp.value().output, "doubled") == 42.0,
            "compiled nested_caller doubled must be 42");

    // Exact narration depth & function_id parity between dynamic and compiled!
    require(
        cmp.value().narrations == dyn.value().narrations,
        "compiled narrations (depth, function_id, message) MUST match dynamic exactly");
    require(cmp.value().narration_trace == dyn.value().narration_trace,
            "compiled indented narration_trace MUST match dynamic exactly");
    require(cmp.value().narrations.size() == 2U &&
                cmp.value().narrations[0].depth == 0U &&
                cmp.value().narrations[0].function_id == "nested_caller" &&
                cmp.value().narrations[1].depth == 1U &&
                cmp.value().narrations[1].function_id == "double_number",
            "expected depth 0 parent and depth 1 child narration entries");
  }

  // Regression D: Identifier collision (`foo-bar` vs `foo_bar` in the same compiled
  // DAG)
  {
    ArcFunctionRecord dash{};
    dash.id = "foo-bar";
    dash.description = "return dashed alpha constant 100";
    dash.return_keys = {"val"};
    dash.lua_source = R"LUA(
function semantic_function(ctx)
  return { ["val"] = 100 }
end
)LUA";

    ArcFunctionRecord under{};
    under.id = "foo_bar";
    under.description = "return underscored beta constant 7";
    under.return_keys = {"val"};
    under.lua_source = R"LUA(
function semantic_function(ctx)
  return { ["val"] = 7 }
end
)LUA";

    ArcFunctionRecord both{};
    both.id = "sum_colliding_ids";
    both.description = "sum results of foo-bar and foo_bar";
    both.return_keys = {"total"};
    both.lua_source = R"LUA(
function semantic_function(ctx)
  local a = arc.do_(ctx, "return dashed alpha constant 100", {})
  local b = arc.do_(ctx, "return underscored beta constant 7", {})
  return { ["total"] = arc.load(a, "val", "int") + arc.load(b, "val", "int") }
end
)LUA";
    require(reg.register_function(dash).has_value(), "register foo-bar");
    require(reg.register_function(under).has_value(), "register foo_bar");
    require(reg.register_function(both).has_value(), "register sum_colliding_ids");

    const auto mod = reg.compile_network("sum_colliding_ids", false);
    require(mod.has_value(), "compile sum_colliding_ids");
    const auto cmp = reg.invoke_compiled_module(mod.value(), Value::object({}));
    require(cmp.has_value(), "invoke compiled sum_colliding_ids");
    require(get_number_field(cmp.value().output, "total") == 107.0,
            "foo-bar (100) + foo_bar (7) must be 107 without identifier collision");
  }
}

} // namespace

int main() {
  try {
    const int fds_before = count_open_fds();
    test_capabilities_and_ideal_gas_law_dynamic_vs_compiled();
    test_vertex_rotation_layered_scoping_and_primitives();
    test_gated_serve_and_fallback();
    test_compiler_cycle_detection_and_perturbation_verification();
    test_adversarial_sandbox_escapes();
    test_persistence_security_and_dense_embeddings();
    test_oom_longjmp_safety_and_compiler_edge_cases();
    const int fds_after = count_open_fds();
    require(fds_after == fds_before,
            "zero FD leaks across cpu_arc_test (before=" + std::to_string(fds_before) +
                ", after=" + std::to_string(fds_after) + ")");
    std::cout << "cpu_arc_test: ALL 7 TEST SUITES PASSED (0 FD leaks)\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "cpu_arc_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
