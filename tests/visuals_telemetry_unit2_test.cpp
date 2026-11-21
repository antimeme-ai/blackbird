#include "blackbird/coding.hpp"
#include "blackbird/context.hpp"
#include "blackbird/display_text.hpp"
#include "blackbird/json.hpp"
#include "blackbird/terminal.hpp"
#include <clocale>
#include <cmath>
#include <filesystem>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;
namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}
struct TempDir {
  std::filesystem::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};
std::unique_ptr<RetainedState> make_state(const std::filesystem::path &dir,
                                          unsigned char seed) {
  const JournalHeader header{
      make_id<EnvironmentId>(seed),
      make_id<AuditStreamId>(static_cast<unsigned char>(seed + 1)),
      1,
      {8 * 1024 * 1024, 24 * 1024 * 1024},
      std::nullopt};
  return unwrap(RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                          NativeJournalDirectory::open(dir.string()))),
                                      "audit", header, {64 * 1024 * 1024, 10000}));
}

void test_token_formatting_and_window_catalog() {
  require(terminal_format_tokens(0) == "0", "0 tokens");
  require(terminal_format_tokens(842) == "842", "sub-1k tokens");
  require(terminal_format_tokens(12000) == "12k", "exact k tokens");
  require(terminal_format_tokens(12440) == "12.4k", "tenths k tokens");
  require(terminal_format_tokens(128000) == "128k", "128k tokens");
  require(terminal_format_tokens(1048576) == "1M", "1M tokens");
  require(terminal_format_tokens(1250000) == "1.3M", "1.3M tokens");

  require(known_context_window_tokens("deepseek/deepseek-v4.1-flash") ==
              std::optional<std::uint64_t>{128000ULL},
          "deepseek window must be 128k");
  require(known_context_window_tokens("claude-opus-4-6") ==
              std::optional<std::uint64_t>{200000ULL},
          "claude-opus-4 window must be 200k");
  require(known_context_window_tokens("gemini-2.5-pro") ==
              std::optional<std::uint64_t>{1048576ULL},
          "gemini-2.5 window must be 1M");
  require(known_context_window_tokens("gpt-4o") ==
              std::optional<std::uint64_t>{128000ULL},
          "gpt-4o window must be 128k");
  require(known_context_window_tokens("openai/o3") ==
              std::optional<std::uint64_t>{200000ULL},
          "o3 window must be 200k");
  require(known_context_window_tokens("moonshot/kimi-k2") ==
              std::optional<std::uint64_t>{256000ULL},
          "kimi-k2 window must be 256k");
  require(!known_context_window_tokens("custom/nano3").has_value(),
          "nano3 must not false-match o3");
  require(!known_context_window_tokens("kimi-v1-8k").has_value(),
          "older kimi-v1 must not false-match kimi-k2");
  require(!known_context_window_tokens("custom/unknown-lab-model").has_value(),
          "unknown model must return nullopt rather than an invented window");
  require(
      terminal_format_tokens(std::numeric_limits<std::uint64_t>::max()).ends_with("M"),
      "UINT64_MAX token count must format without overflow");
}

void test_usage_summary_formatting() {
  TelemetrySnapshot snap{};
  snap.requests = 2;
  snap.last_input = 18200;
  snap.last_cached = 15288;
  snap.last_output = 640;
  snap.last_reasoning = 210;
  snap.last_duration_ms = 9000;
  snap.last_cost_usd = 0.042;
  snap.cost_usd = 0.99;
  const auto summary = terminal_usage_summary(snap);
  require(summary.find("18.2k in (84% cached)") != std::string::npos,
          "summary must include input tokens and cache hit %");
  require(summary.find("640 out") != std::string::npos,
          "summary must include output tokens");
  require(summary.find("71 tok/s") != std::string::npos,
          "summary must include measured throughput");
  require(summary.find("210 reason") != std::string::npos,
          "summary must include reasoning tokens");
  require(summary.find("$0.04") != std::string::npos &&
              summary.find("$0.99") == std::string::npos,
          "summary must show per-request last_cost_usd, not cumulative cost");

  // Sub-50ms duration must omit tok/s rather than printing noisy spikes.
  snap.last_duration_ms = 10;
  require(terminal_usage_summary(snap).find("tok/s") == std::string::npos,
          "sub-50ms duration must not emit spurious tok/s");

  // Huge/NaN cost and UINT64_MAX ratios must never UB or wrap.
  snap.last_cost_usd = std::numeric_limits<double>::quiet_NaN();
  (void)terminal_usage_summary(snap);
  snap.last_cost_usd = 1e20;
  require(terminal_usage_summary(snap).find("$1T+") != std::string::npos,
          "huge cost must cap cleanly without UB");
  snap.last_input = std::numeric_limits<std::uint64_t>::max();
  snap.last_cached = std::numeric_limits<std::uint64_t>::max();
  snap.last_output = std::numeric_limits<std::uint64_t>::max();
  snap.last_duration_ms = 1000;
  require(terminal_usage_summary(snap).find("100% cached") != std::string::npos,
          "UINT64_MAX ratio must not overflow");
}

void test_avionics_rail_colors_and_degradation() {
  TelemetrySnapshot empty{};
  require(terminal_avionics_rail(empty, 120).empty(),
          "empty telemetry must return empty rail");

  TelemetrySnapshot snap{};
  snap.requests = 3;
  snap.last_input = 42100;
  snap.last_cached = 35364;
  snap.last_output = 680;
  snap.total_input = 148000;
  snap.total_output = 9200;
  snap.last_duration_ms = 10000;
  snap.upstream_epoch = 2;
  snap.context_window = 128000;

  const auto wide = terminal_avionics_rail(snap, 120);
  const auto wide_text = chat_plain(wide);
  require(wide_text.find("ctx 42.1k/128k 33%") != std::string::npos,
          "wide rail must show context fraction and percentage");
  require(wide_text.find("▓") != std::string::npos, "wide rail must include gauge bar");
  require(wide_text.find("cache 84%") != std::string::npos,
          "wide rail must include cache hit %");
  require(wide_text.find("68 tok/s") != std::string::npos,
          "wide rail must include throughput");
  require(wide_text.find("Σ 148k/9.2k") != std::string::npos,
          "wide rail must include cumulative totals");
  require(wide_text.find("e2") != std::string::npos,
          "wide rail must include upstream epoch");
  require(wide.front().ink == Ink::success, "33% context must use success ink");

  // Threshold colors: >=70% amber (Ink::user), >=90% red (Ink::failure).
  snap.last_input = 96000; // 75%
  require(terminal_avionics_rail(snap, 120).front().ink == Ink::user,
          "75% context must use warning ink");
  snap.last_input = 118000; // 92%
  require(terminal_avionics_rail(snap, 120).front().ink == Ink::failure,
          "92% context must use danger ink");

  // Width degradation: never exceed max_cells at narrow widths.
  for (const std::size_t width :
       {std::size_t{90}, std::size_t{60}, std::size_t{40}, std::size_t{22}}) {
    const auto row = terminal_avionics_rail(snap, width);
    require(!row.empty(), "rail must render even at narrow widths");
    require(display_cells(chat_plain(row)).value <= width,
            "rail cell width must never exceed max_cells");
  }
  require(terminal_avionics_rail(snap, 8).empty(),
          "rail must return empty below minimum cell width");

  // LC_CTYPE=C fallback must render pure ASCII glyphs with accurate cell width.
  const char *prev_locale = std::setlocale(LC_CTYPE, nullptr);
  const std::string saved_locale = prev_locale ? prev_locale : "";
  std::setlocale(LC_CTYPE, "C");
  const auto ascii_row = terminal_avionics_rail(snap, 80);
  const auto ascii_text = chat_plain(ascii_row);
  require(ascii_text.find("#") != std::string::npos &&
              ascii_text.find(" | ") != std::string::npos &&
              ascii_text.find("tot ") != std::string::npos,
          "LC_CTYPE=C rail must fall back to readable ASCII");
  require(display_cells(ascii_text).value <= 80,
          "LC_CTYPE=C rail must stay within width");
  if (!saved_locale.empty())
    std::setlocale(LC_CTYPE, saved_locale.c_str());
}

void test_engine_cumulative_telemetry_and_stats() {
  TempDir dir{"bb-u2-telemetry"};
  auto root = make_state(dir.path, 71);
  AuditLog log{*root};
  ContextStore context{log};

  struct MeteredProvider final : public CodingProvider {
    unsigned calls = 0;
    Value respond(const Value &,
                  const std::function<void(std::string_view)> &capture) override {
      ++calls;
      std::this_thread::sleep_for(std::chrono::milliseconds{20});
      const auto sse =
          "data: {\"type\":\"response.output_text.delta\",\"item_id\":\"m1\","
          "\"delta\":\"hello\"}\n\n";
      capture(sse);
      std::this_thread::sleep_for(std::chrono::milliseconds{40});
      Value usage;
      if (calls == 1) {
        usage = Value::object(
            {{"input_tokens", Value{Number{10000}}},
             {"output_tokens", Value{Number{500}}},
             {"total_tokens", Value{Number{10500}}},
             {"input_tokens_details",
              Value::object({{"cached_tokens", Value{Number{8000}}},
                             {"cache_write_tokens", Value{Number{1000}}}})},
             {"output_tokens_details",
              Value::object({{"reasoning_tokens", Value{Number{120}}}})},
             {"cost", Value{Number{"0.015"}}}});
      } else {
        // Raw Anthropic Messages API shape: input_tokens is uncached-only, so
        // total input must equal 150 + 9000 + 500 = 9650.
        usage = Value::object({{"input_tokens", Value{Number{150}}},
                               {"output_tokens", Value{Number{300}}},
                               {"cache_read_input_tokens", Value{Number{9000}}},
                               {"cache_creation_input_tokens", Value{Number{500}}},
                               {"cost", Value{Number{"0.020"}}}});
      }
      return Value::object(
          {{"output", Value{Value::Array{Value::object(
                          {{"type", Value{"message"}},
                           {"role", Value{"assistant"}},
                           {"content", Value{Value::Array{Value::object(
                                           {{"type", Value{"output_text"}},
                                            {"text", Value{"hello"}}})}}}})}}},
           {"usage", std::move(usage)}});
    }
  } provider;

  CodingEngine engine{log, context, provider, "deepseek/deepseek-v4.1-flash"};
  std::vector<SessionTelemetry> observed;
  engine.observed_telemetry = [&](const SessionTelemetry &t) { observed.push_back(t); };

  engine.turn({.prompt = "two requests",
               .program = "blackbird.request(); blackbird.request()"});

  require(observed.size() == 2, "expected 2 telemetry observations");
  const auto &t = engine.telemetry();
  require(t.requests == 2, "cumulative request count");
  require(t.last_input_tokens == 9650,
          "raw Anthropic usage must sum uncached + cache_read + cache_creation");
  require(t.input_tokens == 19650, "cumulative input tokens");
  require(t.output_tokens == 800, "cumulative output tokens");
  require(t.cached_tokens == 17000, "cumulative cached tokens");
  require(t.cache_write_tokens == 1500, "cumulative cache write tokens");
  require(t.reasoning_tokens == 120, "cumulative reasoning tokens");
  require(t.last_duration_ms >= 50, "measured request duration");
  require(t.last_ttft_ms >= 10, "measured TTFT");
  require(t.context_window_tokens == std::optional<std::uint64_t>{128000ULL},
          "deepseek model window resolved");
  require(t.last_cost_usd.has_value() && *t.last_cost_usd > 0.019 &&
              *t.last_cost_usd < 0.021,
          "per-request last cost");
  require(t.session_cost_usd.has_value() && *t.session_cost_usd > 0.034 &&
              *t.session_cost_usd < 0.036,
          "cumulative reported cost");

  const auto stats = engine.stats();
  const auto &su = field(stats, "session_usage");
  require(field(su, "requests") == Value{Number{2}}, "stats session_usage.requests");
  require(field(su, "input_tokens") == Value{Number{19650}},
          "stats session_usage.input_tokens");
  require(field(su, "cached_tokens") == Value{Number{17000}},
          "stats session_usage.cached_tokens");
  require(field(su, "context_window_tokens") == Value{Number{128000}},
          "stats session_usage.context_window_tokens");
  require(su.find("session_cost_usd") != nullptr,
          "stats session_usage.session_cost_usd");
}
} // namespace

int main(int argc, char **argv) {
  if (!std::setlocale(LC_CTYPE, "") || display_cells("▓").value == 0) {
    if (!std::setlocale(LC_CTYPE, "en_US.UTF-8"))
      std::setlocale(LC_CTYPE, "C.UTF-8");
  }
  const std::string_view selected = argc >= 2 ? std::string_view{argv[1]} : "all";
  const std::pair<std::string_view, void (*)()> cases[]{
      {"token_formatting_and_window_catalog", test_token_formatting_and_window_catalog},
      {"usage_summary_formatting", test_usage_summary_formatting},
      {"avionics_rail_colors_and_degradation",
       test_avionics_rail_colors_and_degradation},
      {"engine_cumulative_telemetry_and_stats",
       test_engine_cumulative_telemetry_and_stats},
  };
  bool failed = false;
  for (const auto &[name, fn] : cases) {
    if (selected != "all" && selected != name)
      continue;
    try {
      fn();
      std::cout << "PASS " << name << '\n';
    } catch (const std::exception &error) {
      std::cerr << "FAIL " << name << ": " << error.what() << '\n';
      failed = true;
    } catch (const Error &error) {
      std::cerr << "FAIL " << name << ": Error(" << error_name(error.code) << ":"
                << error.detail << ")\n";
      failed = true;
    }
  }
  return failed ? 1 : 0;
}
