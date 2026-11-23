#include "blackbird/coding.hpp"
#include "blackbird/decision_models.hpp"
#include "blackbird/json.hpp"
#include "blackbird/provider_auth.hpp"
#include <iostream>
#include <unistd.h>

using namespace blackbird;
namespace {
void check(bool value, const char *message) {
  if (!value)
    throw std::runtime_error(message);
}
Value parse(std::string_view s) { return unwrap(parse_json(s)); }
Value request() {
  return parse(R"({"state":{"message":"Compiler error: mismatched types"},"questions":{
    "route":{"type":"choice","instructions":"Classify message","criteria":{"compiler":"Compilation error","other":null}},
    "failure":{"type":"noul","instructions":{"question":"Does message report failure?"}},
    "severity":{"type":"score","instructions":"Rate severity","criteria":["None","Moderate","Severe"]}}})");
}
std::string response(std::string_view model = "jev-1.13.0") {
  return std::string{R"({"model":")"} + std::string{model} + R"(","answers":{
    "route":{"type":"choice","choice":"compiler","probabilities":{"compiler":0.8,"other":0.2},"confidence":0.7},
    "failure":{"type":"noul","noul":0.9},
    "severity":{"type":"score","score":1.5,"probabilities":{"0":0,"1":0.5,"2":0.5},"legend":{"0":"None","1":"Moderate","2":"Severe"},"confidence":0.5}},
    "usage":{"input_tokens":421,"output_tokens":14}})";
}
void set(Value &v, std::string_view key, Value value) {
  for (auto &[k, x] : v.object())
    if (k == key) {
      x = std::move(value);
      return;
    }
  v.object().emplace_back(std::string{key}, std::move(value));
}
template <class F> void rejects(F f, ErrorCode code) {
  try {
    f();
  } catch (const Error &e) {
    check(e.code == code, "wrong failure class");
    return;
  }
  throw std::runtime_error("invalid case accepted");
}
int fake(int argc, char **argv) {
  const auto base = std::filesystem::path(std::getenv("BB_JEV_TEST_ROOT"));
  Value::Array args;
  for (int i = 1; i < argc; ++i)
    args.emplace_back(std::string{argv[i]});
  write_file(base / "argv", unwrap(dump_json(Value{args})));
  std::string input{std::istreambuf_iterator<char>{std::cin},
                    std::istreambuf_iterator<char>{}};
  const auto mode = read_file(base / "mode");
  if (mode == "clef") {
    if (input.find("http://127.0.0.1:11435/v1/systemone") == std::string::npos ||
        input.find("Authorization:") != std::string::npos)
      return 12;
    std::cout << response("clef-8b-v1") << "\n200";
    return 0;
  }
  if (mode == "tailscale_clef") {
    if (input.find("http://100.64.12.34:11435/v1/systemone") == std::string::npos ||
        input.find("Authorization:") != std::string::npos)
      return 13;
    std::cout << response("clef-8b-v1") << "\n200";
    return 0;
  }
  if (mode == "custom_decision") {
    if (input.find("https://decision.example.test/v1/systemone") == std::string::npos ||
        input.find("Authorization: Bearer custom-decision-secret") == std::string::npos)
      return 14;
    std::cout << response("oracle-v2") << "\n200";
    return 0;
  }
  if (input.find("Authorization: Bearer native-test-secret") == std::string::npos ||
      input.find("https://api.typesafe.ai/v1/systemone") == std::string::npos)
    return 11;
  if (mode == "curl")
    return 56;
  if (mode == "http") {
    std::cout << "{\"error\":\"overload\"}\n529";
    return 0;
  }
  if (mode == "redirect") {
    std::cout << "\n302";
    return 0;
  }
  if (mode == "overflow") {
    std::cout << std::string(16384, 'x');
    return 0;
  }
  if (mode == "cancel" || mode == "timeout") {
    write_file(base / "started", "yes");
    sleep(3);
  }
  if (mode == "large") {
    std::cout << response() << std::string(131072, ' ') << "\n200";
    return 0;
  }
  if (mode == "malformed")
    std::cout << "not JSON\n200";
  else
    std::cout << response() << "\n200";
  return 0;
}
template <class T> T id(unsigned char value) {
  IdentityBytes b{};
  b[0] = std::byte{value};
  return unwrap(T::from_bytes(b));
}
class NoProvider final : public CodingProvider {
  Value respond(const Value &, const std::function<void(std::string_view)> &) override {
    throw std::runtime_error("unexpected conversational call");
  }
};
} // namespace
int main(int argc, char **argv) {
  if (argc > 1 && std::string_view{argv[1]} == "--disable")
    return fake(argc, argv);
  try {
    auto q = request();
    const auto service = jev_request(q);
    check(string_field(service, "model") == "jev-1.13.0", "default not pinned");
    validate_jev_response(service, parse(response()));
    for (const auto &bad : {"{}", "{\"state\":1,\"questions\":{}}",
                            "{\"state\":\"x\",\"questions\":{\"q\":{\"type\":\"score\","
                            "\"instructions\":\"x\",\"criteria\":[\"only\"]}}}",
                            "{\"state\":\"x\",\"questions\":{\"q\":{\"type\":"
                            "\"unknown\",\"instructions\":\"x\"}}}"})
      rejects([&] { (void)jev_request(parse(bad)); }, ErrorCode::invalid_range);
    auto credentials = q;
    set(credentials, "api_key", Value{"never accept"});
    rejects([&] { (void)jev_request(credentials); }, ErrorCode::invalid_range);
    auto alien = q;
    set(alien, "provider", Value{"alien"});
    rejects([&] { (void)jev_request(alien); }, ErrorCode::unsupported);
    auto model = parse(response());
    set(model, "model", Value{"jev-1.14.0"});
    rejects([&] { validate_jev_response(service, model); }, ErrorCode::corrupt);
    auto alias = q;
    set(alias, "model", Value{"jev-latest"});
    validate_jev_response(jev_request(alias), model);
    for (const auto &bad : {"\"noul\":1.9", "\"score\":1.7", "\"choice\":\"other\"",
                            "\"input_tokens\":-1"}) {
      auto bytes = response();
      const std::string key =
          std::string{bad}.substr(0, std::string{bad}.find(':') + 1);
      auto pos = bytes.find(key);
      auto end = bytes.find_first_of(",}", pos);
      bytes.replace(pos, end - pos, bad);
      rejects([&] { validate_jev_response(service, parse(bytes)); },
              ErrorCode::corrupt);
    }
    auto wrong_legend = parse(response());
    auto answers = field(wrong_legend, "answers");
    auto severity = field(answers, "severity");
    set(severity, "legend", parse(R"({"0":"Severe","1":"Moderate","2":"None"})"));
    set(answers, "severity", severity);
    set(wrong_legend, "answers", answers);
    rejects([&] { validate_jev_response(service, wrong_legend); }, ErrorCode::corrupt);
    auto missing = parse(response());
    auto fewer = field(missing, "answers");
    fewer.object().pop_back();
    set(missing, "answers", fewer);
    rejects([&] { validate_jev_response(service, missing); }, ErrorCode::corrupt);
    auto base = std::filesystem::temp_directory_path() /
                ("blackbird-jev-" + std::to_string(getpid()));
    std::filesystem::create_directories(base);
    std::filesystem::permissions(base, std::filesystem::perms::owner_all);
    (void)setenv("BB_JEV_TEST_ROOT", base.c_str(), 1);
    (void)unsetenv("TYPESAFE_API_KEY");
    (void)unsetenv("jev");
    write_file(base / "credentials", "export jev='native-test-secret' # local test\n");
    write_file(base / "mode", "ok");
    DecisionModelConfig config;
    config.curl_executable = std::filesystem::canonical(argv[0]);
    config.credential_file = base / "credentials";
    config.response_limit = 8192;
    DecisionModels adapter{config};
    std::string observed;
    adapter.observer = [&](std::string_view label, std::string_view bytes) {
      observed += label;
      observed += bytes;
    };
    const auto valid = adapter.evaluate(q);
    check(field(valid, "response") == parse(response()), "raw judgments changed");
    const auto args = read_file(base / "argv");
    check(args.find("native-test-secret") == std::string::npos &&
              observed.find("native-test-secret") == std::string::npos,
          "secret escaped transport");
    check(args.find("--disable") != std::string::npos &&
              args.find("--config") != std::string::npos &&
              args.find("=https") != std::string::npos &&
              args.find("--location") == std::string::npos,
          "curl controls missing");
    const auto &before = args;
    rejects([&] { (void)adapter.evaluate(credentials); }, ErrorCode::invalid_range);
    check(read_file(base / "argv") == before, "invalid request dispatched");
    observed.clear();
    write_file(base / "mode", "http");
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::external_unknown);
    check(observed.find("overload") != std::string::npos &&
              observed.find("529") != std::string::npos,
          "HTTP failure bytes lost");
    write_file(base / "mode", "redirect");
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::external_unknown);
    write_file(base / "mode", "curl");
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::provider_transport);
    write_file(base / "mode", "overflow");
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::capacity);
    write_file(base / "mode", "malformed");
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::corrupt);
    write_file(base / "mode", "large");
    auto large_config = config;
    large_config.response_limit = 262144;
    DecisionModels large{large_config};
    auto short_request = q;
    set(short_request, "timeout_seconds", Value{Number{"1"}});
    check(string_field(large.evaluate(short_request), "status") == "ok",
          "quiet stderr stalled body drainage");
    write_file(base / "mode", "cancel");
    adapter.cancelled = [&] { return std::filesystem::exists(base / "started"); };
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::interrupted);
    adapter.cancelled = {};
    write_file(base / "mode", "timeout");
    auto timed = q;
    set(timed, "timeout_seconds", Value{Number{"1"}});
    rejects([&] { (void)adapter.evaluate(timed); }, ErrorCode::provider_transport);
    write_file(base / "credentials", "jev='bad\nheader'\n");
    rejects([&] { (void)adapter.evaluate(q); }, ErrorCode::unsupported);
    write_file(base / "credentials", "jev=native-test-secret\n");
    write_file(base / "mode", "ok");
    // Verify ProviderAuth stored key (`blackbird auth key jev`) resolves lazily.
    {
      const auto auth_dir = base / "auth";
      (void)setenv("BLACKBIRD_AUTH_HOME", auth_dir.c_str(), 1);
      (void)unsetenv("BLACKBIRD_JEV_ENV_FILE");
      ProviderAuth auth;
      auth.set_key("jev", "default", "native-test-secret");
      DecisionModelConfig auth_cfg;
      auth_cfg.curl_executable = config.curl_executable;
      auth_cfg.response_limit = 8192;
      DecisionModels auth_adapter{auth_cfg};
      const auto via_auth = auth_adapter.evaluate(q);
      check(string_field(via_auth, "status") == "ok",
            "ProviderAuth stored jev key failed");
      (void)unsetenv("BLACKBIRD_AUTH_HOME");
    }
    const auto auditdir = base / "session";
    std::filesystem::create_directory(auditdir);
    std::filesystem::permissions(auditdir, std::filesystem::perms::owner_all);
    JournalHeader h{
        id<EnvironmentId>(51), id<AuditStreamId>(52), 3, {32768, 131072}, std::nullopt};
    auto root = unwrap(
        RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                  NativeJournalDirectory::open(auditdir.string()))),
                              "audit", h, {64 * 1024 * 1024, 10000}));
    AuditLog log{*root};
    ContextStore context{log};
    NoProvider provider;
    CodingEngine engine{log, context, provider, "test", config};
    engine.turn({"", "return blackbird.decide(blackbird.json.decode([=[" +
                         unwrap(dump_json(q)) + "]=]))"});
    const auto result = engine.workflow_result();
    const auto ref = string_field(result, "audit_ref");
    bool settled = false;
    for (const auto &fact : root->committed_facts())
      if (const auto *admission = std::get_if<AttemptAdmissionEvent>(&fact.event.body);
          admission && hex_identity(admission->attempt.bytes()) == ref) {
        const auto attempt = unwrap(root->attempt(admission->attempt));
        settled = attempt.opened && attempt.observation &&
                  attempt.observation->disposition == AttemptDisposition::success;
      }
    check(settled, "native effect not linked/settled");
    check(read_file(auditdir / "audit").find("native-test-secret") == std::string::npos,
          "credential in audit");
    check(read_file(auditdir / "audit").find("decision_model.response") !=
              std::string::npos,
          "raw response absent from audit");
    bool registered = false;
    bool open_provider_schema = false;
    const auto definitions = tool_definitions();
    for (const auto &tool : definitions.array())
      if (string_field(tool, "name") == "decision_model") {
        registered = true;
        const auto &props = field(field(tool, "parameters"), "properties");
        const auto &prov = field(props, "provider");
        open_provider_schema =
            string_field(prov, "type") == "string" && !prov.find("enum");
      }
    check(registered, "model tool missing");
    check(open_provider_schema,
          "decision_model provider schema still hardcoded to enum");

    // Generalized decision companion: built-in clef (loopback HTTP, no API key),
    // Tailscale CGNAT HTTP, remote plain HTTP rejection, custom ProviderAuth provider,
    // and blind-sealed decision trials.
    {
      const auto auth_dir = base / "companion-auth";
      (void)setenv("BLACKBIRD_AUTH_HOME", auth_dir.c_str(), 1);
      (void)unsetenv("CLEF_API_KEY");
      (void)unsetenv("BLACKBIRD_CLEF_URL");
      ProviderAuth auth;
      const auto clef_desc = auth.descriptor("clef");
      check(string_field(clef_desc, "protocol") == "decision" &&
                string_field(clef_desc, "base_url") == "http://127.0.0.1:11435/v1" &&
                string_field(clef_desc, "environment") == "CLEF_API_KEY",
            "built-in clef descriptor mismatch");
      bool catalog_has_clef = false;
      for (const auto &entry : field(auth.catalog(), "providers").array())
        if (string_field(entry, "id") == "clef")
          catalog_has_clef = true;
      check(catalog_has_clef, "built-in clef missing from catalog");

      auto non_decision = q;
      set(non_decision, "provider", Value{"openai"});
      rejects([&] { (void)decision_request(non_decision); }, ErrorCode::unsupported);

      auto clef_req = q;
      set(clef_req, "provider", Value{"clef"});
      const auto clef_default_wire = decision_request(clef_req);
      check(string_field(clef_default_wire, "model") == "clef-latest",
            "clef default model not clef-latest");
      validate_decision_response(clef_default_wire, parse(response("clef-8b-v1")),
                                 "clef");

      set(clef_req, "model", Value{"clef-8b-v1"});
      const auto clef_pinned_wire = decision_request(clef_req);
      validate_decision_response(clef_pinned_wire, parse(response("clef-8b-v1")),
                                 "clef");
      rejects(
          [&] {
            validate_decision_response(clef_pinned_wire, parse(response("clef-8b-v2")),
                                       "clef");
          },
          ErrorCode::corrupt);

      write_file(base / "mode", "clef");
      DecisionModelConfig local_cfg;
      local_cfg.curl_executable = config.curl_executable;
      local_cfg.response_limit = 8192;
      DecisionModels local_adapter{local_cfg};
      const auto clef_out = local_adapter.evaluate(clef_req);
      check(string_field(clef_out, "status") == "ok" &&
                string_field(clef_out, "provider") == "clef" &&
                string_field(clef_out, "requested_model") == "clef-8b-v1" &&
                field(clef_out, "response") == parse(response("clef-8b-v1")),
            "clef loopback evaluation failed");
      const auto clef_argv = read_file(base / "argv");
      check(clef_argv.find("\"=http\"") != std::string::npos &&
                clef_argv.find("\"=https\"") == std::string::npos,
            "clef loopback did not enforce --proto =http");

      // Tailscale CGNAT (100.64.0.0/10) allows plain HTTP.
      (void)setenv("BLACKBIRD_CLEF_URL", "http://100.64.12.34:11435/v1", 1);
      write_file(base / "mode", "tailscale_clef");
      const auto ts_out = local_adapter.evaluate(clef_req);
      check(string_field(ts_out, "status") == "ok", "Tailscale CGNAT HTTP failed");
      check(read_file(base / "argv").find("\"=http\"") != std::string::npos,
            "Tailscale CGNAT did not use --proto =http");

      // Plain HTTP to non-local remote hosts must reject before dispatch.
      const auto argv_before_remote = read_file(base / "argv");
      for (const char *bad_url :
           {"http://example.com/v1/systemone", "http://100.128.0.1:11435/v1",
            "http://100.63.255.255:11435/v1", "http://localhost.evil.com/v1"}) {
        (void)setenv("BLACKBIRD_CLEF_URL", bad_url, 1);
        rejects([&] { (void)local_adapter.evaluate(clef_req); },
                ErrorCode::unsupported);
        check(read_file(base / "argv") == argv_before_remote,
              "rejected remote plain HTTP dispatched curl");
      }
      (void)unsetenv("BLACKBIRD_CLEF_URL");

      // Custom registered protocol=decision provider with stored key over HTTPS.
      auth.add_provider("oracle", "https://decision.example.test/v1", "decision",
                        "ORACLE_DECISION_KEY");
      auth.set_key("oracle", "default", "custom-decision-secret");
      (void)unsetenv("ORACLE_DECISION_KEY");
      auto custom_req = q;
      set(custom_req, "provider", Value{"oracle"});
      rejects([&] { (void)decision_request(custom_req); }, ErrorCode::invalid_range);
      set(custom_req, "model", Value{"oracle-v2"});
      write_file(base / "mode", "custom_decision");
      const auto custom_out = local_adapter.evaluate(custom_req);
      check(string_field(custom_out, "status") == "ok" &&
                string_field(custom_out, "provider") == "oracle" &&
                string_field(custom_out, "requested_model") == "oracle-v2" &&
                field(custom_out, "response") == parse(response("oracle-v2")),
            "custom decision provider evaluation failed");
      check(read_file(base / "argv").find("\"=https\"") != std::string::npos,
            "custom HTTPS provider did not enforce --proto =https");

      // Blind-sealed decision trial verification.
      const auto seal = decision_blind_seal(clef_pinned_wire, clef_out);
      const auto first_pass =
          parse(R"({"decision":"compiler","confidence":"high","notes":"independent"})");
      const auto verified = decision_blind_verify(seal, clef_pinned_wire, first_pass);
      check(verified.has_value(), "intact blind seal failed verification");
      check(std::get<bool>(field(verified.value(), "verified").value()) &&
                field(verified.value(), "first_pass") == first_pass &&
                field(verified.value(), "result") == clef_out &&
                string_field(verified.value(), "seal_sha256") ==
                    string_field(seal, "seal_sha256"),
            "blind verify payload mismatch");

      // Canonical key ordering: logically identical request with reordered keys
      // verifies.
      const auto reordered =
          Value::object({{"questions", field(clef_pinned_wire, "questions")},
                         {"state", field(clef_pinned_wire, "state")},
                         {"model", field(clef_pinned_wire, "model")}});
      check(decision_blind_verify(seal, reordered, first_pass).has_value(),
            "canonical JSON key reordering broke blind verification");

      // Tampered request must fail verification.
      auto tampered_req = clef_pinned_wire;
      set(tampered_req, "state", Value{"tampered state"});
      const auto bad_req = decision_blind_verify(seal, tampered_req, first_pass);
      check(!bad_req.has_value() && bad_req.error().code == ErrorCode::corrupt,
            "tampered request passed blind verification");

      // Tampered sealed result must fail verification.
      auto tampered_seal_result = seal;
      auto altered_result = clef_out;
      set(altered_result, "provider", Value{"tampered"});
      set(tampered_seal_result, "result", altered_result);
      const auto bad_res =
          decision_blind_verify(tampered_seal_result, clef_pinned_wire, first_pass);
      check(!bad_res.has_value() && bad_res.error().code == ErrorCode::corrupt,
            "tampered sealed result passed blind verification");

      // Tampered seal hash must fail verification.
      auto tampered_seal_hash = seal;
      set(tampered_seal_hash, "seal_sha256", Value{"sha256:" + std::string(64, '0')});
      const auto bad_hash =
          decision_blind_verify(tampered_seal_hash, clef_pinned_wire, first_pass);
      check(!bad_hash.has_value() && bad_hash.error().code == ErrorCode::corrupt,
            "tampered seal digest passed blind verification");

      (void)unsetenv("BLACKBIRD_AUTH_HOME");
    }

    std::filesystem::remove_all(base);
    std::cout << "decision models passed\n";
    return 0;
  } catch (const Error &e) {
    std::cerr << error_name(e.code) << ' ' << e.detail << '\n';
    return 1;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
