#include "blackbird/capabilities.hpp"
#include "blackbird/json.hpp"

#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

template <class T> T must_opt(std::optional<T> opt, const char *context) {
  if (!opt.has_value())
    throw std::runtime_error(std::string{context} + ": missing optional value");
  return std::move(*opt);
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
}

struct TempDir {
  std::filesystem::path path;
  TempDir() {
    std::string tmpl =
        (std::filesystem::temp_directory_path() / "blackbird-capabilities-test-XXXXXX")
            .string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    char *created = ::mkdtemp(buf.data());
    if (created == nullptr)
      throw std::runtime_error("mkdtemp failed");
    path = std::filesystem::path{created};
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
};

CapabilityDefinition make_sample_skill(std::string id, std::string body) {
  CapabilityDefinition def{};
  def.id = std::move(id);
  def.kind = CapabilityKind::skill;
  def.title = "Sample Skill";
  def.description = "Reusable diagnostic review skill";
  def.body = std::move(body);
  return def;
}

void test_sha256_vectors() {
  g_stage = "sha256_vectors";
  // FIPS 180-4 test vectors.
  check(capability_sha256_hex("") ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256('') mismatch");
  check(capability_sha256_hex("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256('abc') mismatch");
  check(capability_sha256_hex(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha256(448-bit) mismatch");
  const std::string exact64(64, 'a');
  check(capability_sha256_hex(exact64) ==
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        "sha256(64*'a') mismatch");
}

void test_id_and_enum_validation() {
  g_stage = "id_and_enum_validation";
  check(valid_capability_id("release-lookup_1"), "valid id rejected");
  check(valid_capability_id("a"), "single char id rejected");
  check(valid_capability_id("0_skill-9"), "leading digit id rejected");
  check(valid_capability_id(std::string(64, 'a')), "64-char id rejected");
  check(!valid_capability_id(""), "empty id accepted");
  check(!valid_capability_id(std::string(65, 'a')), "65-char id accepted");
  check(!valid_capability_id("-leading-dash"), "leading dash accepted");
  check(!valid_capability_id("../escape"), "path traversal id accepted");
  check(!valid_capability_id("a/b"), "slash id accepted");
  check(!valid_capability_id("a\\b"), "backslash id accepted");
  check(!valid_capability_id("Upper"), "uppercase id accepted");
  check(!valid_capability_id("has.dot"), "dot id accepted");
  check(!valid_capability_id("has space"), "space id accepted");

  check(must(parse_capability_kind("skill"), "parse skill") == CapabilityKind::skill,
        "kind skill mismatch");
  check(must(parse_capability_kind("prompt_template"), "parse prompt_template") ==
            CapabilityKind::prompt_template,
        "kind prompt_template mismatch");
  check(must(parse_capability_kind("lua_recipe"), "parse lua_recipe") ==
            CapabilityKind::lua_recipe,
        "kind lua_recipe mismatch");
  check(must(parse_capability_kind("api_recipe"), "parse api_recipe") ==
            CapabilityKind::api_recipe,
        "kind api_recipe mismatch");
  check(!parse_capability_kind("unknown").has_value(), "unknown kind accepted");

  check(must(parse_capability_param_type("enum"), "parse enum") ==
            CapabilityParamType::enumeration,
        "param enum mismatch");
  check(capability_param_type_name(CapabilityParamType::enumeration) == "enum",
        "param enum name mismatch");
}

void test_save_load_precedence_and_delete(const std::filesystem::path &base) {
  g_stage = "save_load_precedence_and_delete";
  const auto project_dir = default_project_skills_dir(base / "repo");
  const auto user_dir = base / "user-config" / "blackbird" / "skills";

  CapabilityDefinition builtin_def =
      make_sample_skill("review-patch", "Builtin review {{target}}");
  builtin_def.params.push_back(CapabilityParam{
      "target",
      CapabilityParamType::string,
      true,
      std::nullopt,
      {},
      "Target file",
  });

  CapabilityCatalogConfig cfg{};
  cfg.project_dir = project_dir;
  cfg.user_dir = user_dir;
  cfg.builtins.push_back(builtin_def);

  auto catalog = must(CapabilityCatalog::open(cfg), "open catalog");

  // Builtin is immediately visible, read_only, with no shadowed entries.
  auto initial =
      must_opt(must(catalog.get("review-patch"), "get builtin"), "builtin missing");
  check(initial.scope == CapabilityScope::builtin, "expected builtin scope");
  check(initial.read_only, "builtin must be read_only");
  check(initial.shadowed.empty(), "builtin should not shadow anything");

  // Saving to builtin scope is refused.
  auto builtin_save = catalog.save(CapabilityScope::builtin, builtin_def);
  check(!builtin_save.has_value() &&
            builtin_save.error().code == ErrorCode::unsupported,
        "saving to builtin scope must fail with unsupported");

  // Save user override of review-patch.
  CapabilityDefinition user_def =
      make_sample_skill("review-patch", "User review {{target}}");
  user_def.params = builtin_def.params;
  auto saved_user = must(catalog.save(CapabilityScope::user, user_def), "save user");
  check(saved_user.scope == CapabilityScope::user, "saved user scope mismatch");
  check(saved_user.source_path == user_dir / "review-patch.json",
        "saved user source_path mismatch");
  check(saved_user.sha256.size() == 64, "saved user sha256 length mismatch");

  // Verify saved file permissions are 0600 and directory is 0700.
  struct stat st{};
  check(::lstat(saved_user.source_path.c_str(), &st) == 0, "lstat saved file failed");
  check(S_ISREG(st.st_mode), "saved file is not regular");
  check((st.st_mode & 0777) == 0600, "saved file mode must be 0600");
  check(::lstat(user_dir.c_str(), &st) == 0, "lstat user dir failed");
  check((st.st_mode & 0777) == 0700, "created skills dir mode must be 0700");

  // User overrides builtin and retains builtin provenance in shadowed.
  auto after_user = must_opt(must(catalog.get("review-patch"), "get after user"),
                             "missing after user");
  check(after_user.scope == CapabilityScope::user, "user should override builtin");
  check(after_user.shadowed.size() == 1, "expected 1 shadowed entry (builtin)");
  check(after_user.shadowed[0].scope == CapabilityScope::builtin,
        "shadowed entry should be builtin");
  check(after_user.shadowed[0].sha256 == initial.sha256,
        "shadowed builtin sha mismatch");

  // Save project override of review-patch.
  CapabilityDefinition project_def =
      make_sample_skill("review-patch", "Project review {{target}}");
  project_def.params = builtin_def.params;
  auto saved_proj =
      must(catalog.save(CapabilityScope::project, project_def), "save project");
  check(saved_proj.scope == CapabilityScope::project, "saved project scope mismatch");

  auto after_proj = must_opt(must(catalog.get("review-patch"), "get after project"),
                             "missing after project");
  check(after_proj.scope == CapabilityScope::project, "project must override user");
  check(after_proj.body == "Project review {{target}}", "project body mismatch");
  check(after_proj.shadowed.size() == 2, "expected 2 shadowed entries (user, builtin)");
  check(after_proj.shadowed[0].scope == CapabilityScope::user,
        "first shadowed entry must be user");
  check(after_proj.shadowed[0].source_path == saved_user.source_path,
        "shadowed user source_path mismatch");
  check(after_proj.shadowed[0].sha256 == saved_user.sha256,
        "shadowed user sha256 mismatch");
  check(after_proj.shadowed[1].scope == CapabilityScope::builtin,
        "second shadowed entry must be builtin");

  // Delete project override: user becomes effective again.
  must_void(catalog.remove(CapabilityScope::project, "review-patch"),
            "remove project override");
  auto after_del = must_opt(must(catalog.get("review-patch"), "get after delete"),
                            "missing after delete");
  check(after_del.scope == CapabilityScope::user,
        "user should resurface after project delete");
  check(after_del.shadowed.size() == 1, "expected 1 shadowed entry after delete");

  // Deleting non-existent project entry fails cleanly.
  auto missing_del = catalog.remove(CapabilityScope::project, "review-patch");
  check(!missing_del.has_value() &&
            missing_del.error().code == ErrorCode::invalid_identity,
        "removing missing entry should fail with invalid_identity");

  // Saving read_only definition prevents overwriting or deleting it.
  CapabilityDefinition ro_def = make_sample_skill("locked-recipe", "GET /health");
  ro_def.kind = CapabilityKind::api_recipe;
  ro_def.read_only = true;
  (void)must(catalog.save(CapabilityScope::project, ro_def), "save read_only");
  auto overwrite_ro = catalog.save(CapabilityScope::project, ro_def);
  check(!overwrite_ro.has_value() && overwrite_ro.error().code == ErrorCode::conflict,
        "overwriting read_only definition must fail with conflict");
  auto remove_ro = catalog.remove(CapabilityScope::project, "locked-recipe");
  check(!remove_ro.has_value() && remove_ro.error().code == ErrorCode::conflict,
        "removing read_only definition must fail with conflict");
}

void test_path_containment_and_symlinks(const std::filesystem::path &base) {
  g_stage = "path_containment_and_symlinks";
  const auto good_dir = base / "safe-skills";
  const auto escape_target = base / "secret.json";
  {
    std::ofstream out(escape_target);
    out << R"({"id":"escape","kind":"skill","body":"secret"})";
  }

  // Reject '..' in configured directory path.
  CapabilityCatalogConfig traversal_cfg{};
  traversal_cfg.project_dir = good_dir / ".." / "outside";
  auto bad_open = CapabilityCatalog::open(traversal_cfg);
  check(!bad_open.has_value() && bad_open.error().code == ErrorCode::invalid_range,
        "'..' in config dir must be rejected");

  // Reject symlinked scope directory.
  check(::mkdir(good_dir.c_str(), mode_t{0700}) == 0, "mkdir good_dir failed");
  const auto link_dir = base / "symlink-skills";
  check(::symlink(good_dir.c_str(), link_dir.c_str()) == 0, "symlink scope dir failed");
  CapabilityCatalogConfig link_cfg{};
  link_cfg.project_dir = link_dir;
  auto link_open = CapabilityCatalog::open(link_cfg);
  check(!link_open.has_value() && link_open.error().code == ErrorCode::io,
        "symlink scope dir must be rejected");

  // Reject world/group-writable scope directory.
  const auto writable_dir = base / "world-writable-skills";
  check(::mkdir(writable_dir.c_str(), mode_t{0700}) == 0, "mkdir writable failed");
  check(::chmod(writable_dir.c_str(), mode_t{0777}) == 0, "chmod 0777 failed");
  CapabilityCatalogConfig writable_cfg{};
  writable_cfg.project_dir = writable_dir;
  auto writable_open = CapabilityCatalog::open(writable_cfg);
  check(!writable_open.has_value() && writable_open.error().code == ErrorCode::io,
        "world-writable dir must be rejected");

  // Open valid catalog and save a good skill so last_good_ is populated.
  CapabilityCatalogConfig ok_cfg{};
  ok_cfg.project_dir = good_dir;
  auto catalog = must(CapabilityCatalog::open(ok_cfg), "open good_dir");
  (void)must(
      catalog.save(CapabilityScope::project, make_sample_skill("good-one", "Hello")),
      "save good-one");

  // Reject invalid IDs on save/get/remove/resolve.
  auto bad_save =
      catalog.save(CapabilityScope::project, make_sample_skill("../escape", "Nope"));
  check(!bad_save.has_value() && bad_save.error().code == ErrorCode::invalid_identity,
        "path traversal id on save must fail");
  auto bad_get = catalog.get("../escape");
  check(!bad_get.has_value() && bad_get.error().code == ErrorCode::invalid_identity,
        "path traversal id on get must fail");
  auto bad_resolve = catalog.resolve("a/b", {});
  check(!bad_resolve.has_value() &&
            bad_resolve.error().code == ErrorCode::invalid_identity,
        "slash id on resolve must fail");

  // Plant a symlink file inside the skills directory.
  const auto sym_file = good_dir / "escape.json";
  check(::symlink(escape_target.c_str(), sym_file.c_str()) == 0, "symlink file failed");

  // Direct get, save-over, remove, and strict list must all reject the symlink!
  auto get_sym = catalog.get("escape");
  check(!get_sym.has_value() && get_sym.error().code == ErrorCode::io,
        "symlink file on get must fail");
  auto save_sym =
      catalog.save(CapabilityScope::project, make_sample_skill("escape", "overwrite"));
  check(!save_sym.has_value() && save_sym.error().code == ErrorCode::io,
        "saving over symlink must fail");
  auto rm_sym = catalog.remove(CapabilityScope::project, "escape");
  check(!rm_sym.has_value() && rm_sym.error().code == ErrorCode::io,
        "removing symlink must fail");
  auto strict_list = catalog.list();
  check(!strict_list.has_value() && strict_list.error().code == ErrorCode::io,
        "strict list must fail on planted symlink");

  // Stale last-good fallback returns previously known good catalog marked stale!
  CapabilityListQuery stale_query{};
  stale_query.allow_stale_on_error = true;
  auto stale_page = must(catalog.list(stale_query), "stale list fallback");
  check(stale_page.stale, "fallback page must be marked stale");
  check(stale_page.last_error.has_value() &&
            stale_page.last_error->code == ErrorCode::io,
        "fallback page must report last_error");
  check(stale_page.total == 1 && stale_page.items.size() == 1 &&
            stale_page.items[0].id == "good-one",
        "fallback page must preserve last-good items");

  // Removing the bad symlink restores healthy live listing.
  check(::unlink(sym_file.c_str()) == 0, "unlink symlink failed");
  auto recovered = must(catalog.list(), "recovered list");
  check(!recovered.stale && recovered.total == 1, "recovered list should not be stale");
}

void test_typed_params_and_non_recursive_expansion(const std::filesystem::path &base) {
  g_stage = "typed_params_and_non_recursive_expansion";
  CapabilityCatalogConfig cfg{};
  cfg.project_dir = base / "params-skills";
  auto catalog = must(CapabilityCatalog::open(cfg), "open params catalog");

  CapabilityDefinition recipe{};
  recipe.id = "release-lookup";
  recipe.kind = CapabilityKind::api_recipe;
  recipe.title = "Release Lookup";
  recipe.description = "Fetch release metadata for a repo";
  recipe.body = "GET /repos/{{owner}}/{{repo}}/releases?limit={{limit}}&draft={{draft}}"
                "&format={{format}}&note={{note}} lua={{1,2}}";
  recipe.params = {
      CapabilityParam{
          "owner", CapabilityParamType::string, true, std::nullopt, {}, "Org or user"},
      CapabilityParam{
          "repo", CapabilityParamType::string, true, std::nullopt, {}, "Repository"},
      CapabilityParam{"limit",
                      CapabilityParamType::integer,
                      false,
                      std::optional<std::string>{"10"},
                      {},
                      "Max releases"},
      CapabilityParam{"draft",
                      CapabilityParamType::boolean,
                      false,
                      std::optional<std::string>{"false"},
                      {},
                      "Include drafts"},
      CapabilityParam{"format",
                      CapabilityParamType::enumeration,
                      false,
                      std::optional<std::string>{"json"},
                      {"json", "summary", "raw"},
                      "Output format"},
      CapabilityParam{"note",
                      CapabilityParamType::string,
                      false,
                      std::nullopt,
                      {},
                      "Optional note"},
  };

  auto saved = must(catalog.save(CapabilityScope::project, recipe), "save recipe");

  // Happy path with defaults applied and optional empty omitted.
  auto ok =
      must(catalog.resolve("release-lookup", {{"owner", "acme"}, {"repo", "blackbird"}},
                           saved.sha256),
           "resolve defaults");
  check(!ok.executed, "resolve must NEVER set executed=true");
  check(ok.sha256 == saved.sha256, "resolved sha256 mismatch");
  check(ok.bound_params.at("limit") == "10", "default integer not applied");
  check(ok.bound_params.at("draft") == "false", "default boolean not applied");
  check(ok.bound_params.at("format") == "json", "default enum not applied");
  check(ok.bound_params.find("note") == ok.bound_params.end(),
        "unset optional param should not appear in bound_params");
  check(ok.rendered_text ==
            "GET /repos/acme/blackbird/releases?limit=10&draft=false&format=json"
            "&note= lua={{1,2}}",
        "rendered_text mismatch");

  // Explicit overrides including negative integer and non-recursive {{repo}} injection!
  auto injected = must(catalog.resolve("release-lookup",
                                       {{"owner", "{{repo}}"},
                                        {"repo", "SECRET_REPO"},
                                        {"limit", "-42"},
                                        {"draft", "true"},
                                        {"format", "summary"},
                                        {"note", "literal {{owner}}"}},
                                       saved.sha256),
                       "resolve injection safety");
  check(!injected.executed, "injected resolve executed must be false");
  check(injected.rendered_text ==
            "GET /repos/{{repo}}/SECRET_REPO/releases?limit=-42&draft=true"
            "&format=summary&note=literal {{owner}} lua={{1,2}}",
        "non-recursive template substitution violated!");

  // Missing required parameter.
  auto missing_req = catalog.resolve("release-lookup", {{"owner", "acme"}});
  check(!missing_req.has_value() &&
            missing_req.error().code == ErrorCode::invalid_range,
        "missing required param must fail");

  // Bad integer values.
  for (const char *bad_int :
       {"abc", "12.3", "+5", " 5", "5 ", "999999999999999999999"}) {
    auto res = catalog.resolve("release-lookup",
                               {{"owner", "a"}, {"repo", "b"}, {"limit", bad_int}});
    check(!res.has_value() && res.error().code == ErrorCode::invalid_range,
          "bad integer must fail");
  }

  // Bad boolean values.
  for (const char *bad_bool : {"TRUE", "1", "yes", "false "}) {
    auto res = catalog.resolve("release-lookup",
                               {{"owner", "a"}, {"repo", "b"}, {"draft", bad_bool}});
    check(!res.has_value() && res.error().code == ErrorCode::invalid_range,
          "bad boolean must fail");
  }

  // Out-of-enum value.
  auto bad_enum = catalog.resolve("release-lookup",
                                  {{"owner", "a"}, {"repo", "b"}, {"format", "yaml"}});
  check(!bad_enum.has_value() && bad_enum.error().code == ErrorCode::invalid_range,
        "out-of-enum value must fail");

  // Unknown extra argument.
  auto extra_arg = catalog.resolve("release-lookup",
                                   {{"owner", "a"}, {"repo", "b"}, {"evil", "inject"}});
  check(!extra_arg.has_value() && extra_arg.error().code == ErrorCode::invalid_range,
        "unknown extra arg must fail");

  // Invalid definition at save time: default doesn't match type / enum / body > 64 KiB.
  CapabilityDefinition bad_def = recipe;
  bad_def.id = "bad-default";
  bad_def.params[2].default_value = "not-an-int";
  auto bad_save_int = catalog.save(CapabilityScope::project, bad_def);
  check(!bad_save_int.has_value() &&
            bad_save_int.error().code == ErrorCode::invalid_range,
        "invalid integer default must be rejected on save");

  CapabilityDefinition huge_def =
      make_sample_skill("too-big", std::string(kCapabilityMaxBodyBytes + 1, 'x'));
  auto bad_save_huge = catalog.save(CapabilityScope::project, huge_def);
  check(!bad_save_huge.has_value() &&
            bad_save_huge.error().code == ErrorCode::invalid_range,
        "oversized body (>64 KiB) must be rejected");

  std::string invalid_utf8 = "bad-\xff-utf8";
  auto bad_save_utf8 = catalog.save(CapabilityScope::project,
                                    make_sample_skill("bad-utf8", invalid_utf8));
  check(!bad_save_utf8.has_value() &&
            bad_save_utf8.error().code == ErrorCode::invalid_range,
        "invalid UTF-8 body must be rejected");

  std::string with_nul = std::string{"abc"} + '\0' + "def";
  auto bad_save_nul =
      catalog.save(CapabilityScope::project, make_sample_skill("bad-nul", with_nul));
  check(!bad_save_nul.has_value() &&
            bad_save_nul.error().code == ErrorCode::invalid_range,
        "NUL byte in body must be rejected");
}

void test_stale_form_protection(const std::filesystem::path &base) {
  g_stage = "stale_form_protection";
  const auto project_dir = base / "stale-skills";
  CapabilityCatalogConfig cfg{};
  cfg.project_dir = project_dir;
  auto catalog = must(CapabilityCatalog::open(cfg), "open stale catalog");

  CapabilityDefinition def{};
  def.id = "deploy-check";
  def.kind = CapabilityKind::prompt_template;
  def.title = "Deploy Check";
  def.description = "Check staging rollout";
  def.body = "Inspect {{env}} rollout";
  def.params.push_back(CapabilityParam{"env",
                                       CapabilityParamType::enumeration,
                                       true,
                                       std::nullopt,
                                       {"staging", "prod"},
                                       "Target environment"});

  auto v1 = must(catalog.save(CapabilityScope::project, def), "save v1");

  // Resolving with pinned v1 sha256 succeeds before edit.
  auto resolved_v1 =
      must(catalog.resolve("deploy-check", {{"env", "staging"}}, v1.sha256),
           "resolve with v1 sha256");
  check(resolved_v1.rendered_text == "Inspect staging rollout", "v1 render mismatch");
  check(!resolved_v1.executed, "v1 executed must be false");

  // Simulate external edit directly on disk (changing body/schema).
  const auto file_path = project_dir / "deploy-check.json";
  {
    std::ofstream out(file_path, std::ios::trunc);
    out << R"({
      "version": 1,
      "id": "deploy-check",
      "kind": "prompt_template",
      "title": "Deploy Check",
      "description": "Check staging rollout",
      "body": "CHANGED target {{env}} rollout",
      "params": [
        {
          "name": "env",
          "type": "enum",
          "required": true,
          "default_value": null,
          "allowed_values": ["staging", "prod"],
          "description": "Target environment"
        }
      ],
      "read_only": false
    })";
  }

  // Resolving with the stale v1 expected_sha256 MUST fail with ErrorCode::conflict!
  auto stale_res = catalog.resolve("deploy-check", {{"env", "staging"}}, v1.sha256);
  check(!stale_res.has_value() && stale_res.error().code == ErrorCode::conflict,
        "stale expected_sha256 must fail with ErrorCode::conflict");

  // Fetching current definition yields the new sha256, which resolves cleanly.
  auto v2 = must_opt(must(catalog.get("deploy-check"), "get v2"), "v2 missing");
  check(v2.sha256 != v1.sha256, "v2 sha256 must differ from v1");
  auto resolved_v2 = must(catalog.resolve("deploy-check", {{"env", "prod"}}, v2.sha256),
                          "resolve with v2 sha256");
  check(resolved_v2.rendered_text == "CHANGED target prod rollout",
        "v2 render mismatch");
  check(!resolved_v2.executed, "v2 executed must be false");
}

void test_bounded_pagination_and_json(const std::filesystem::path &base) {
  g_stage = "bounded_pagination_and_json";
  CapabilityCatalogConfig cfg{};
  cfg.project_dir = base / "paged-skills";
  auto catalog = must(CapabilityCatalog::open(cfg), "open paged catalog");

  // Populate 70 capabilities across kinds to exercise default (16) and max (64) bounds.
  for (int i = 0; i < 70; ++i) {
    char id_buf[32];
    std::snprintf(id_buf, sizeof(id_buf), "cap-%02d", i);
    CapabilityDefinition def{};
    def.id = id_buf;
    if (i % 4 == 0)
      def.kind = CapabilityKind::skill;
    else if (i % 4 == 1)
      def.kind = CapabilityKind::prompt_template;
    else if (i % 4 == 2)
      def.kind = CapabilityKind::lua_recipe;
    else
      def.kind = CapabilityKind::api_recipe;
    def.title = (i % 10 == 0) ? "Alpha Special" : "Regular Entry";
    def.description = "Catalog item " + std::to_string(i);
    def.body = "Body " + std::to_string(i);
    (void)must(catalog.save(CapabilityScope::project, def), "save paged item");
  }

  // Default limit is 16.
  auto page1 = must(catalog.list(), "default list");
  check(page1.total == 70, "total should be 70");
  check(page1.limit == 16, "default limit should be 16");
  check(page1.items.size() == 16, "page1 should have 16 items");
  check(page1.has_more, "page1 should have_more");
  check(page1.items.front().id == "cap-00" && page1.items.back().id == "cap-15",
        "page1 sort order mismatch");

  // Limit > 64 is clamped to kCapabilityMaxListLimit (64).
  CapabilityListQuery max_q{};
  max_q.limit = 200;
  auto max_page = must(catalog.list(max_q), "clamped max list");
  check(max_page.limit == 64, "limit must clamp to 64");
  check(max_page.items.size() == 64, "clamped page size must be 64");
  check(max_page.has_more, "64 of 70 should have_more");

  // Tail page.
  CapabilityListQuery tail_q{};
  tail_q.offset = 64;
  tail_q.limit = 16;
  auto tail_page = must(catalog.list(tail_q), "tail list");
  check(tail_page.total == 70, "tail total should be 70");
  check(tail_page.items.size() == 6, "tail should have 6 items");
  check(!tail_page.has_more, "tail should not have_more");
  check(tail_page.items.front().id == "cap-64" && tail_page.items.back().id == "cap-69",
        "tail item range mismatch");

  // Filter by kind + case-insensitive text query.
  CapabilityListQuery filter_q{};
  filter_q.kind = CapabilityKind::skill;
  filter_q.text = "alpha";
  auto filtered = must(catalog.list(filter_q), "filtered list");
  // i % 4 == 0 AND i % 10 == 0 => i in {0, 20, 40, 60} => 4 matches.
  check(filtered.total == 4, "expected 4 filtered items");
  check(filtered.items.size() == 4, "expected 4 returned filtered items");
  check(!filtered.has_more, "filtered should not have_more");

  // Limit == 0 is rejected.
  CapabilityListQuery zero_q{};
  zero_q.limit = 0;
  auto zero_res = catalog.list(zero_q);
  check(!zero_res.has_value() && zero_res.error().code == ErrorCode::invalid_range,
        "limit == 0 must fail");

  // Verify JSON serialization helpers round-trip through parse_json cleanly.
  auto page_json = must(to_json(filtered), "page to_json");
  auto parsed_page = must(parse_json(page_json), "parse page json");
  check(parsed_page.find("total") != nullptr, "page json missing total");
  check(parsed_page.find("has_more") != nullptr, "page json missing has_more");
  check(parsed_page.find("items") != nullptr, "page json missing items");

  auto def_json = must(to_json(filtered.items[0]), "def to_json");
  auto parsed_def = must(parse_json(def_json), "parse def json");
  check(parsed_def.find("sha256") != nullptr, "def json missing sha256");

  auto res_obj = must(catalog.resolve("cap-00", {}), "resolve cap-00");
  auto res_json = must(to_json(res_obj), "resolved to_json");
  auto parsed_res = must(parse_json(res_json), "parse resolved json");
  const Value *executed = parsed_res.find("executed");
  check(executed != nullptr && std::holds_alternative<bool>(executed->value()) &&
            !std::get<bool>(executed->value()),
        "resolved json must carry executed=false");
}

} // namespace

int main() {
  try {
    TempDir tmp;
    test_sha256_vectors();
    test_id_and_enum_validation();
    test_save_load_precedence_and_delete(tmp.path);
    test_path_containment_and_symlinks(tmp.path);
    test_typed_params_and_non_recursive_expansion(tmp.path);
    test_stale_form_protection(tmp.path);
    test_bounded_pagination_and_json(tmp.path);
    std::cout << "PASS capabilities\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL [" << g_stage << "]: " << ex.what() << "\n";
    return 1;
  }
}
