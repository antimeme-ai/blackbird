#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/value.hpp"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

inline constexpr std::size_t kCapabilityMaxIdLength = 64;
inline constexpr std::size_t kCapabilityMaxParamNameLength = 64;
inline constexpr std::size_t kCapabilityMaxBodyBytes = 64 * 1024;
inline constexpr std::size_t kCapabilityMaxRenderedBytes = 256 * 1024;
inline constexpr std::size_t kCapabilityMaxFieldBytes = 4096;
inline constexpr std::size_t kCapabilityMaxParams = 64;
inline constexpr std::size_t kCapabilityMaxEnumValues = 64;
inline constexpr std::size_t kCapabilityMaxFileBytes = 256 * 1024;
inline constexpr std::size_t kCapabilityDefaultListLimit = 16;
inline constexpr std::size_t kCapabilityMaxListLimit = 64;

enum class CapabilityKind : std::uint8_t {
  skill,
  prompt_template,
  lua_recipe,
  api_recipe,
};

enum class CapabilityScope : std::uint8_t {
  project,
  user,
  builtin,
};

enum class CapabilityParamType : std::uint8_t {
  string,
  integer,
  boolean,
  enumeration,
};

std::string_view capability_kind_name(CapabilityKind kind) noexcept;
Result<CapabilityKind> parse_capability_kind(std::string_view name) noexcept;

std::string_view capability_scope_name(CapabilityScope scope) noexcept;
Result<CapabilityScope> parse_capability_scope(std::string_view name) noexcept;

std::string_view capability_param_type_name(CapabilityParamType type) noexcept;
Result<CapabilityParamType> parse_capability_param_type(std::string_view name) noexcept;

// Valid identifier: [a-z0-9_-], length 1..64, no leading '-'.
bool valid_capability_id(std::string_view id) noexcept;
bool valid_capability_param_name(std::string_view name) noexcept;

struct CapabilityParam {
  std::string name;
  CapabilityParamType type = CapabilityParamType::string;
  bool required = false;
  std::optional<std::string> default_value;
  std::vector<std::string> allowed_values;
  std::string description;
  bool operator==(const CapabilityParam &) const = default;
};

struct CapabilityShadowed {
  CapabilityScope scope = CapabilityScope::user;
  std::filesystem::path source_path;
  std::string sha256;
  bool operator==(const CapabilityShadowed &) const = default;
};

struct CapabilityDefinition {
  std::string id;
  CapabilityKind kind = CapabilityKind::skill;
  std::string title;
  std::string description;
  CapabilityScope scope = CapabilityScope::project;
  std::filesystem::path source_path;
  std::string sha256;
  std::string body;
  std::vector<CapabilityParam> params;
  bool read_only = false;
  std::vector<CapabilityShadowed> shadowed;
  bool operator==(const CapabilityDefinition &) const = default;
};

struct CapabilityResolved {
  std::string id;
  CapabilityKind kind = CapabilityKind::skill;
  CapabilityScope scope = CapabilityScope::project;
  std::string sha256;
  std::map<std::string, std::string> bound_params;
  std::string rendered_text;
  // Invariant: resolving a capability definition NEVER executes it.
  bool executed = false;
  bool operator==(const CapabilityResolved &) const = default;
};

struct CapabilityListQuery {
  std::optional<CapabilityKind> kind;
  std::optional<CapabilityScope> scope;
  std::string text;
  std::size_t offset = 0;
  std::size_t limit = kCapabilityDefaultListLimit;
  // When true and live disk refresh fails, return the last-good catalog page
  // marked stale=true with last_error populated instead of failing outright.
  bool allow_stale_on_error = false;
};

struct CapabilityListPage {
  std::size_t total = 0;
  std::size_t offset = 0;
  std::size_t limit = kCapabilityDefaultListLimit;
  bool has_more = false;
  bool stale = false;
  std::optional<Error> last_error;
  std::vector<CapabilityDefinition> items;
  bool operator==(const CapabilityListPage &) const = default;
};

struct CapabilityCatalogConfig {
  std::optional<std::filesystem::path> project_dir;
  std::optional<std::filesystem::path> user_dir;
  std::vector<CapabilityDefinition> builtins;
};

// Computes lowercase 64-char hex FIPS 180-4 SHA-256 of arbitrary bytes.
std::string capability_sha256_hex(std::string_view bytes);

// Computes deterministic canonical SHA-256 over a definition's semantic fields
// (id, kind, title, description, body, params).
std::string compute_capability_sha256(const CapabilityDefinition &definition);

// Default scope directory helpers.
std::filesystem::path
default_project_skills_dir(const std::filesystem::path &project_root);
std::optional<std::filesystem::path> default_user_skills_dir();

// Native Value and JSON interchange helpers for CLI, model tools, Lua and TUI.
Value to_value(const CapabilityParam &param);
Value to_value(const CapabilityShadowed &shadowed);
Value to_value(const CapabilityDefinition &definition);
Value to_value(const CapabilityResolved &resolved);
Value to_value(const CapabilityListPage &page);

Result<std::string> to_json(const CapabilityParam &param);
Result<std::string> to_json(const CapabilityDefinition &definition);
Result<std::string> to_json(const CapabilityResolved &resolved);
Result<std::string> to_json(const CapabilityListPage &page);

// Qualified catalog of reusable Skills, Prompt Templates, Lua Recipes and
// API Recipes stored as <id>.json under configured scope directories with
// deterministic precedence (project > user > builtin) and full provenance.
//
// Invariants:
// - Saving validates and writes atomically; it NEVER executes code or tools.
// - Resolving validates typed parameters, checks optional expected_sha256 for
//   stale-form protection, performs single-pass non-recursive {{param}}
//   substitution, and NEVER executes code or tools (executed is always false).
// - Path containment strictly rejects '..', '/', symlinks (O_NOFOLLOW),
//   foreign-owned or group/world-writable directories and files.
class CapabilityCatalog {
public:
  static Result<CapabilityCatalog> open(CapabilityCatalogConfig config);

  const std::optional<std::filesystem::path> &project_dir() const noexcept {
    return project_dir_;
  }
  const std::optional<std::filesystem::path> &user_dir() const noexcept {
    return user_dir_;
  }

  // Reloads all scopes into the internal last-good snapshot.
  Result<void> refresh();

  // Bounded paged listing with optional category/scope/text filters.
  Result<CapabilityListPage> list(const CapabilityListQuery &query = {});

  // Looks up the effective definition for id (project > user > builtin),
  // retaining shadowed provenance from lower-precedence scopes.
  Result<std::optional<CapabilityDefinition>> get(std::string_view id) const;

  // Saves a definition atomically to the requested writable scope
  // (project or user). Never executes any recipe, Lua or tool code.
  Result<CapabilityDefinition> save(CapabilityScope scope,
                                    const CapabilityDefinition &definition);

  // Removes a writable definition from the requested scope (project or user).
  Result<void> remove(CapabilityScope scope, std::string_view id);

  // Validates arguments against the current definition, verifies optional
  // expected_sha256 (failing with ErrorCode::conflict on mismatch), and
  // performs deterministic single-pass {{param}} expansion without executing.
  Result<CapabilityResolved>
  resolve(std::string_view id, const std::map<std::string, std::string> &args,
          std::optional<std::string_view> expected_sha256 = std::nullopt) const;

private:
  CapabilityCatalog(std::optional<std::filesystem::path> project_dir,
                    std::optional<std::filesystem::path> user_dir,
                    std::map<std::string, CapabilityDefinition> builtins)
      : project_dir_(std::move(project_dir)), user_dir_(std::move(user_dir)),
        builtins_(std::move(builtins)) {}

  Result<std::map<std::string, CapabilityDefinition>> load_all_scopes() const;
  Result<CapabilityListPage>
  paginate_map(const std::map<std::string, CapabilityDefinition> &source,
               const CapabilityListQuery &query, bool stale,
               std::optional<Error> last_error) const;

  std::optional<std::filesystem::path> project_dir_;
  std::optional<std::filesystem::path> user_dir_;
  std::map<std::string, CapabilityDefinition> builtins_;
  std::map<std::string, CapabilityDefinition> last_good_;
  bool has_last_good_ = false;
};

} // namespace blackbird
