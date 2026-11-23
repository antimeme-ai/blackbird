#pragma once

#include "blackbird/foundation.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird::sandbox {

enum class SandboxError : std::int64_t {
  none = 0,
  invalid_spec = 3000,
  invalid_path = 3001,
  control_char_in_path = 3002,
  canonicalize_failed = 3003,
  unsupported_platform = 3004,
  backend_unavailable = 3005,
  seatbelt_init_failed = 3006,
  no_new_privs_failed = 3007,
  landlock_unavailable = 3008,
  landlock_ruleset_failed = 3009,
  landlock_rule_failed = 3010,
  landlock_restrict_failed = 3011,
  seccomp_arch_unsupported = 3012,
  seccomp_install_failed = 3013,
  fork_failed = 3014,
  pipe_failed = 3015,
  waitpid_failed = 3016,
  empty_argv = 3017,
};

constexpr SandboxError sandbox_error_of(const Error &error) noexcept {
  return static_cast<SandboxError>(error.detail);
}

std::string_view sandbox_error_name(SandboxError detail) noexcept;

enum class SandboxProfile : std::uint8_t {
  none = 0,      // black-flag: zero sandbox overhead
  guarded = 1,   // RW workspace+tmp, RO system+safe home, deny secret stores
  sandboxed = 2, // strict allow-list, no home browse, deny outbound network
  airgap = 3,    // strict allow-list + zero network (TCP/UDP/DNS/raw)
};

std::string_view sandbox_profile_name(SandboxProfile profile) noexcept;
std::optional<SandboxProfile> parse_sandbox_profile(std::string_view text) noexcept;

struct SandboxSpec {
  SandboxProfile profile = SandboxProfile::none;
  std::filesystem::path workspace_root;
  std::filesystem::path tmp_dir;
  std::filesystem::path home_dir;
  std::vector<std::filesystem::path> denied_paths;
  std::vector<std::filesystem::path> extra_read_paths;
  bool deny_workspace_dotenv = true;
  bool include_default_denied_paths = true;
};

struct SandboxCapabilities {
  std::string platform;
  bool available = false;
  std::string backend_name;
  int landlock_abi_version = 0;
  bool supports_network_airgap = false;
  std::vector<std::string> caveats;

  bool operator==(const SandboxCapabilities &) const = default;
};

struct SandboxProbeResult {
  int exit_code = -1;
  int term_signal = 0;
  bool sandbox_apply_failed = false;
  SandboxError sandbox_error = SandboxError::none;
  std::string output;
};

// Probes kernel containment primitives available on the running host.
SandboxCapabilities probe_os_sandbox_capabilities();

// Returns the standard secret-store paths under home_dir and Blackbird env overrides.
std::vector<std::filesystem::path>
default_denied_paths(const std::filesystem::path &home_dir);

// Escapes a string literal for macOS SBPL, rejecting NUL and ASCII control characters.
Result<std::string> escape_sbpl_string(std::string_view input);

// Builds a strict macOS Seatbelt SBPL profile for spec (callable on any OS for
// testing).
Result<std::string> build_macos_seatbelt_profile(const SandboxSpec &spec);

// Applies kernel containment irrevocably to the current process (called right before
// execvp in a child process). Fails closed on any error; never silently runs
// unsandboxed.
Result<void> apply_os_sandbox_to_current_process(const SandboxSpec &spec);

// Forks a child, applies spec via apply_os_sandbox_to_current_process, execvp's argv,
// and captures exit status + combined stdout/stderr output.
Result<SandboxProbeResult> run_sandboxed_child_probe(
    const SandboxSpec &spec, const std::vector<std::string> &argv,
    const std::optional<std::filesystem::path> &cwd = std::nullopt);

} // namespace blackbird::sandbox
