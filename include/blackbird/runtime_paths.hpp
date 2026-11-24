#pragma once
#include <filesystem>

namespace blackbird {
// Packaged defaults belong to the executable, never cwd or a developer checkout.
// Explicit caller-selected workflow/asset overrides remain outside this resolver.
struct RuntimePath {
  std::filesystem::path relative;
  std::filesystem::path development;
};
const std::filesystem::path &runtime_executable();
std::filesystem::path runtime_resource(const RuntimePath &path);
std::filesystem::path runtime_helper(const RuntimePath &path);
} // namespace blackbird
