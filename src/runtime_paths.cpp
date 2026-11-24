#include "blackbird/runtime_paths.hpp"
#include "blackbird/foundation.hpp"
#include <cerrno>
#include <string>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#else
#include <unistd.h>
#endif

namespace blackbird {
namespace {
const std::filesystem::path &executable() {
  static const auto path = [] {
#ifdef __APPLE__
    std::uint32_t length = 0;
    (void)::_NSGetExecutablePath(nullptr, &length);
    std::string value(length, '\0');
    if (!length || ::_NSGetExecutablePath(value.data(), &length) != 0)
      throw Error{ErrorCode::io, errno};
    return std::filesystem::canonical(value.c_str());
#else
    std::string value(256, '\0');
    for (;;) {
      const auto size = ::readlink("/proc/self/exe", value.data(), value.size());
      if (size < 0)
        throw Error{ErrorCode::io, errno};
      if (static_cast<std::size_t>(size) < value.size()) {
        value.resize(static_cast<std::size_t>(size));
        return std::filesystem::canonical(value);
      }
      if (value.size() > value.max_size() / 2)
        throw Error{ErrorCode::invalid_range};
      value.resize(value.size() * 2);
    }
#endif
  }();
  return path;
}
bool bundle(const std::filesystem::path &directory) {
  return directory.filename() == "MacOS" &&
         directory.parent_path().filename() == "Contents";
}
bool in_build_tree() {
#ifdef BLACKBIRD_BUILD_DIR
  std::error_code ec;
  const auto build_dir = std::filesystem::weakly_canonical(BLACKBIRD_BUILD_DIR, ec);
  if (ec || build_dir.empty())
    return false;
  const auto exe_dir = executable().parent_path();
  if (exe_dir == build_dir)
    return true;
  const auto rel = exe_dir.lexically_relative(build_dir);
  return !rel.empty() && *rel.begin() != "..";
#else
  return false;
#endif
}
} // namespace
const std::filesystem::path &runtime_executable() { return executable(); }
std::filesystem::path runtime_resource(const RuntimePath &path) {
  const auto directory = executable().parent_path();
  std::error_code ec;
  if (bundle(directory)) {
    const auto candidate =
        directory.parent_path() / "Resources/Blackbird" / path.relative;
    if (std::filesystem::exists(candidate, ec))
      return candidate;
    return {};
  }
  for (const auto &root :
       {directory / "../share/blackbird", directory / "../../share/blackbird"}) {
    ec.clear();
    if (std::filesystem::is_directory(root, ec)) {
      const auto candidate = (root / path.relative).lexically_normal();
      ec.clear();
      if (std::filesystem::exists(candidate, ec))
        return candidate;
    }
  }
  if (in_build_tree() && !path.development.empty()) {
    ec.clear();
    if (std::filesystem::exists(path.development, ec))
      return path.development;
  }
  return {};
}
std::filesystem::path runtime_helper(const RuntimePath &path) {
  const auto directory = executable().parent_path();
  const auto sibling = directory / path.relative;
  std::error_code ec;
  if (std::filesystem::is_regular_file(sibling, ec))
    return sibling;
  if (in_build_tree() && !path.development.empty()) {
    ec.clear();
    if (std::filesystem::is_regular_file(path.development, ec))
      return path.development;
  }
  return {};
}
} // namespace blackbird
