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
} // namespace
std::filesystem::path runtime_resource(const RuntimePath &path) {
  const auto directory = executable().parent_path();
  if (bundle(directory))
    return directory.parent_path() / "Resources/Blackbird" / path.relative;
  for (const auto &root :
       {directory / "../share/blackbird", directory / "../../share/blackbird"})
    if (std::filesystem::is_directory(root))
      return (root / path.relative).lexically_normal();
  return path.development;
}
std::filesystem::path runtime_helper(const RuntimePath &path) {
  const auto directory = executable().parent_path();
  const auto sibling = directory / path.relative;
  if (bundle(directory) || std::filesystem::is_regular_file(sibling))
    return sibling;
  return path.development;
}
} // namespace blackbird
