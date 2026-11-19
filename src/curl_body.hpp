#pragma once
#include "native_process.hpp"
#include <cstdio>
namespace blackbird::detail {
// Derived request body only. Credentials stay on the original stdin config pipe.
// tmpfile is unlinked; the copied CLOEXEC descriptor is passed only to this curl.
class CurlBody final {
  int descriptor_ = -1;

public:
  explicit CurlBody(std::string_view body) {
    if (body.size() <= 1024 * 1024)
      return;
    FILE *file = nullptr;
    {
      const std::lock_guard lock{process_spawn_mutex};
      file = std::tmpfile();
      if (file && ::fcntl(::fileno(file), F_SETFD, FD_CLOEXEC) < 0) {
        const auto saved = errno;
        std::fclose(file);
        throw Error{ErrorCode::io, saved};
      }
    }
    if (!file)
      throw Error{ErrorCode::io, errno};
    try {
      if (std::fwrite(body.data(), 1, body.size(), file) != body.size() ||
          std::fflush(file) || ::fseeko(file, 0, SEEK_SET))
        throw Error{ErrorCode::io, errno};
      descriptor_ = ::fcntl(::fileno(file), F_DUPFD_CLOEXEC, 10);
      if (descriptor_ < 0)
        throw Error{ErrorCode::io, errno};
    } catch (...) {
      std::fclose(file);
      throw;
    }
    std::fclose(file);
  }
  ~CurlBody() {
    if (descriptor_ >= 0)
      ::close(descriptor_);
  }
  CurlBody(const CurlBody &) = delete;
  CurlBody &operator=(const CurlBody &) = delete;
  int descriptor() const { return descriptor_; }
  bool staged() const { return descriptor_ >= 0; }
};
} // namespace blackbird::detail
