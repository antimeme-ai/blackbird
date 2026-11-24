#pragma once

#include <filesystem>
#include <memory>

namespace blackbird {

// Separate process, started only for a configured, writable application session.
// Its pipe lifetime outlasts the recorder so the final sweep sees its closed run.
class TraceArchiveWorker {
public:
  static std::unique_ptr<TraceArchiveWorker>
  start(const std::filesystem::path &session);
  ~TraceArchiveWorker();
  TraceArchiveWorker(const TraceArchiveWorker &) = delete;
  TraceArchiveWorker &operator=(const TraceArchiveWorker &) = delete;

private:
  TraceArchiveWorker() = default;
  int input_ = -1;
  int process_ = -1;
};

// Multicall entry point for the trace archive helper (`--internal-archive`).
int run_archive_main(int argc, char **argv);

} // namespace blackbird
