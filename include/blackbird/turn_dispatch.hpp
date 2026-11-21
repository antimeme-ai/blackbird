#pragma once
#include <cstdint>
#include <mutex>
#include <optional>

namespace blackbird {
// Local commitment only, never a claim of remote delivery/cancellation. The
// terminal owner begins a generation after joining the preceding worker. Stop
// and each provider attempt commitment serialize here; no callback or I/O runs
// while holding this mutex. Queued terminal work has a separate per-item hold.
class TurnDispatch {
public:
  using Token = std::uint64_t;
  Token begin() {
    const std::lock_guard lock{mutex_};
    ++generation_;
    stopped_ = false;
    return generation_;
  }
  bool stop(Token target) {
    const std::lock_guard lock{mutex_};
    if (target != generation_)
      return false;
    stopped_ = true;
    return true;
  }
  Token current() const {
    const std::lock_guard lock{mutex_};
    return generation_;
  }
  // A returned commitment precedes any later stop of this generation. A stop
  // that won refuses both first attempts and retries, regardless of timer state.
  std::optional<std::uint64_t> commit(Token target) {
    const std::lock_guard lock{mutex_};
    if (target != generation_ || stopped_)
      return std::nullopt;
    return ++commitment_;
  }

private:
  mutable std::mutex mutex_;
  Token generation_ = 0;
  std::uint64_t commitment_ = 0;
  bool stopped_ = false;
};
} // namespace blackbird
