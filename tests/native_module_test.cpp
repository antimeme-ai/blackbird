#include "blackbird/native_module.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird;

void check(bool condition, int line) {
  if (!condition) {
    std::fprintf(stderr, "native_module_test:%d\n", line);
    std::abort();
  }
}

#define CHECK(...) check((__VA_ARGS__), __LINE__)

template <typename T> T need(Result<T> result) {
  CHECK(result.has_value());
  return std::move(result).value();
}

void need(Result<void> result) { CHECK(result.has_value()); }

struct FixturePaths {
  std::string v1;
  std::string v2;
  std::string bad;
};

FixturePaths resolve_fixtures(int argc, char **argv) {
  if (argc >= 4) {
    return FixturePaths{argv[1], argv[2], argv[3]};
  }
#if defined(BLACKBIRD_NATIVE_FIXTURE_V1) && defined(BLACKBIRD_NATIVE_FIXTURE_V2) &&    \
    defined(BLACKBIRD_NATIVE_FIXTURE_BAD)
  return FixturePaths{BLACKBIRD_NATIVE_FIXTURE_V1, BLACKBIRD_NATIVE_FIXTURE_V2,
                      BLACKBIRD_NATIVE_FIXTURE_BAD};
#else
  std::fprintf(stderr, "native_module_test: missing fixture paths\n");
  std::abort();
#endif
}

void test_lifecycle_pinning_drain_and_isolation(const FixturePaths &paths) {
  NativeModuleHost host;

  // Initial empty state.
  {
    const auto st = host.status();
    CHECK(!st.has_active);
    CHECK(st.active_generation == 0);
    CHECK(st.active_in_flight == 0);
    CHECK(st.staged_candidates == 0);
    CHECK(st.retired_pending_unload == 0);
    CHECK(!st.can_rollback);

    const auto no_lease = host.acquire_active();
    CHECK(!no_lease.has_value());
    CHECK(no_lease.error().code == ErrorCode::stale_handle);
  }

  // Load and activate v1 -> generation 1.
  const auto cand_v1 = need(host.load_candidate(paths.v1));
  CHECK(cand_v1.candidate_id == 1);
  CHECK(cand_v1.info.abi_version == BLACKBIRD_MODULE_ABI_VERSION);
  CHECK(cand_v1.info.name == "fixture_prefix");
  CHECK(cand_v1.info.version == "1.0.0");
  CHECK(host.status().staged_candidates == 1);
  CHECK(!host.status().has_active);

  const auto gen1 = need(host.activate(cand_v1.candidate_id));
  CHECK(gen1 == 1);
  {
    const auto st = host.status();
    CHECK(st.has_active);
    CHECK(st.active_generation == 1);
    CHECK(st.staged_candidates == 0);
    CHECK(st.retired_pending_unload == 0);
    CHECK(st.active_info.has_value());
    if (st.active_info.has_value()) {
      CHECK(st.active_info->version == "1.0.0");
    }
  }

  {
    const auto lease_v1 = need(host.acquire_active());
    CHECK(lease_v1.valid());
    CHECK(lease_v1.generation_id() == 1);
    CHECK(lease_v1.abi_version() == BLACKBIRD_MODULE_ABI_VERSION);
    CHECK(lease_v1.name() == "fixture_prefix");
    CHECK(lease_v1.version() == "1.0.0");
    CHECK(need(lease_v1.transform("hello")) == "v1:hello");
    CHECK(need(lease_v1.transform("")) == "v1:");

    // Exercise dynamic buffer growth (input > initial 256-byte scratch buffer).
    const std::string large(4096U, 'x');
    CHECK(need(lease_v1.transform(large)) == "v1:" + large);
  }

  // Hold an explicit lease on v1 while activating v2.
  {
    auto held_v1 = need(host.acquire_active());
    CHECK(held_v1.generation_id() == 1);
    CHECK(held_v1.in_flight() == 1);
    CHECK(host.status().active_in_flight == 1);

    const auto cand_v2 = need(host.load_candidate(paths.v2));
    CHECK(cand_v2.info.version == "2.0.0");
    const auto gen2 = need(host.activate(cand_v2.candidate_id));
    CHECK(gen2 == 2);

    // New acquire_active() serves v2.
    {
      const auto lease_v2 = need(host.acquire_active());
      CHECK(lease_v2.generation_id() == 2);
      CHECK(lease_v2.version() == "2.0.0");
      CHECK(need(lease_v2.transform("hello")) == "v2:hello");
    }

    // v1 must still be loaded and pending unload while held_v1 is alive.
    {
      const auto st = host.status();
      CHECK(st.active_generation == 2);
      CHECK(st.retired_pending_unload == 1);
      CHECK(st.can_rollback);
      CHECK(host.retire_drained() == 0);
    }

    // Held v1 lease still safely executes v1 code.
    CHECK(need(held_v1.transform("delayed")) == "v1:delayed");
  }

  // Dropping held_v1 must drain and unload v1 immediately.
  {
    const auto st = host.status();
    CHECK(st.active_generation == 2);
    CHECK(st.retired_pending_unload == 0);
    CHECK(st.total_unloads >= 1);
  }

  // Failed candidate isolation: ABI 999 must be rejected without disturbing v2.
  {
    const auto bad = host.load_candidate(paths.bad);
    CHECK(!bad.has_value());
    CHECK(bad.error().code == ErrorCode::unsupported);
    CHECK(bad.error().detail == 999);

    const auto st = host.status();
    CHECK(st.active_generation == 2);
    CHECK(st.staged_candidates == 0);
    CHECK(st.retired_pending_unload == 0);

    const auto lease_v2 = need(host.acquire_active());
    CHECK(lease_v2.generation_id() == 2);
    CHECK(need(lease_v2.transform("ok")) == "v2:ok");
  }

  // Discard staged candidate path.
  {
    const auto staged = need(host.load_candidate(paths.v1));
    CHECK(host.status().staged_candidates == 1);
    need(host.discard_candidate(staged.candidate_id));
    CHECK(host.status().staged_candidates == 0);
    const auto stale_activate = host.activate(staged.candidate_id);
    CHECK(!stale_activate.has_value());
    CHECK(stale_activate.error().code == ErrorCode::stale_handle);
  }
}

void test_path_safety(const FixturePaths &paths) {
  NativeModuleHost host;
  const auto cand_v1 = need(host.load_candidate(paths.v1));
  CHECK(need(host.activate(cand_v1.candidate_id)) == 1);

  // Empty path.
  {
    const auto res = host.load_candidate("");
    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::invalid_range);
  }

  // Relative path.
  {
    const auto res = host.load_candidate("native_module_fixture_v1.dylib");
    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::invalid_range);
  }

  // Embedded NUL byte.
  {
    std::string nul_path = paths.v1;
    nul_path.push_back('\0');
    nul_path.append("suffix");
    const auto res = host.load_candidate(nul_path);
    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::invalid_range);
  }

  // Non-existent absolute path.
  {
    const auto res = host.load_candidate("/nonexistent/blackbird/module.so");
    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::io);
  }

  // Directory (not a regular file).
  {
    const std::filesystem::path dir = std::filesystem::path{paths.v1}.parent_path();
    const auto res = host.load_candidate(dir.string());
    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::unsupported);
  }

  // Symlink (must be rejected via lstat / O_NOFOLLOW).
  {
    const std::filesystem::path link_path =
        std::filesystem::temp_directory_path() /
        ("blackbird_native_mod_link_" + std::to_string(::getpid()) + ".so");
    std::error_code ec;
    std::filesystem::remove(link_path, ec);
    std::filesystem::create_symlink(paths.v1, link_path, ec);
    CHECK(!ec);

    const auto res = host.load_candidate(link_path.string());
    std::filesystem::remove(link_path, ec);

    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::unsupported);
  }

  // Active v1 generation remains unaffected.
  const auto lease = need(host.acquire_active());
  CHECK(need(lease.transform("safe")) == "v1:safe");
}

void test_rollback(const FixturePaths &paths) {
  NativeModuleHost host;

  // Rollback with no history fails cleanly.
  {
    const auto res = host.rollback();
    CHECK(!res.has_value());
    CHECK(res.error().code == ErrorCode::conflict);
  }

  const auto c1 = need(host.load_candidate(paths.v1));
  CHECK(need(host.activate(c1.candidate_id)) == 1);
  const auto c2 = need(host.load_candidate(paths.v2));
  CHECK(need(host.activate(c2.candidate_id)) == 2);
  CHECK(host.status().retired_pending_unload == 0);

  // Case 1: previous generation (v1) already unloaded -> rollback reloads cleanly.
  const auto gen3 = need(host.rollback());
  CHECK(gen3 == 3);
  {
    const auto lease = need(host.acquire_active());
    CHECK(lease.generation_id() == 3);
    CHECK(need(lease.transform("reloaded")) == "v1:reloaded");
  }

  // Case 2: previous generation (v1) still pinned -> rollback revives in-place.
  {
    auto pin_v1 = need(host.acquire_active());
    const auto c2_again = need(host.load_candidate(paths.v2));
    CHECK(need(host.activate(c2_again.candidate_id)) == 4);
    CHECK(host.status().retired_pending_unload == 1);

    const auto gen5 = need(host.rollback());
    CHECK(gen5 == 5);
    CHECK(host.status().retired_pending_unload == 0);
    CHECK(need(pin_v1.transform("pinned")) == "v1:pinned");
  }

  // After dropping pin_v1, revived v1 must remain active and loaded.
  const auto lease = need(host.acquire_active());
  CHECK(lease.generation_id() == 5);
  CHECK(need(lease.transform("alive")) == "v1:alive");
}

void test_multithreaded_swap_stress(const FixturePaths &paths) {
  NativeModuleHost host;
  const auto initial = need(host.load_candidate(paths.v1));
  CHECK(need(host.activate(initial.candidate_id)) == 1);

  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> seen_v1{0};
  std::atomic<std::uint64_t> seen_v2{0};
  std::atomic<std::uint64_t> total_calls{0};

  constexpr int kReaderThreads = 4;
  std::vector<std::thread> readers;
  readers.reserve(kReaderThreads);

  for (int tid = 0; tid < kReaderThreads; ++tid) {
    readers.emplace_back([&, tid]() {
      std::uint64_t iter = 0;
      while (!stop.load(std::memory_order_acquire) || iter < 20U) {
        const auto lease = need(host.acquire_active());
        const std::string payload =
            "t" + std::to_string(tid) + "-" + std::to_string(iter);
        const std::string output = need(lease.transform(payload));
        if (output == "v1:" + payload) {
          seen_v1.fetch_add(1, std::memory_order_relaxed);
        } else if (output == "v2:" + payload) {
          seen_v2.fetch_add(1, std::memory_order_relaxed);
        } else {
          CHECK(false);
        }
        total_calls.fetch_add(1, std::memory_order_relaxed);
        ++iter;
      }
    });
  }

  // Wait briefly until readers are actively hammering v1.
  while (total_calls.load(std::memory_order_relaxed) < 100U) {
    std::this_thread::yield();
  }

  // Swap v1 <-> v2 10 times concurrently while readers execute.
  constexpr int kSwapCount = 10;
  for (int swap = 0; swap < kSwapCount; ++swap) {
    const std::string &target_path = (swap % 2 == 0) ? paths.v2 : paths.v1;
    const auto candidate = need(host.load_candidate(target_path));
    const auto gen = need(host.activate(candidate.candidate_id));
    CHECK(gen == static_cast<std::uint64_t>(swap + 2));
    for (int pause = 0; pause < 32; ++pause) {
      std::this_thread::yield();
    }
  }

  stop.store(true, std::memory_order_release);
  for (auto &reader : readers) {
    reader.join();
  }

  CHECK(seen_v1.load(std::memory_order_relaxed) > 0);
  CHECK(seen_v2.load(std::memory_order_relaxed) > 0);
  CHECK(host.retire_drained() == 0);

  const auto st = host.status();
  CHECK(st.active_in_flight == 0);
  CHECK(st.retired_pending_unload == 0);
  CHECK(st.active_generation == static_cast<std::uint64_t>(kSwapCount + 1));
  CHECK(st.total_unloads == static_cast<std::uint64_t>(kSwapCount));
}

} // namespace

int main(int argc, char **argv) {
  const auto paths = resolve_fixtures(argc, argv);
  test_lifecycle_pinning_drain_and_isolation(paths);
  test_path_safety(paths);
  test_rollback(paths);
  test_multithreaded_swap_stress(paths);
  return 0;
}
