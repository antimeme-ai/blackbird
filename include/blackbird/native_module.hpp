#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/native_module_abi.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace blackbird {

inline constexpr std::size_t kNativeModuleMaxMetadataBytes = 128;
inline constexpr std::size_t kNativeModuleMaxInputBytes = 4U * 1024U * 1024U;
inline constexpr std::size_t kNativeModuleMaxOutputBytes = 4U * 1024U * 1024U;

namespace detail {
struct NativeModuleHostState;
struct NativeModuleSlot;
} // namespace detail

struct NativeModuleDescriptorInfo {
  std::uint32_t abi_version = 0;
  std::string name;
  std::string version;
  std::filesystem::path path;
  bool operator==(const NativeModuleDescriptorInfo &) const = default;
};

struct NativeModuleCandidate {
  std::uint64_t candidate_id = 0;
  NativeModuleDescriptorInfo info;
  bool operator==(const NativeModuleCandidate &) const = default;
};

struct NativeModuleStatus {
  bool has_active = false;
  std::uint64_t active_generation = 0;
  std::uint64_t active_in_flight = 0;
  std::optional<NativeModuleDescriptorInfo> active_info;
  std::size_t staged_candidates = 0;
  std::size_t retired_pending_unload = 0;
  std::uint64_t total_unloads = 0;
  bool can_rollback = false;
};

// Explicit RAII pin on one loaded module generation. While alive, the pinned
// generation's in-flight refcount stays positive and its shared library cannot
// be passed to dlclose.
class ModuleGenerationLease {
public:
  ModuleGenerationLease() noexcept = default;
  ModuleGenerationLease(const ModuleGenerationLease &) = delete;
  ModuleGenerationLease &operator=(const ModuleGenerationLease &) = delete;
  ModuleGenerationLease(ModuleGenerationLease &&other) noexcept;
  ModuleGenerationLease &operator=(ModuleGenerationLease &&other) noexcept;
  ~ModuleGenerationLease();

  bool valid() const noexcept { return slot_ != nullptr; }
  explicit operator bool() const noexcept { return valid(); }

  std::uint64_t generation_id() const noexcept { return generation_id_; }
  std::uint32_t abi_version() const noexcept;
  std::string_view name() const noexcept;
  std::string_view version() const noexcept;
  std::uint64_t in_flight() const noexcept;

  Result<std::string> transform(std::string_view input) const;
  void release() noexcept;

private:
  friend class NativeModuleHost;

  ModuleGenerationLease(std::shared_ptr<detail::NativeModuleHostState> state,
                        std::shared_ptr<detail::NativeModuleSlot> slot,
                        std::uint64_t generation_id) noexcept;

  std::shared_ptr<detail::NativeModuleHostState> state_;
  std::shared_ptr<detail::NativeModuleSlot> slot_;
  std::uint64_t generation_id_ = 0;
};

// Hot-reloadable native C++ module boundary (Core Plan U5 prototype):
// stages and validates versioned C ABI shared libraries, activates candidates
// atomically with monotonic generation IDs, pins callers via RAII leases, and
// defers dlclose until retired generations drain to zero in-flight leases.
class NativeModuleHost {
public:
  NativeModuleHost();
  NativeModuleHost(const NativeModuleHost &) = delete;
  NativeModuleHost &operator=(const NativeModuleHost &) = delete;
  NativeModuleHost(NativeModuleHost &&other) noexcept;
  NativeModuleHost &operator=(NativeModuleHost &&other) noexcept;
  ~NativeModuleHost();

  Result<NativeModuleCandidate> load_candidate(std::string_view path);
  Result<void> discard_candidate(std::uint64_t candidate_id);
  Result<std::uint64_t> activate(std::uint64_t candidate_id);
  Result<std::uint64_t> rollback();

  Result<ModuleGenerationLease> acquire_active() const;
  std::size_t retire_drained();
  NativeModuleStatus status() const;

private:
  void shutdown() noexcept;

  std::shared_ptr<detail::NativeModuleHostState> state_;
};

} // namespace blackbird
