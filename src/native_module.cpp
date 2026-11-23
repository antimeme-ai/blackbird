#include "blackbird/native_module.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace blackbird {
namespace detail {

struct NativeModuleSlot {
  std::uint64_t candidate_id = 0;
  std::uint64_t generation_id = 0;
  NativeModuleDescriptorInfo info;
  void *dl_handle = nullptr;
  BlackbirdModuleTransformFn transform_fn = nullptr;
  std::atomic<std::uint64_t> in_flight{0};
  bool retired = false;
  bool unloaded = false;
};

struct NativeModuleHostState {
  // Lock ordering: always acquire load_mutex before state_mutex.
  std::mutex load_mutex;
  mutable std::mutex state_mutex;

  std::shared_ptr<NativeModuleSlot> active;
  std::unordered_map<std::uint64_t, std::shared_ptr<NativeModuleSlot>> staged;
  std::vector<std::shared_ptr<NativeModuleSlot>> retired;
  std::weak_ptr<NativeModuleSlot> previous_slot;
  std::optional<std::filesystem::path> previous_path;

  std::uint64_t next_candidate_id = 1;
  std::uint64_t next_generation_id = 0;
  std::uint64_t total_unloads = 0;
};

} // namespace detail

namespace {

class ScopedFd {
public:
  explicit ScopedFd(int fd) noexcept : fd_(fd) {}
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ~ScopedFd() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }
  int get() const noexcept { return fd_; }

private:
  int fd_ = -1;
};

class ScopedDlHandle {
public:
  explicit ScopedDlHandle(void *handle) noexcept : handle_(handle) {}
  ScopedDlHandle(const ScopedDlHandle &) = delete;
  ScopedDlHandle &operator=(const ScopedDlHandle &) = delete;
  ~ScopedDlHandle() {
    if (handle_ != nullptr) {
      ::dlclose(handle_);
    }
  }
  void *get() const noexcept { return handle_; }
  void *release() noexcept { return std::exchange(handle_, nullptr); }

private:
  void *handle_ = nullptr;
};

Result<std::string> validate_module_path(std::string_view path) {
  if (path.empty() || path.find('\0') != std::string_view::npos) {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }
  if (path.front() != '/') {
    return Result<std::string>::failure({ErrorCode::invalid_range});
  }

  std::string owned{path};
  struct stat lst{};
  if (::lstat(owned.c_str(), &lst) != 0) {
    return Result<std::string>::failure({ErrorCode::io, errno});
  }
  if (!S_ISREG(lst.st_mode)) {
    return Result<std::string>::failure({ErrorCode::unsupported});
  }

  const ScopedFd fd{::open(owned.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)};
  if (fd.get() < 0) {
    const int err = errno;
    if (err == ELOOP) {
      return Result<std::string>::failure({ErrorCode::unsupported, err});
    }
    return Result<std::string>::failure({ErrorCode::io, err});
  }

  struct stat fst{};
  if (::fstat(fd.get(), &fst) != 0) {
    return Result<std::string>::failure({ErrorCode::io, errno});
  }
  if (!S_ISREG(fst.st_mode) || fst.st_dev != lst.st_dev || fst.st_ino != lst.st_ino) {
    return Result<std::string>::failure({ErrorCode::unsupported});
  }

  return Result<std::string>::success(std::move(owned));
}

Result<std::string> validate_metadata_string(const char *raw) {
  if (raw == nullptr) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  const std::size_t len = ::strnlen(raw, kNativeModuleMaxMetadataBytes + 1U);
  if (len == 0 || len > kNativeModuleMaxMetadataBytes) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  const std::string_view view{raw, len};
  if (!valid_utf8(view)) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  for (const char ch : view) {
    const auto byte = static_cast<unsigned char>(ch);
    if (byte < 0x20U || byte == 0x7FU) {
      return Result<std::string>::failure({ErrorCode::corrupt});
    }
  }
  return Result<std::string>::success(std::string{view});
}

Result<void> probe_transform(BlackbirdModuleTransformFn transform_fn) {
  static constexpr std::string_view kProbeInput = "probe";
  std::array<char, 256> out_buf{};
  std::size_t out_len = 0;

  const int rc = transform_fn(kProbeInput.data(), kProbeInput.size(), out_buf.data(),
                              out_buf.size(), &out_len);
  if (rc != BLACKBIRD_MODULE_OK || out_len > out_buf.size()) {
    return Result<void>::failure({ErrorCode::corrupt, rc});
  }

  if (out_len > 0) {
    std::array<char, 256> small_buf{};
    std::size_t needed = 0;
    const int small_rc = transform_fn(kProbeInput.data(), kProbeInput.size(),
                                      small_buf.data(), out_len - 1U, &needed);
    if (small_rc == BLACKBIRD_MODULE_OK || needed != out_len) {
      return Result<void>::failure({ErrorCode::corrupt, small_rc});
    }
  }
  return Result<void>::success();
}

// Caller must hold state->load_mutex (and NOT state->state_mutex).
Result<std::shared_ptr<detail::NativeModuleSlot>>
load_and_validate_slot(std::string_view path) {
  auto checked_path = validate_module_path(path);
  if (!checked_path.has_value()) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        checked_path.error());
  }

  (void)::dlerror();
  ScopedDlHandle dl_guard{
      ::dlopen(checked_path.value().c_str(), RTLD_NOW | RTLD_LOCAL)};
  if (dl_guard.get() == nullptr) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        {ErrorCode::corrupt});
  }

  (void)::dlerror();
  void *sym = ::dlsym(dl_guard.get(), BLACKBIRD_MODULE_DESCRIBE_SYMBOL);
  if (sym == nullptr) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        {ErrorCode::corrupt});
  }

  BlackbirdModuleDescribeFn describe_fn = nullptr;
  static_assert(sizeof(describe_fn) == sizeof(sym));
  std::memcpy(&describe_fn, &sym, sizeof(describe_fn));
  if (describe_fn == nullptr) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        {ErrorCode::corrupt});
  }

  const BlackbirdModuleDescriptor *desc = describe_fn();
  if (desc == nullptr) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        {ErrorCode::corrupt});
  }

  if (desc->abi_version != BLACKBIRD_MODULE_ABI_VERSION) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        {ErrorCode::unsupported, static_cast<std::int64_t>(desc->abi_version)});
  }

  auto valid_name = validate_metadata_string(desc->name);
  if (!valid_name.has_value()) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        valid_name.error());
  }
  auto valid_version = validate_metadata_string(desc->version);
  if (!valid_version.has_value()) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        valid_version.error());
  }
  if (desc->transform == nullptr) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(
        {ErrorCode::corrupt});
  }

  const auto probe = probe_transform(desc->transform);
  if (!probe.has_value()) {
    return Result<std::shared_ptr<detail::NativeModuleSlot>>::failure(probe.error());
  }

  auto slot = std::make_shared<detail::NativeModuleSlot>();
  slot->info.abi_version = desc->abi_version;
  slot->info.name = std::move(valid_name).value();
  slot->info.version = std::move(valid_version).value();
  slot->info.path = std::filesystem::path{std::move(checked_path).value()};
  slot->transform_fn = desc->transform;
  slot->dl_handle = dl_guard.release();
  return Result<std::shared_ptr<detail::NativeModuleSlot>>::success(std::move(slot));
}

// Caller must hold state.state_mutex. Returns a dl_handle to close outside the
// lock if the slot has already drained; otherwise keeps it in state.retired.
void *
retire_slot_locked(detail::NativeModuleHostState &state,
                   const std::shared_ptr<detail::NativeModuleSlot> &slot) noexcept {
  if (!slot || slot->unloaded) {
    return nullptr;
  }
  slot->retired = true;
  if (slot->in_flight.load(std::memory_order_acquire) == 0) {
    void *handle = std::exchange(slot->dl_handle, nullptr);
    slot->unloaded = true;
    ++state.total_unloads;
    std::erase(state.retired, slot);
    return handle;
  }
  if (std::ranges::find(state.retired, slot) == state.retired.end()) {
    state.retired.push_back(slot);
  }
  return nullptr;
}

} // namespace

ModuleGenerationLease::ModuleGenerationLease(
    std::shared_ptr<detail::NativeModuleHostState> state,
    std::shared_ptr<detail::NativeModuleSlot> slot,
    std::uint64_t generation_id) noexcept
    : state_(std::move(state)), slot_(std::move(slot)), generation_id_(generation_id) {}

ModuleGenerationLease::ModuleGenerationLease(ModuleGenerationLease &&other) noexcept
    : state_(std::move(other.state_)), slot_(std::move(other.slot_)),
      generation_id_(std::exchange(other.generation_id_, 0)) {}

ModuleGenerationLease &
ModuleGenerationLease::operator=(ModuleGenerationLease &&other) noexcept {
  if (this != &other) {
    release();
    state_ = std::move(other.state_);
    slot_ = std::move(other.slot_);
    generation_id_ = std::exchange(other.generation_id_, 0);
  }
  return *this;
}

ModuleGenerationLease::~ModuleGenerationLease() { release(); }

std::uint32_t ModuleGenerationLease::abi_version() const noexcept {
  return slot_ ? slot_->info.abi_version : 0;
}

std::string_view ModuleGenerationLease::name() const noexcept {
  return slot_ ? std::string_view{slot_->info.name} : std::string_view{};
}

std::string_view ModuleGenerationLease::version() const noexcept {
  return slot_ ? std::string_view{slot_->info.version} : std::string_view{};
}

std::uint64_t ModuleGenerationLease::in_flight() const noexcept {
  return slot_ ? slot_->in_flight.load(std::memory_order_acquire) : 0;
}

Result<std::string> ModuleGenerationLease::transform(std::string_view input) const {
  if (!slot_ || slot_->transform_fn == nullptr) {
    return Result<std::string>::failure({ErrorCode::stale_handle});
  }
  if (input.size() > kNativeModuleMaxInputBytes) {
    return Result<std::string>::failure({ErrorCode::capacity});
  }

  const char *in_ptr = input.empty() ? "" : input.data();
  const std::size_t initial_cap =
      std::clamp(input.size() + 64U, std::size_t{256}, kNativeModuleMaxOutputBytes);
  std::string output(initial_cap, '\0');
  std::size_t out_len = 0;

  int rc =
      slot_->transform_fn(in_ptr, input.size(), output.data(), output.size(), &out_len);
  if (rc == BLACKBIRD_MODULE_ERR_BUFFER_TOO_SMALL) {
    if (out_len > kNativeModuleMaxOutputBytes) {
      return Result<std::string>::failure({ErrorCode::capacity});
    }
    if (out_len <= output.size()) {
      return Result<std::string>::failure({ErrorCode::corrupt, rc});
    }
    output.resize(out_len);
    std::size_t retry_len = 0;
    rc = slot_->transform_fn(in_ptr, input.size(), output.data(), output.size(),
                             &retry_len);
    out_len = retry_len;
  }

  if (rc != BLACKBIRD_MODULE_OK) {
    const ErrorCode code = rc == BLACKBIRD_MODULE_ERR_INVALID_ARG
                               ? ErrorCode::invalid_range
                               : ErrorCode::corrupt;
    return Result<std::string>::failure({code, rc});
  }
  if (out_len > output.size()) {
    return Result<std::string>::failure({ErrorCode::corrupt});
  }
  output.resize(out_len);
  return Result<std::string>::success(std::move(output));
}

void ModuleGenerationLease::release() noexcept {
  if (!slot_) {
    return;
  }
  auto state = std::move(state_);
  auto slot = std::move(slot_);
  generation_id_ = 0;

  const std::uint64_t previous =
      slot->in_flight.fetch_sub(1, std::memory_order_acq_rel);
  if (previous != 1 || !state) {
    return;
  }

  void *handle_to_close = nullptr;
  {
    std::lock_guard<std::mutex> lock(state->state_mutex);
    if (slot->retired && !slot->unloaded &&
        slot->in_flight.load(std::memory_order_acquire) == 0) {
      handle_to_close = std::exchange(slot->dl_handle, nullptr);
      slot->unloaded = true;
      ++state->total_unloads;
      std::erase(state->retired, slot);
    }
  }
  if (handle_to_close != nullptr) {
    ::dlclose(handle_to_close);
  }
}

NativeModuleHost::NativeModuleHost()
    : state_(std::make_shared<detail::NativeModuleHostState>()) {}

NativeModuleHost::NativeModuleHost(NativeModuleHost &&other) noexcept = default;

NativeModuleHost &NativeModuleHost::operator=(NativeModuleHost &&other) noexcept {
  if (this != &other) {
    shutdown();
    state_ = std::move(other.state_);
  }
  return *this;
}

NativeModuleHost::~NativeModuleHost() { shutdown(); }

void NativeModuleHost::shutdown() noexcept {
  if (!state_) {
    return;
  }
  std::vector<void *> handles_to_close;
  {
    std::lock_guard<std::mutex> lock(state_->state_mutex);
    for (auto &[id, staged_slot] : state_->staged) {
      (void)id;
      if (void *handle = retire_slot_locked(*state_, staged_slot); handle != nullptr) {
        handles_to_close.push_back(handle);
      }
    }
    state_->staged.clear();

    if (state_->active) {
      if (void *handle = retire_slot_locked(*state_, state_->active);
          handle != nullptr) {
        handles_to_close.push_back(handle);
      }
      state_->active.reset();
    }

    auto remaining = std::move(state_->retired);
    state_->retired.clear();
    for (auto &retired_slot : remaining) {
      if (void *handle = retire_slot_locked(*state_, retired_slot); handle != nullptr) {
        handles_to_close.push_back(handle);
      }
    }
  }
  for (void *handle : handles_to_close) {
    ::dlclose(handle);
  }
}

Result<NativeModuleCandidate> NativeModuleHost::load_candidate(std::string_view path) {
  if (!state_) {
    return Result<NativeModuleCandidate>::failure({ErrorCode::stale_handle});
  }

  std::lock_guard<std::mutex> load_lock(state_->load_mutex);
  auto loaded = load_and_validate_slot(path);
  if (!loaded.has_value()) {
    return Result<NativeModuleCandidate>::failure(loaded.error());
  }

  auto slot = std::move(loaded).value();
  NativeModuleCandidate candidate{};
  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    slot->candidate_id = state_->next_candidate_id++;
    candidate.candidate_id = slot->candidate_id;
    candidate.info = slot->info;
    state_->staged.emplace(slot->candidate_id, std::move(slot));
  }
  return Result<NativeModuleCandidate>::success(std::move(candidate));
}

Result<void> NativeModuleHost::discard_candidate(std::uint64_t candidate_id) {
  if (!state_) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }

  void *handle_to_close = nullptr;
  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    const auto it = state_->staged.find(candidate_id);
    if (it == state_->staged.end()) {
      return Result<void>::failure({ErrorCode::stale_handle});
    }
    auto slot = std::move(it->second);
    state_->staged.erase(it);
    handle_to_close = retire_slot_locked(*state_, slot);
  }
  if (handle_to_close != nullptr) {
    ::dlclose(handle_to_close);
  }
  return Result<void>::success();
}

Result<std::uint64_t> NativeModuleHost::activate(std::uint64_t candidate_id) {
  if (!state_) {
    return Result<std::uint64_t>::failure({ErrorCode::stale_handle});
  }

  void *handle_to_close = nullptr;
  std::uint64_t new_generation = 0;
  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    const auto it = state_->staged.find(candidate_id);
    if (it == state_->staged.end()) {
      return Result<std::uint64_t>::failure({ErrorCode::stale_handle});
    }
    auto next_slot = std::move(it->second);
    state_->staged.erase(it);

    auto old_active = std::move(state_->active);
    new_generation = ++state_->next_generation_id;
    next_slot->generation_id = new_generation;
    next_slot->retired = false;
    state_->active = std::move(next_slot);

    if (old_active) {
      state_->previous_path = old_active->info.path;
      state_->previous_slot = old_active;
      handle_to_close = retire_slot_locked(*state_, old_active);
    }
  }
  if (handle_to_close != nullptr) {
    ::dlclose(handle_to_close);
  }
  return Result<std::uint64_t>::success(new_generation);
}

Result<std::uint64_t> NativeModuleHost::rollback() {
  if (!state_) {
    return Result<std::uint64_t>::failure({ErrorCode::stale_handle});
  }

  std::lock_guard<std::mutex> load_lock(state_->load_mutex);

  std::string reload_path;
  void *handle_to_close = nullptr;
  std::uint64_t revived_generation = 0;
  bool revived = false;

  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    if (!state_->active || !state_->previous_path.has_value()) {
      return Result<std::uint64_t>::failure({ErrorCode::conflict});
    }

    if (auto prev = state_->previous_slot.lock(); prev && !prev->unloaded) {
      // Fast path: previous generation is still loaded (pinned by a lease).
      std::erase(state_->retired, prev);
      prev->retired = false;
      auto old_active = std::move(state_->active);
      revived_generation = ++state_->next_generation_id;
      prev->generation_id = revived_generation;
      state_->active = std::move(prev);

      state_->previous_path = old_active->info.path;
      state_->previous_slot = old_active;
      handle_to_close = retire_slot_locked(*state_, old_active);
      revived = true;
    } else {
      reload_path = state_->previous_path->string();
    }
  }

  if (revived) {
    if (handle_to_close != nullptr) {
      ::dlclose(handle_to_close);
    }
    return Result<std::uint64_t>::success(revived_generation);
  }

  auto reloaded = load_and_validate_slot(reload_path);
  if (!reloaded.has_value()) {
    return Result<std::uint64_t>::failure(reloaded.error());
  }

  auto next_slot = std::move(reloaded).value();
  std::uint64_t new_generation = 0;
  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    auto old_active = std::move(state_->active);
    new_generation = ++state_->next_generation_id;
    next_slot->generation_id = new_generation;
    next_slot->retired = false;
    state_->active = std::move(next_slot);

    if (old_active) {
      state_->previous_path = old_active->info.path;
      state_->previous_slot = old_active;
      handle_to_close = retire_slot_locked(*state_, old_active);
    }
  }
  if (handle_to_close != nullptr) {
    ::dlclose(handle_to_close);
  }
  return Result<std::uint64_t>::success(new_generation);
}

Result<ModuleGenerationLease> NativeModuleHost::acquire_active() const {
  if (!state_) {
    return Result<ModuleGenerationLease>::failure({ErrorCode::stale_handle});
  }

  std::shared_ptr<detail::NativeModuleSlot> slot;
  std::uint64_t gen_id = 0;
  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    if (!state_->active) {
      return Result<ModuleGenerationLease>::failure({ErrorCode::stale_handle});
    }
    slot = state_->active;
    gen_id = slot->generation_id;
    slot->in_flight.fetch_add(1, std::memory_order_acq_rel);
  }
  return Result<ModuleGenerationLease>::success(
      ModuleGenerationLease{state_, std::move(slot), gen_id});
}

std::size_t NativeModuleHost::retire_drained() {
  if (!state_) {
    return 0;
  }

  std::vector<void *> handles_to_close;
  {
    std::lock_guard<std::mutex> state_lock(state_->state_mutex);
    std::vector<std::shared_ptr<detail::NativeModuleSlot>> still_pinned;
    still_pinned.reserve(state_->retired.size());

    for (auto &slot : state_->retired) {
      if (slot->unloaded) {
        continue;
      }
      if (slot->in_flight.load(std::memory_order_acquire) == 0) {
        void *handle = std::exchange(slot->dl_handle, nullptr);
        slot->unloaded = true;
        ++state_->total_unloads;
        if (handle != nullptr) {
          handles_to_close.push_back(handle);
        }
      } else {
        still_pinned.push_back(std::move(slot));
      }
    }
    state_->retired = std::move(still_pinned);
  }

  for (void *handle : handles_to_close) {
    ::dlclose(handle);
  }
  return handles_to_close.size();
}

NativeModuleStatus NativeModuleHost::status() const {
  NativeModuleStatus out{};
  if (!state_) {
    return out;
  }
  std::lock_guard<std::mutex> state_lock(state_->state_mutex);
  if (state_->active) {
    out.has_active = true;
    out.active_generation = state_->active->generation_id;
    out.active_in_flight = state_->active->in_flight.load(std::memory_order_acquire);
    out.active_info = state_->active->info;
  }
  out.staged_candidates = state_->staged.size();
  out.retired_pending_unload = state_->retired.size();
  out.total_unloads = state_->total_unloads;
  out.can_rollback = state_->active && state_->previous_path.has_value();
  return out;
}

} // namespace blackbird
