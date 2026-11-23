#include "blackbird/capabilities.hpp"
#include "blackbird/json.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <limits>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr std::uint64_t kCapabilitySchemaVersion = 1;
constexpr std::size_t kReadChunkBytes = 32 * 1024;
constexpr std::string_view kJsonSuffix = ".json";

std::atomic<std::uint64_t> g_tmp_counter{0};

Error native_error(int err) noexcept {
  if (err == EINTR)
    return {ErrorCode::interrupted, err};
  if (err == ENOTSUP)
    return {ErrorCode::unsupported, err};
  return {ErrorCode::io, err};
}

class ScopedFd {
public:
  ScopedFd() = default;
  explicit ScopedFd(int fd) noexcept : fd_(fd) {}
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ScopedFd(ScopedFd &&other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
  ScopedFd &operator=(ScopedFd &&other) noexcept {
    if (this != &other) {
      reset();
      fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
  }
  ~ScopedFd() { reset(); }

  int get() const noexcept { return fd_; }
  explicit operator bool() const noexcept { return fd_ >= 0; }
  int release() noexcept { return std::exchange(fd_, -1); }
  void reset(int next = -1) noexcept {
    if (fd_ >= 0)
      (void)::close(fd_);
    fd_ = next;
  }

private:
  int fd_ = -1;
};

class ScopedDir {
public:
  explicit ScopedDir(DIR *dir) noexcept : dir_(dir) {}
  ScopedDir(const ScopedDir &) = delete;
  ScopedDir &operator=(const ScopedDir &) = delete;
  ~ScopedDir() {
    if (dir_ != nullptr)
      (void)::closedir(dir_);
  }
  DIR *get() const noexcept { return dir_; }

private:
  DIR *dir_ = nullptr;
};

// FIPS 180-4 SHA-256 block compression.
constexpr std::array<std::uint32_t, 64> kSha256K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

constexpr std::uint32_t rotr32(std::uint32_t x, unsigned n) noexcept {
  return (x >> n) | (x << (32U - n));
}

void sha256_compress(std::array<std::uint32_t, 8> &state,
                     const unsigned char *block) noexcept {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) {
    const std::size_t j = i * 4;
    w[i] = (static_cast<std::uint32_t>(block[j]) << 24U) |
           (static_cast<std::uint32_t>(block[j + 1]) << 16U) |
           (static_cast<std::uint32_t>(block[j + 2]) << 8U) |
           static_cast<std::uint32_t>(block[j + 3]);
  }
  for (std::size_t i = 16; i < 64; ++i) {
    const std::uint32_t s0 =
        rotr32(w[i - 15], 7U) ^ rotr32(w[i - 15], 18U) ^ (w[i - 15] >> 3U);
    const std::uint32_t s1 =
        rotr32(w[i - 2], 17U) ^ rotr32(w[i - 2], 19U) ^ (w[i - 2] >> 10U);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  std::uint32_t a = state[0];
  std::uint32_t b = state[1];
  std::uint32_t c = state[2];
  std::uint32_t d = state[3];
  std::uint32_t e = state[4];
  std::uint32_t f = state[5];
  std::uint32_t g = state[6];
  std::uint32_t h = state[7];

  for (std::size_t i = 0; i < 64; ++i) {
    const std::uint32_t s1 = rotr32(e, 6U) ^ rotr32(e, 11U) ^ rotr32(e, 25U);
    const std::uint32_t ch = (e & f) ^ ((~e) & g);
    const std::uint32_t temp1 = h + s1 + ch + kSha256K[i] + w[i];
    const std::uint32_t s0 = rotr32(a, 2U) ^ rotr32(a, 13U) ^ rotr32(a, 22U);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t temp2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

bool valid_text_field(std::string_view text, std::size_t max_bytes) noexcept {
  if (text.size() > max_bytes)
    return false;
  if (text.find('\0') != std::string_view::npos)
    return false;
  return valid_utf8(text);
}

bool valid_scope_dir_path(const std::filesystem::path &path) {
  const std::string raw = path.string();
  if (raw.empty() || raw.find('\0') != std::string::npos)
    return false;
  for (const auto &component : path) {
    if (component == "..")
      return false;
  }
  return true;
}

Result<void> check_safe_fd(int fd, bool expect_directory) noexcept {
  struct stat st{};
  if (::fstat(fd, &st) != 0)
    return Result<void>::failure(native_error(errno));
  const bool kind_ok = expect_directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode);
  if (!kind_ok)
    return Result<void>::failure({ErrorCode::io, EPERM});
  // Require owner match and reject group-writable or world-writable modes.
  if (st.st_uid != ::geteuid() || (st.st_mode & 0022) != 0)
    return Result<void>::failure({ErrorCode::io, EPERM});
  return Result<void>::success();
}

Result<void> fsync_fd(int fd) noexcept {
  while (::fsync(fd) != 0) {
    if (errno == EINTR)
      continue;
    return Result<void>::failure(native_error(errno));
  }
  return Result<void>::success();
}

Result<void> write_all_fd(int fd, std::string_view data) noexcept {
  std::size_t offset = 0;
  while (offset < data.size()) {
    const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      return Result<void>::failure(native_error(errno));
    }
    if (written == 0)
      return Result<void>::failure({ErrorCode::io, EIO});
    offset += static_cast<std::size_t>(written);
  }
  return Result<void>::success();
}

Result<std::string> read_bounded_fd(const ScopedFd &fd, std::size_t max_bytes) {
  struct stat st{};
  if (::fstat(fd.get(), &st) != 0)
    return Result<std::string>::failure(native_error(errno));
  if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0022) != 0)
    return Result<std::string>::failure({ErrorCode::io, EPERM});
  if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > max_bytes)
    return Result<std::string>::failure({ErrorCode::capacity});

  std::string out;
  out.reserve(static_cast<std::size_t>(st.st_size));
  std::array<char, kReadChunkBytes> chunk{};
  for (;;) {
    const ssize_t count = ::read(fd.get(), chunk.data(), chunk.size());
    if (count < 0) {
      if (errno == EINTR)
        continue;
      return Result<std::string>::failure(native_error(errno));
    }
    if (count == 0)
      break;
    const auto bytes = static_cast<std::size_t>(count);
    if (bytes > max_bytes - out.size())
      return Result<std::string>::failure({ErrorCode::capacity});
    out.append(chunk.data(), bytes);
  }
  return Result<std::string>::success(std::move(out));
}

std::string strip_trailing_slashes(const std::filesystem::path &path) {
  std::string out = path.string();
  while (out.size() > 1 && out.back() == '/')
    out.pop_back();
  return out;
}

Result<std::optional<ScopedFd>>
open_existing_scope_dir(const std::filesystem::path &dir) {
  const std::string path_str = strip_trailing_slashes(dir);
  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT)
      return Result<std::optional<ScopedFd>>::success(std::nullopt);
    return Result<std::optional<ScopedFd>>::failure(native_error(errno));
  }
  ScopedFd owned{fd};
  auto checked = check_safe_fd(owned.get(), true);
  if (!checked.has_value())
    return Result<std::optional<ScopedFd>>::failure(checked.error());
  return Result<std::optional<ScopedFd>>::success(std::move(owned));
}

Result<ScopedFd> open_or_create_scope_dir(const std::filesystem::path &dir) {
  const std::string path_str = strip_trailing_slashes(dir);
  bool created = false;
  if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
    created = true;
  } else if (errno == ENOENT) {
    const auto parent = std::filesystem::path{path_str}.parent_path();
    if (!parent.empty()) {
      std::error_code ec;
      (void)std::filesystem::create_directories(parent, ec);
      if (ec)
        return Result<ScopedFd>::failure({ErrorCode::io, ec.value()});
    }
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno != EEXIST) {
      return Result<ScopedFd>::failure(native_error(errno));
    }
  } else if (errno != EEXIST) {
    return Result<ScopedFd>::failure(native_error(errno));
  }

  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0)
    return Result<ScopedFd>::failure(native_error(errno));
  ScopedFd owned{fd};

  if (created && ::fchmod(owned.get(), mode_t{0700}) != 0)
    return Result<ScopedFd>::failure(native_error(errno));

  auto checked = check_safe_fd(owned.get(), true);
  if (!checked.has_value())
    return Result<ScopedFd>::failure(checked.error());

  return Result<ScopedFd>::success(std::move(owned));
}

Result<void> validate_param_value(const CapabilityParam &param,
                                  std::string_view value) noexcept {
  if (!valid_text_field(value, kCapabilityMaxFieldBytes))
    return Result<void>::failure({ErrorCode::invalid_range});

  switch (param.type) {
  case CapabilityParamType::string:
    return Result<void>::success();
  case CapabilityParamType::integer: {
    if (value.empty())
      return Result<void>::failure({ErrorCode::invalid_range});
    // Reject leading '+' or whitespace; accept optional '-' followed by digits.
    const char *begin = value.data();
    const char *end = value.data() + value.size();
    std::int64_t parsed = 0;
    const auto [ptr, ec] = std::from_chars(begin, end, parsed, 10);
    if (ec != std::errc{} || ptr != end)
      return Result<void>::failure({ErrorCode::invalid_range});
    return Result<void>::success();
  }
  case CapabilityParamType::boolean:
    if (value == "true" || value == "false")
      return Result<void>::success();
    return Result<void>::failure({ErrorCode::invalid_range});
  case CapabilityParamType::enumeration: {
    const auto it =
        std::find(param.allowed_values.begin(), param.allowed_values.end(), value);
    if (it == param.allowed_values.end())
      return Result<void>::failure({ErrorCode::invalid_range});
    return Result<void>::success();
  }
  }
  return Result<void>::failure({ErrorCode::invalid_range});
}

Result<void> validate_param(const CapabilityParam &param) {
  if (!valid_capability_param_name(param.name))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_text_field(param.description, kCapabilityMaxFieldBytes))
    return Result<void>::failure({ErrorCode::invalid_range});

  if (param.type == CapabilityParamType::enumeration) {
    if (param.allowed_values.empty() ||
        param.allowed_values.size() > kCapabilityMaxEnumValues) {
      return Result<void>::failure({ErrorCode::invalid_range});
    }
    std::set<std::string_view> seen;
    for (const auto &entry : param.allowed_values) {
      if (!valid_text_field(entry, kCapabilityMaxFieldBytes))
        return Result<void>::failure({ErrorCode::invalid_range});
      if (!seen.insert(entry).second)
        return Result<void>::failure({ErrorCode::invalid_range});
    }
  } else if (!param.allowed_values.empty()) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }

  if (param.default_value.has_value()) {
    auto checked = validate_param_value(param, *param.default_value);
    if (!checked.has_value())
      return checked;
  }

  return Result<void>::success();
}

Result<void> validate_definition(const CapabilityDefinition &definition) {
  if (!valid_capability_id(definition.id))
    return Result<void>::failure({ErrorCode::invalid_identity});
  if (!valid_text_field(definition.title, kCapabilityMaxFieldBytes))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_text_field(definition.description, kCapabilityMaxFieldBytes))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (!valid_text_field(definition.body, kCapabilityMaxBodyBytes))
    return Result<void>::failure({ErrorCode::invalid_range});
  if (definition.params.size() > kCapabilityMaxParams)
    return Result<void>::failure({ErrorCode::capacity});

  std::set<std::string_view> seen_names;
  for (const auto &param : definition.params) {
    auto valid = validate_param(param);
    if (!valid.has_value())
      return valid;
    if (!seen_names.insert(param.name).second)
      return Result<void>::failure({ErrorCode::invalid_range});
  }
  return Result<void>::success();
}

void append_lp(std::string &out, std::string_view value) {
  out.append(std::to_string(value.size()));
  out.push_back(':');
  out.append(value.data(), value.size());
  out.push_back('\n');
}

const std::string *find_string_field(const Value &object, std::string_view key) {
  const Value *field = object.find(key);
  if (field == nullptr)
    return nullptr;
  return std::get_if<std::string>(&field->value());
}

const bool *find_bool_field(const Value &object, std::string_view key) {
  const Value *field = object.find(key);
  if (field == nullptr)
    return nullptr;
  return std::get_if<bool>(&field->value());
}

Result<CapabilityParam> param_from_value(const Value &value) {
  const auto *obj = std::get_if<Value::Object>(&value.value());
  if (obj == nullptr)
    return Result<CapabilityParam>::failure({ErrorCode::corrupt});

  for (const auto &[key, _] : *obj) {
    if (key != "name" && key != "type" && key != "required" && key != "default_value" &&
        key != "allowed_values" && key != "description") {
      return Result<CapabilityParam>::failure({ErrorCode::corrupt});
    }
  }

  const auto *name = find_string_field(value, "name");
  const auto *type_name = find_string_field(value, "type");
  if (name == nullptr || type_name == nullptr)
    return Result<CapabilityParam>::failure({ErrorCode::corrupt});

  auto parsed_type = parse_capability_param_type(*type_name);
  if (!parsed_type.has_value())
    return Result<CapabilityParam>::failure({ErrorCode::corrupt});

  CapabilityParam out{};
  out.name = *name;
  out.type = parsed_type.value();

  if (const Value *req = value.find("required"); req != nullptr) {
    const auto *req_bool = std::get_if<bool>(&req->value());
    if (req_bool == nullptr)
      return Result<CapabilityParam>::failure({ErrorCode::corrupt});
    out.required = *req_bool;
  }

  if (const Value *def_val = value.find("default_value"); def_val != nullptr) {
    if (std::holds_alternative<std::nullptr_t>(def_val->value())) {
      out.default_value = std::nullopt;
    } else if (const auto *def_str = std::get_if<std::string>(&def_val->value())) {
      out.default_value = *def_str;
    } else {
      return Result<CapabilityParam>::failure({ErrorCode::corrupt});
    }
  }

  if (const Value *allowed = value.find("allowed_values"); allowed != nullptr) {
    const auto *arr = std::get_if<Value::Array>(&allowed->value());
    if (arr == nullptr)
      return Result<CapabilityParam>::failure({ErrorCode::corrupt});
    out.allowed_values.reserve(arr->size());
    for (const auto &entry : *arr) {
      const auto *s = std::get_if<std::string>(&entry.value());
      if (s == nullptr)
        return Result<CapabilityParam>::failure({ErrorCode::corrupt});
      out.allowed_values.push_back(*s);
    }
  }

  if (const Value *desc = value.find("description"); desc != nullptr) {
    const auto *desc_str = std::get_if<std::string>(&desc->value());
    if (desc_str == nullptr)
      return Result<CapabilityParam>::failure({ErrorCode::corrupt});
    out.description = *desc_str;
  }

  auto valid = validate_param(out);
  if (!valid.has_value())
    return Result<CapabilityParam>::failure({ErrorCode::corrupt});
  return Result<CapabilityParam>::success(std::move(out));
}

struct FileLoadContext {
  CapabilityScope scope;
  std::string_view expected_id;
  std::filesystem::path source_path;
};

Result<CapabilityDefinition> parse_definition_json(std::string_view raw,
                                                   const FileLoadContext &ctx) {
  ValueLimits limits{};
  limits.bytes = kCapabilityMaxFileBytes;
  limits.nodes = 4096;
  limits.depth = 16;

  auto parsed = parse_json(raw, limits);
  if (!parsed.has_value())
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});

  const Value &root = parsed.value();
  const auto *obj = std::get_if<Value::Object>(&root.value());
  if (obj == nullptr)
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});

  for (const auto &[key, _] : *obj) {
    if (key != "version" && key != "id" && key != "kind" && key != "title" &&
        key != "description" && key != "body" && key != "params" &&
        key != "read_only" && key != "sha256") {
      return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
    }
  }

  if (const Value *ver = root.find("version"); ver != nullptr) {
    const auto *num = std::get_if<Number>(&ver->value());
    if (num == nullptr)
      return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
    const auto *u64 = std::get_if<std::uint64_t>(&num->storage());
    const auto *i64 = std::get_if<std::int64_t>(&num->storage());
    const bool ok =
        (u64 != nullptr && *u64 == kCapabilitySchemaVersion) ||
        (i64 != nullptr && *i64 == static_cast<std::int64_t>(kCapabilitySchemaVersion));
    if (!ok)
      return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
  }

  const auto *id = find_string_field(root, "id");
  const auto *kind_str = find_string_field(root, "kind");
  const auto *body = find_string_field(root, "body");
  if (id == nullptr || kind_str == nullptr || body == nullptr)
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
  if (*id != ctx.expected_id)
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});

  auto parsed_kind = parse_capability_kind(*kind_str);
  if (!parsed_kind.has_value())
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});

  CapabilityDefinition out{};
  out.id = *id;
  out.kind = parsed_kind.value();
  out.body = *body;
  out.scope = ctx.scope;
  out.source_path = ctx.source_path;

  if (const Value *title = root.find("title"); title != nullptr) {
    const auto *s = std::get_if<std::string>(&title->value());
    if (s == nullptr)
      return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
    out.title = *s;
  }

  if (const Value *desc = root.find("description"); desc != nullptr) {
    const auto *s = std::get_if<std::string>(&desc->value());
    if (s == nullptr)
      return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
    out.description = *s;
  }

  if (const auto *ro = find_bool_field(root, "read_only"); ro != nullptr) {
    out.read_only = *ro;
  } else if (root.find("read_only") != nullptr) {
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
  }

  if (const Value *params_val = root.find("params"); params_val != nullptr) {
    const auto *arr = std::get_if<Value::Array>(&params_val->value());
    if (arr == nullptr)
      return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});
    out.params.reserve(arr->size());
    for (const auto &entry : *arr) {
      auto parsed_param = param_from_value(entry);
      if (!parsed_param.has_value())
        return Result<CapabilityDefinition>::failure(parsed_param.error());
      out.params.push_back(std::move(parsed_param).value());
    }
  }

  auto valid = validate_definition(out);
  if (!valid.has_value())
    return Result<CapabilityDefinition>::failure({ErrorCode::corrupt});

  out.sha256 = compute_capability_sha256(out);
  return Result<CapabilityDefinition>::success(std::move(out));
}

Result<std::optional<CapabilityDefinition>>
read_single_from_dir(int dir_fd, const FileLoadContext &ctx) {
  std::string filename{ctx.expected_id};
  filename.append(kJsonSuffix);

  int fd = -1;
  do {
    fd = ::openat(dir_fd, filename.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT)
      return Result<std::optional<CapabilityDefinition>>::success(std::nullopt);
    return Result<std::optional<CapabilityDefinition>>::failure(native_error(errno));
  }
  ScopedFd owned{fd};

  auto content = read_bounded_fd(owned, kCapabilityMaxFileBytes);
  if (!content.has_value())
    return Result<std::optional<CapabilityDefinition>>::failure(content.error());

  auto parsed = parse_definition_json(content.value(), ctx);
  if (!parsed.has_value())
    return Result<std::optional<CapabilityDefinition>>::failure(parsed.error());

  return Result<std::optional<CapabilityDefinition>>::success(
      std::move(parsed).value());
}

Result<std::vector<CapabilityDefinition>>
load_scope_directory(const std::filesystem::path &dir, CapabilityScope scope) {
  auto opened = open_existing_scope_dir(dir);
  if (!opened.has_value())
    return Result<std::vector<CapabilityDefinition>>::failure(opened.error());
  auto opt_fd = std::move(opened).value();
  if (!opt_fd.has_value())
    return Result<std::vector<CapabilityDefinition>>::success({});

  const int dir_fd = opt_fd->get();
  const int dup_fd = ::fcntl(dir_fd, F_DUPFD_CLOEXEC, 0);
  if (dup_fd < 0)
    return Result<std::vector<CapabilityDefinition>>::failure(native_error(errno));
  DIR *raw_dir = ::fdopendir(dup_fd);
  if (raw_dir == nullptr) {
    const int err = errno;
    (void)::close(dup_fd);
    return Result<std::vector<CapabilityDefinition>>::failure(native_error(err));
  }
  ScopedDir dir_stream{raw_dir};

  std::vector<std::string> ids;
  for (;;) {
    errno = 0;
    const struct dirent *entry = ::readdir(dir_stream.get());
    if (entry == nullptr) {
      if (errno != 0)
        return Result<std::vector<CapabilityDefinition>>::failure(native_error(errno));
      break;
    }
    const std::string_view name{entry->d_name};
    if (name == "." || name == ".." || name.starts_with('.'))
      continue;
    if (!name.ends_with(kJsonSuffix))
      continue;
    const std::string_view stem = name.substr(0, name.size() - kJsonSuffix.size());
    if (!valid_capability_id(stem))
      return Result<std::vector<CapabilityDefinition>>::failure({ErrorCode::corrupt});
    ids.emplace_back(stem);
  }

  std::sort(ids.begin(), ids.end());
  std::vector<CapabilityDefinition> results;
  results.reserve(ids.size());
  for (const auto &id : ids) {
    const FileLoadContext ctx{scope, id, dir / (id + ".json")};
    auto loaded = read_single_from_dir(dir_fd, ctx);
    if (!loaded.has_value())
      return Result<std::vector<CapabilityDefinition>>::failure(loaded.error());
    auto opt_def = std::move(loaded).value();
    if (opt_def.has_value())
      results.push_back(std::move(*opt_def));
  }
  return Result<std::vector<CapabilityDefinition>>::success(std::move(results));
}

Value definition_storage_document(const CapabilityDefinition &definition) {
  Value::Array params;
  params.reserve(definition.params.size());
  for (const auto &param : definition.params)
    params.push_back(to_value(param));
  return Value::object({
      {"version", Value{Number{kCapabilitySchemaVersion}}},
      {"id", Value{definition.id}},
      {"kind", Value{std::string{capability_kind_name(definition.kind)}}},
      {"title", Value{definition.title}},
      {"description", Value{definition.description}},
      {"body", Value{definition.body}},
      {"params", Value{std::move(params)}},
      {"read_only", Value{definition.read_only}},
      {"sha256", Value{definition.sha256}},
  });
}

Result<void> write_definition_atomic(int dir_fd, const CapabilityDefinition &definition,
                                     std::string_view target_name) {
  ValueLimits limits{};
  limits.bytes = kCapabilityMaxFileBytes;
  auto encoded = dump_json(definition_storage_document(definition), limits);
  if (!encoded.has_value())
    return Result<void>::failure(encoded.error());
  std::string payload = std::move(encoded).value();
  payload.push_back('\n');

  const auto pid = static_cast<unsigned long long>(::getpid());
  std::string tmp_name;
  ScopedFd tmp_fd;
  for (int attempt = 0; attempt < 64; ++attempt) {
    const auto seq = g_tmp_counter.fetch_add(1, std::memory_order_relaxed);
    tmp_name =
        "." + definition.id + ".tmp." + std::to_string(pid) + "." + std::to_string(seq);
    int fd = -1;
    do {
      fd = ::openat(dir_fd, tmp_name.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
      tmp_fd.reset(fd);
      break;
    }
    if (errno != EEXIST)
      return Result<void>::failure(native_error(errno));
  }
  if (!tmp_fd)
    return Result<void>::failure({ErrorCode::conflict, EEXIST});

  class TempFileGuard {
  public:
    TempFileGuard(int parent_fd, std::string name) noexcept
        : parent_fd_(parent_fd), name_(std::move(name)) {}
    TempFileGuard(const TempFileGuard &) = delete;
    TempFileGuard &operator=(const TempFileGuard &) = delete;
    ~TempFileGuard() {
      if (active_)
        (void)::unlinkat(parent_fd_, name_.c_str(), 0);
    }
    void dismiss() noexcept { active_ = false; }
    const char *c_str() const noexcept { return name_.c_str(); }

  private:
    int parent_fd_;
    std::string name_;
    bool active_ = true;
  } cleanup{dir_fd, std::move(tmp_name)};

  auto written = write_all_fd(tmp_fd.get(), payload);
  if (!written.has_value())
    return written;
  auto synced = fsync_fd(tmp_fd.get());
  if (!synced.has_value())
    return synced;
  const int raw_fd = tmp_fd.release();
  if (::close(raw_fd) != 0)
    return Result<void>::failure(native_error(errno));

  const std::string target_str{target_name};
  if (::renameat(dir_fd, cleanup.c_str(), dir_fd, target_str.c_str()) != 0)
    return Result<void>::failure(native_error(errno));
  cleanup.dismiss();
  return fsync_fd(dir_fd);
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

bool contains_case_insensitive(std::string_view haystack,
                               std::string_view needle_lower) {
  if (needle_lower.empty())
    return true;
  return ascii_lower(haystack).find(needle_lower) != std::string::npos;
}

void merge_definition(std::map<std::string, CapabilityDefinition> &merged,
                      CapabilityDefinition candidate) {
  auto it = merged.find(candidate.id);
  if (it == merged.end()) {
    merged.emplace(candidate.id, std::move(candidate));
  } else {
    it->second.shadowed.push_back(CapabilityShadowed{
        candidate.scope,
        std::move(candidate.source_path),
        std::move(candidate.sha256),
    });
  }
}

Result<std::string>
render_template_single_pass(const CapabilityDefinition &definition,
                            const std::map<std::string, std::string> &bound_params,
                            const std::set<std::string_view> &declared_params) {
  const std::string_view body = definition.body;
  std::string out;
  out.reserve(body.size());

  auto append_checked = [&](std::string_view piece) -> Result<void> {
    if (piece.size() > kCapabilityMaxRenderedBytes - out.size())
      return Result<void>::failure({ErrorCode::capacity});
    out.append(piece.data(), piece.size());
    return Result<void>::success();
  };

  std::size_t pos = 0;
  while (pos < body.size()) {
    const std::size_t open = body.find("{{", pos);
    if (open == std::string_view::npos) {
      auto ok = append_checked(body.substr(pos));
      if (!ok.has_value())
        return Result<std::string>::failure(ok.error());
      break;
    }

    auto prefix_ok = append_checked(body.substr(pos, open - pos));
    if (!prefix_ok.has_value())
      return Result<std::string>::failure(prefix_ok.error());

    const std::size_t close = body.find("}}", open + 2);
    if (close == std::string_view::npos) {
      auto rest_ok = append_checked(body.substr(open));
      if (!rest_ok.has_value())
        return Result<std::string>::failure(rest_ok.error());
      break;
    }

    const std::string_view token = body.substr(open + 2, close - (open + 2));
    if (declared_params.contains(token)) {
      const auto found = bound_params.find(std::string{token});
      if (found != bound_params.end()) {
        auto val_ok = append_checked(found->second);
        if (!val_ok.has_value())
          return Result<std::string>::failure(val_ok.error());
      }
      // Advance strictly past "}}" so parameter values are never re-scanned.
      pos = close + 2;
    } else {
      // Preserve literal "{{" (e.g., Lua nested tables) and continue scanning.
      auto lit_ok = append_checked("{{");
      if (!lit_ok.has_value())
        return Result<std::string>::failure(lit_ok.error());
      pos = open + 2;
    }
  }

  return Result<std::string>::success(std::move(out));
}

} // namespace

std::string_view capability_kind_name(CapabilityKind kind) noexcept {
  switch (kind) {
  case CapabilityKind::skill:
    return "skill";
  case CapabilityKind::prompt_template:
    return "prompt_template";
  case CapabilityKind::lua_recipe:
    return "lua_recipe";
  case CapabilityKind::api_recipe:
    return "api_recipe";
  }
  return "skill";
}

Result<CapabilityKind> parse_capability_kind(std::string_view name) noexcept {
  if (name == "skill")
    return Result<CapabilityKind>::success(CapabilityKind::skill);
  if (name == "prompt_template")
    return Result<CapabilityKind>::success(CapabilityKind::prompt_template);
  if (name == "lua_recipe")
    return Result<CapabilityKind>::success(CapabilityKind::lua_recipe);
  if (name == "api_recipe")
    return Result<CapabilityKind>::success(CapabilityKind::api_recipe);
  return Result<CapabilityKind>::failure({ErrorCode::invalid_range});
}

std::string_view capability_scope_name(CapabilityScope scope) noexcept {
  switch (scope) {
  case CapabilityScope::project:
    return "project";
  case CapabilityScope::user:
    return "user";
  case CapabilityScope::builtin:
    return "builtin";
  }
  return "project";
}

Result<CapabilityScope> parse_capability_scope(std::string_view name) noexcept {
  if (name == "project")
    return Result<CapabilityScope>::success(CapabilityScope::project);
  if (name == "user")
    return Result<CapabilityScope>::success(CapabilityScope::user);
  if (name == "builtin")
    return Result<CapabilityScope>::success(CapabilityScope::builtin);
  return Result<CapabilityScope>::failure({ErrorCode::invalid_range});
}

std::string_view capability_param_type_name(CapabilityParamType type) noexcept {
  switch (type) {
  case CapabilityParamType::string:
    return "string";
  case CapabilityParamType::integer:
    return "integer";
  case CapabilityParamType::boolean:
    return "boolean";
  case CapabilityParamType::enumeration:
    return "enum";
  }
  return "string";
}

Result<CapabilityParamType>
parse_capability_param_type(std::string_view name) noexcept {
  if (name == "string")
    return Result<CapabilityParamType>::success(CapabilityParamType::string);
  if (name == "integer")
    return Result<CapabilityParamType>::success(CapabilityParamType::integer);
  if (name == "boolean")
    return Result<CapabilityParamType>::success(CapabilityParamType::boolean);
  if (name == "enum")
    return Result<CapabilityParamType>::success(CapabilityParamType::enumeration);
  return Result<CapabilityParamType>::failure({ErrorCode::invalid_range});
}

bool valid_capability_id(std::string_view id) noexcept {
  if (id.empty() || id.size() > kCapabilityMaxIdLength)
    return false;
  if (id.front() == '-')
    return false;
  for (const char ch : id) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

bool valid_capability_param_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > kCapabilityMaxParamNameLength)
    return false;
  if (name.front() == '-')
    return false;
  for (const char ch : name) {
    const bool ok =
        (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
    if (!ok)
      return false;
  }
  return true;
}

std::string capability_sha256_hex(std::string_view bytes) {
  std::array<std::uint32_t, 8> state{
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  const auto *data = reinterpret_cast<const unsigned char *>(bytes.data());
  const std::size_t whole = bytes.size() - (bytes.size() % 64);
  for (std::size_t at = 0; at < whole; at += 64)
    sha256_compress(state, data + at);

  std::array<unsigned char, 128> tail{};
  const std::size_t rest = bytes.size() - whole;
  if (rest > 0)
    std::copy_n(data + whole, rest, tail.begin());
  tail[rest] = 0x80U;
  const std::size_t blocks = rest < 56 ? 1U : 2U;
  const std::uint64_t bit_len = static_cast<std::uint64_t>(bytes.size()) * 8U;
  for (std::size_t i = 0; i < 8; ++i) {
    tail[(blocks * 64) - 1 - i] =
        static_cast<unsigned char>((bit_len >> (8U * i)) & 0xffU);
  }
  for (std::size_t i = 0; i < blocks; ++i)
    sha256_compress(state, tail.data() + (i * 64));

  static constexpr std::string_view kHex = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (const auto word : state) {
    for (int shift = 28; shift >= 0; shift -= 4) {
      out.push_back(kHex[(word >> static_cast<unsigned>(shift)) & 0xfU]);
    }
  }
  return out;
}

std::string compute_capability_sha256(const CapabilityDefinition &definition) {
  std::string canonical;
  canonical.reserve(256 + definition.body.size());
  canonical.append("blackbird.capability.v1\n");
  append_lp(canonical, definition.id);
  append_lp(canonical, capability_kind_name(definition.kind));
  append_lp(canonical, definition.title);
  append_lp(canonical, definition.description);
  append_lp(canonical, definition.body);
  canonical.append("params:");
  canonical.append(std::to_string(definition.params.size()));
  canonical.push_back('\n');
  for (const auto &param : definition.params) {
    append_lp(canonical, param.name);
    append_lp(canonical, capability_param_type_name(param.type));
    canonical.append(param.required ? "req:1\n" : "req:0\n");
    if (param.default_value.has_value()) {
      canonical.append("def:1:");
      append_lp(canonical, *param.default_value);
    } else {
      canonical.append("def:0\n");
    }
    canonical.append("enum:");
    canonical.append(std::to_string(param.allowed_values.size()));
    canonical.push_back('\n');
    for (const auto &entry : param.allowed_values)
      append_lp(canonical, entry);
    append_lp(canonical, param.description);
  }
  return capability_sha256_hex(canonical);
}

std::filesystem::path
default_project_skills_dir(const std::filesystem::path &project_root) {
  return project_root / ".blackbird" / "skills";
}

std::optional<std::filesystem::path> default_user_skills_dir() {
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME");
      xdg != nullptr && xdg[0] != '\0')
    return std::filesystem::path{xdg} / "blackbird" / "skills";
  if (const char *home = std::getenv("HOME"); home != nullptr && home[0] != '\0')
    return std::filesystem::path{home} / ".config" / "blackbird" / "skills";
  return std::nullopt;
}

Value to_value(const CapabilityParam &param) {
  Value::Array allowed;
  allowed.reserve(param.allowed_values.size());
  for (const auto &entry : param.allowed_values)
    allowed.emplace_back(entry);

  Value::Object obj{
      {"name", Value{param.name}},
      {"type", Value{std::string{capability_param_type_name(param.type)}}},
      {"required", Value{param.required}},
      {"default_value",
       param.default_value.has_value() ? Value{*param.default_value} : Value{nullptr}},
      {"allowed_values", Value{std::move(allowed)}},
      {"description", Value{param.description}},
  };
  return Value::object(std::move(obj));
}

Value to_value(const CapabilityShadowed &shadowed) {
  return Value::object({
      {"scope", Value{std::string{capability_scope_name(shadowed.scope)}}},
      {"source_path", Value{shadowed.source_path.string()}},
      {"sha256", Value{shadowed.sha256}},
  });
}

Value to_value(const CapabilityDefinition &definition) {
  Value::Array params;
  params.reserve(definition.params.size());
  for (const auto &param : definition.params)
    params.push_back(to_value(param));

  Value::Array shadowed;
  shadowed.reserve(definition.shadowed.size());
  for (const auto &entry : definition.shadowed)
    shadowed.push_back(to_value(entry));

  return Value::object({
      {"id", Value{definition.id}},
      {"kind", Value{std::string{capability_kind_name(definition.kind)}}},
      {"title", Value{definition.title}},
      {"description", Value{definition.description}},
      {"scope", Value{std::string{capability_scope_name(definition.scope)}}},
      {"source_path", Value{definition.source_path.string()}},
      {"sha256", Value{definition.sha256}},
      {"body", Value{definition.body}},
      {"params", Value{std::move(params)}},
      {"read_only", Value{definition.read_only}},
      {"shadowed", Value{std::move(shadowed)}},
  });
}

Value to_value(const CapabilityResolved &resolved) {
  Value::Object bound;
  bound.reserve(resolved.bound_params.size());
  for (const auto &[key, val] : resolved.bound_params)
    bound.emplace_back(key, Value{val});

  return Value::object({
      {"id", Value{resolved.id}},
      {"kind", Value{std::string{capability_kind_name(resolved.kind)}}},
      {"scope", Value{std::string{capability_scope_name(resolved.scope)}}},
      {"sha256", Value{resolved.sha256}},
      {"bound_params", Value::object(std::move(bound))},
      {"rendered_text", Value{resolved.rendered_text}},
      {"executed", Value{resolved.executed}},
  });
}

Value to_value(const CapabilityListPage &page) {
  Value::Array items;
  items.reserve(page.items.size());
  for (const auto &item : page.items)
    items.push_back(to_value(item));

  Value::Object obj{
      {"total", Value{Number{static_cast<std::uint64_t>(page.total)}}},
      {"offset", Value{Number{static_cast<std::uint64_t>(page.offset)}}},
      {"limit", Value{Number{static_cast<std::uint64_t>(page.limit)}}},
      {"has_more", Value{page.has_more}},
      {"stale", Value{page.stale}},
      {"last_error", page.last_error.has_value()
                         ? Value{std::string{error_name(page.last_error->code)}}
                         : Value{nullptr}},
      {"items", Value{std::move(items)}},
  };
  return Value::object(std::move(obj));
}

Result<std::string> to_json(const CapabilityParam &param) {
  return dump_json(to_value(param));
}

Result<std::string> to_json(const CapabilityDefinition &definition) {
  return dump_json(to_value(definition));
}

Result<std::string> to_json(const CapabilityResolved &resolved) {
  return dump_json(to_value(resolved));
}

Result<std::string> to_json(const CapabilityListPage &page) {
  return dump_json(to_value(page));
}

Result<CapabilityCatalog> CapabilityCatalog::open(CapabilityCatalogConfig config) {
  try {
    if (config.project_dir.has_value() && !valid_scope_dir_path(*config.project_dir))
      return Result<CapabilityCatalog>::failure({ErrorCode::invalid_range});
    if (config.user_dir.has_value() && !valid_scope_dir_path(*config.user_dir))
      return Result<CapabilityCatalog>::failure({ErrorCode::invalid_range});

    std::map<std::string, CapabilityDefinition> normalized_builtins;
    for (auto entry : config.builtins) {
      auto valid = validate_definition(entry);
      if (!valid.has_value())
        return Result<CapabilityCatalog>::failure(valid.error());
      entry.scope = CapabilityScope::builtin;
      entry.read_only = true;
      entry.shadowed.clear();
      entry.sha256 = compute_capability_sha256(entry);
      if (!normalized_builtins.emplace(entry.id, std::move(entry)).second)
        return Result<CapabilityCatalog>::failure({ErrorCode::conflict});
    }

    CapabilityCatalog catalog{std::move(config.project_dir), std::move(config.user_dir),
                              std::move(normalized_builtins)};
    auto initial = catalog.refresh();
    if (!initial.has_value())
      return Result<CapabilityCatalog>::failure(initial.error());
    return Result<CapabilityCatalog>::success(std::move(catalog));
  } catch (const std::bad_alloc &) {
    return Result<CapabilityCatalog>::failure({ErrorCode::allocation});
  }
}

Result<std::map<std::string, CapabilityDefinition>>
CapabilityCatalog::load_all_scopes() const {
  std::map<std::string, CapabilityDefinition> merged;

  if (project_dir_.has_value()) {
    auto loaded = load_scope_directory(*project_dir_, CapabilityScope::project);
    if (!loaded.has_value())
      return Result<std::map<std::string, CapabilityDefinition>>::failure(
          loaded.error());
    for (auto &def : loaded.value())
      merge_definition(merged, std::move(def));
  }

  if (user_dir_.has_value()) {
    auto loaded = load_scope_directory(*user_dir_, CapabilityScope::user);
    if (!loaded.has_value())
      return Result<std::map<std::string, CapabilityDefinition>>::failure(
          loaded.error());
    for (auto &def : loaded.value())
      merge_definition(merged, std::move(def));
  }

  for (const auto &[_, builtin_def] : builtins_)
    merge_definition(merged, builtin_def);

  return Result<std::map<std::string, CapabilityDefinition>>::success(
      std::move(merged));
}

Result<void> CapabilityCatalog::refresh() {
  try {
    auto loaded = load_all_scopes();
    if (!loaded.has_value())
      return Result<void>::failure(loaded.error());
    last_good_ = std::move(loaded).value();
    has_last_good_ = true;
    return Result<void>::success();
  } catch (const std::bad_alloc &) {
    return Result<void>::failure({ErrorCode::allocation});
  }
}

Result<CapabilityListPage> CapabilityCatalog::paginate_map(
    const std::map<std::string, CapabilityDefinition> &source,
    const CapabilityListQuery &query, bool stale,
    std::optional<Error> last_error) const {
  if (query.limit == 0)
    return Result<CapabilityListPage>::failure({ErrorCode::invalid_range});
  if (!valid_text_field(query.text, kCapabilityMaxFieldBytes))
    return Result<CapabilityListPage>::failure({ErrorCode::invalid_range});

  const std::size_t effective_limit = std::min(query.limit, kCapabilityMaxListLimit);
  const std::string needle = ascii_lower(query.text);

  std::vector<const CapabilityDefinition *> matched;
  matched.reserve(source.size());
  for (const auto &[_, def] : source) {
    if (query.kind.has_value() && def.kind != *query.kind)
      continue;
    if (query.scope.has_value() && def.scope != *query.scope)
      continue;
    if (!needle.empty()) {
      const bool hit =
          contains_case_insensitive(def.id, needle) ||
          contains_case_insensitive(def.title, needle) ||
          contains_case_insensitive(def.description, needle) ||
          contains_case_insensitive(capability_kind_name(def.kind), needle);
      if (!hit)
        continue;
    }
    matched.push_back(&def);
  }

  CapabilityListPage page{};
  page.total = matched.size();
  page.offset = query.offset;
  page.limit = effective_limit;
  page.stale = stale;
  page.last_error = last_error;

  if (query.offset < matched.size()) {
    const std::size_t remaining = matched.size() - query.offset;
    const std::size_t take = std::min(remaining, effective_limit);
    page.items.reserve(take);
    for (std::size_t i = 0; i < take; ++i)
      page.items.push_back(*matched[query.offset + i]);
    page.has_more = take < remaining;
  }

  return Result<CapabilityListPage>::success(std::move(page));
}

Result<CapabilityListPage> CapabilityCatalog::list(const CapabilityListQuery &query) {
  try {
    if (query.limit == 0)
      return Result<CapabilityListPage>::failure({ErrorCode::invalid_range});
    if (!valid_text_field(query.text, kCapabilityMaxFieldBytes))
      return Result<CapabilityListPage>::failure({ErrorCode::invalid_range});

    auto loaded = load_all_scopes();
    if (!loaded.has_value()) {
      if (query.allow_stale_on_error && has_last_good_) {
        return paginate_map(last_good_, query, true, loaded.error());
      }
      return Result<CapabilityListPage>::failure(loaded.error());
    }
    last_good_ = std::move(loaded).value();
    has_last_good_ = true;
    return paginate_map(last_good_, query, false, std::nullopt);
  } catch (const std::bad_alloc &) {
    return Result<CapabilityListPage>::failure({ErrorCode::allocation});
  }
}

Result<std::optional<CapabilityDefinition>>
CapabilityCatalog::get(std::string_view id) const {
  if (!valid_capability_id(id))
    return Result<std::optional<CapabilityDefinition>>::failure(
        {ErrorCode::invalid_identity});

  try {
    std::optional<CapabilityDefinition> effective;
    auto consider = [&](CapabilityDefinition candidate) {
      if (!effective.has_value()) {
        effective = std::move(candidate);
      } else {
        effective->shadowed.push_back(CapabilityShadowed{
            candidate.scope,
            std::move(candidate.source_path),
            std::move(candidate.sha256),
        });
      }
    };

    const auto inspect_scope_dir = [&](const std::optional<std::filesystem::path> &dir,
                                       CapabilityScope scope) -> Result<void> {
      if (!dir.has_value())
        return Result<void>::success();
      auto opened = open_existing_scope_dir(*dir);
      if (!opened.has_value())
        return Result<void>::failure(opened.error());
      auto opt_fd = std::move(opened).value();
      if (!opt_fd.has_value())
        return Result<void>::success();
      const FileLoadContext ctx{scope, id, *dir / (std::string{id} + ".json")};
      auto loaded = read_single_from_dir(opt_fd->get(), ctx);
      if (!loaded.has_value())
        return Result<void>::failure(loaded.error());
      auto opt_def = std::move(loaded).value();
      if (opt_def.has_value())
        consider(std::move(*opt_def));
      return Result<void>::success();
    };

    auto project_res = inspect_scope_dir(project_dir_, CapabilityScope::project);
    if (!project_res.has_value())
      return Result<std::optional<CapabilityDefinition>>::failure(project_res.error());

    auto user_res = inspect_scope_dir(user_dir_, CapabilityScope::user);
    if (!user_res.has_value())
      return Result<std::optional<CapabilityDefinition>>::failure(user_res.error());

    if (const auto it = builtins_.find(std::string{id}); it != builtins_.end())
      consider(it->second);

    return Result<std::optional<CapabilityDefinition>>::success(std::move(effective));
  } catch (const std::bad_alloc &) {
    return Result<std::optional<CapabilityDefinition>>::failure(
        {ErrorCode::allocation});
  }
}

Result<CapabilityDefinition>
CapabilityCatalog::save(CapabilityScope scope, const CapabilityDefinition &definition) {
  if (scope == CapabilityScope::builtin)
    return Result<CapabilityDefinition>::failure({ErrorCode::unsupported});

  const std::optional<std::filesystem::path> &target_dir =
      scope == CapabilityScope::project ? project_dir_ : user_dir_;
  if (!target_dir.has_value())
    return Result<CapabilityDefinition>::failure({ErrorCode::unsupported});

  auto valid = validate_definition(definition);
  if (!valid.has_value())
    return Result<CapabilityDefinition>::failure(valid.error());

  try {
    auto opened = open_or_create_scope_dir(*target_dir);
    if (!opened.has_value())
      return Result<CapabilityDefinition>::failure(opened.error());
    ScopedFd dir_fd = std::move(opened).value();

    const std::string filename = definition.id + ".json";
    struct stat existing_st{};
    if (::fstatat(dir_fd.get(), filename.c_str(), &existing_st, AT_SYMLINK_NOFOLLOW) ==
        0) {
      if (!S_ISREG(existing_st.st_mode))
        return Result<CapabilityDefinition>::failure({ErrorCode::io, EPERM});
      const FileLoadContext ctx{scope, definition.id, *target_dir / filename};
      auto existing = read_single_from_dir(dir_fd.get(), ctx);
      if (existing.has_value()) {
        const auto &opt_existing = existing.value();
        if (opt_existing.has_value() && opt_existing->read_only)
          return Result<CapabilityDefinition>::failure({ErrorCode::conflict});
      }
    } else if (errno != ENOENT) {
      return Result<CapabilityDefinition>::failure(native_error(errno));
    }

    CapabilityDefinition stored = definition;
    stored.scope = scope;
    stored.source_path = *target_dir / filename;
    stored.shadowed.clear();
    stored.sha256 = compute_capability_sha256(stored);

    auto written = write_definition_atomic(dir_fd.get(), stored, filename);
    if (!written.has_value())
      return Result<CapabilityDefinition>::failure(written.error());

    // Best-effort refresh of last_good_ snapshot after saving.
    (void)refresh();
    return Result<CapabilityDefinition>::success(std::move(stored));
  } catch (const std::bad_alloc &) {
    return Result<CapabilityDefinition>::failure({ErrorCode::allocation});
  }
}

Result<void> CapabilityCatalog::remove(CapabilityScope scope, std::string_view id) {
  if (scope == CapabilityScope::builtin)
    return Result<void>::failure({ErrorCode::unsupported});
  if (!valid_capability_id(id))
    return Result<void>::failure({ErrorCode::invalid_identity});

  const std::optional<std::filesystem::path> &target_dir =
      scope == CapabilityScope::project ? project_dir_ : user_dir_;
  if (!target_dir.has_value())
    return Result<void>::failure({ErrorCode::unsupported});

  try {
    auto opened = open_existing_scope_dir(*target_dir);
    if (!opened.has_value())
      return Result<void>::failure(opened.error());
    auto opt_fd = std::move(opened).value();
    if (!opt_fd.has_value())
      return Result<void>::failure({ErrorCode::invalid_identity, ENOENT});

    const std::string filename = std::string{id} + ".json";
    struct stat st{};
    if (::fstatat(opt_fd->get(), filename.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
      if (errno == ENOENT)
        return Result<void>::failure({ErrorCode::invalid_identity, ENOENT});
      return Result<void>::failure(native_error(errno));
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() || (st.st_mode & 0022) != 0)
      return Result<void>::failure({ErrorCode::io, EPERM});

    const FileLoadContext ctx{scope, id, *target_dir / filename};
    auto existing = read_single_from_dir(opt_fd->get(), ctx);
    if (existing.has_value()) {
      const auto &opt_existing = existing.value();
      if (opt_existing.has_value() && opt_existing->read_only)
        return Result<void>::failure({ErrorCode::conflict});
    }

    if (::unlinkat(opt_fd->get(), filename.c_str(), 0) != 0)
      return Result<void>::failure(native_error(errno));
    auto synced = fsync_fd(opt_fd->get());
    if (!synced.has_value())
      return synced;

    (void)refresh();
    return Result<void>::success();
  } catch (const std::bad_alloc &) {
    return Result<void>::failure({ErrorCode::allocation});
  }
}

Result<CapabilityResolved>
CapabilityCatalog::resolve(std::string_view id,
                           const std::map<std::string, std::string> &args,
                           std::optional<std::string_view> expected_sha256) const {
  auto fetched = get(id);
  if (!fetched.has_value())
    return Result<CapabilityResolved>::failure(fetched.error());
  auto opt_def = std::move(fetched).value();
  if (!opt_def.has_value())
    return Result<CapabilityResolved>::failure({ErrorCode::invalid_identity, ENOENT});

  const CapabilityDefinition &def = *opt_def;
  if (expected_sha256.has_value() && *expected_sha256 != def.sha256)
    return Result<CapabilityResolved>::failure({ErrorCode::conflict});

  try {
    std::set<std::string_view> declared_params;
    for (const auto &param : def.params)
      declared_params.insert(param.name);

    // Reject unknown arguments and invalid UTF-8 / NUL / oversized values.
    for (const auto &[key, val] : args) {
      if (!declared_params.contains(key))
        return Result<CapabilityResolved>::failure({ErrorCode::invalid_range});
      if (!valid_text_field(val, kCapabilityMaxFieldBytes))
        return Result<CapabilityResolved>::failure({ErrorCode::invalid_range});
    }

    std::map<std::string, std::string> bound_params;
    for (const auto &param : def.params) {
      std::optional<std::string_view> chosen;
      if (const auto it = args.find(param.name); it != args.end()) {
        chosen = it->second;
      } else if (param.default_value.has_value()) {
        chosen = *param.default_value;
      } else if (param.required) {
        return Result<CapabilityResolved>::failure({ErrorCode::invalid_range});
      }

      if (chosen.has_value()) {
        auto valid = validate_param_value(param, *chosen);
        if (!valid.has_value())
          return Result<CapabilityResolved>::failure(valid.error());
        bound_params.emplace(param.name, std::string{*chosen});
      }
    }

    auto rendered = render_template_single_pass(def, bound_params, declared_params);
    if (!rendered.has_value())
      return Result<CapabilityResolved>::failure(rendered.error());

    CapabilityResolved out{};
    out.id = def.id;
    out.kind = def.kind;
    out.scope = def.scope;
    out.sha256 = def.sha256;
    out.bound_params = std::move(bound_params);
    out.rendered_text = std::move(rendered).value();
    out.executed = false;
    return Result<CapabilityResolved>::success(std::move(out));
  } catch (const std::bad_alloc &) {
    return Result<CapabilityResolved>::failure({ErrorCode::allocation});
  }
}

} // namespace blackbird
