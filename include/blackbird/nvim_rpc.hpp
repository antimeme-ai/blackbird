#pragma once

#include "blackbird/foundation.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace blackbird {

enum class NvimRpcError : std::int64_t {
  none = 0,
  msgpack_incomplete = 4000,
  msgpack_corrupt = 4001,
  msgpack_trailing_bytes = 4002,
  msgpack_depth_exceeded = 4003,
  msgpack_bytes_exceeded = 4004,
  msgpack_elements_exceeded = 4005,
  msgpack_invalid_format = 4006,
  invalid_argument = 4010,
  unsafe_script_rejected = 4011,
  spawn_failed = 4020,
  pipe_failed = 4021,
  not_connected = 4022,
  io_failed = 4023,
  timeout = 4024,
  eof = 4025,
  protocol_violation = 4026,
  rpc_remote_error = 4027,
  treesitter_error = 4028,
};

constexpr NvimRpcError nvim_rpc_error_of(const Error &error) noexcept {
  return static_cast<NvimRpcError>(error.detail);
}

std::string_view nvim_rpc_error_name(NvimRpcError detail) noexcept;

inline constexpr std::size_t kMsgPackDefaultMaxDepth = 32U;
inline constexpr std::size_t kMsgPackDefaultMaxBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kMsgPackDefaultMaxElements = 65536U;

struct MsgPackLimits {
  std::size_t max_depth = kMsgPackDefaultMaxDepth;
  std::size_t max_bytes = kMsgPackDefaultMaxBytes;
  std::size_t max_elements = kMsgPackDefaultMaxElements;
};

struct MsgPackExt {
  std::int8_t type = 0;
  std::vector<std::uint8_t> data;

  bool operator==(const MsgPackExt &) const = default;
};

struct MsgPackValue;
struct MsgPackMapEntry;

struct MsgPackArray {
  std::vector<MsgPackValue> items;

  MsgPackArray();
  explicit MsgPackArray(std::vector<MsgPackValue> values);
  MsgPackArray(const MsgPackArray &other);
  MsgPackArray &operator=(const MsgPackArray &other);
  MsgPackArray(MsgPackArray &&other) noexcept;
  MsgPackArray &operator=(MsgPackArray &&other) noexcept;
  ~MsgPackArray();

  std::size_t size() const noexcept;
  bool empty() const noexcept;
  void push_back(MsgPackValue value);
  MsgPackValue &operator[](std::size_t index);
  const MsgPackValue &operator[](std::size_t index) const;
  bool operator==(const MsgPackArray &other) const;
};

struct MsgPackMap {
  std::vector<MsgPackMapEntry> entries;

  MsgPackMap();
  explicit MsgPackMap(std::vector<MsgPackMapEntry> values);
  MsgPackMap(const MsgPackMap &other);
  MsgPackMap &operator=(const MsgPackMap &other);
  MsgPackMap(MsgPackMap &&other) noexcept;
  MsgPackMap &operator=(MsgPackMap &&other) noexcept;
  ~MsgPackMap();

  std::size_t size() const noexcept;
  bool empty() const noexcept;
  void push_back(MsgPackMapEntry entry);
  const MsgPackValue *find(std::string_view key) const noexcept;
  bool operator==(const MsgPackMap &other) const;
};

struct MsgPackValue {
  using Bin = std::vector<std::uint8_t>;
  using Storage =
      std::variant<std::monostate, bool, std::int64_t, std::uint64_t, double,
                   std::string, Bin, MsgPackArray, MsgPackMap, MsgPackExt>;

  Storage data;

  MsgPackValue() : data(std::monostate{}) {}
  explicit MsgPackValue(std::monostate) : data(std::monostate{}) {}
  explicit MsgPackValue(bool value) : data(value) {}
  explicit MsgPackValue(std::int64_t value) : data(value) {}
  explicit MsgPackValue(std::uint64_t value) : data(value) {}
  explicit MsgPackValue(double value) : data(value) {}
  explicit MsgPackValue(std::string value) : data(std::move(value)) {}
  explicit MsgPackValue(std::string_view value) : data(std::string{value}) {}
  explicit MsgPackValue(const char *value)
      : data(std::string{value != nullptr ? value : ""}) {}
  explicit MsgPackValue(Bin value) : data(std::move(value)) {}
  explicit MsgPackValue(MsgPackArray value) : data(std::move(value)) {}
  explicit MsgPackValue(MsgPackMap value) : data(std::move(value)) {}
  explicit MsgPackValue(MsgPackExt value) : data(std::move(value)) {}

  static MsgPackValue nil() { return MsgPackValue{}; }
  static MsgPackValue boolean(bool value) { return MsgPackValue{value}; }
  static MsgPackValue int64(std::int64_t value) { return MsgPackValue{value}; }
  static MsgPackValue uint64(std::uint64_t value) { return MsgPackValue{value}; }
  static MsgPackValue number(double value) { return MsgPackValue{value}; }
  static MsgPackValue string(std::string value) {
    return MsgPackValue{std::move(value)};
  }
  static MsgPackValue bin(Bin value) { return MsgPackValue{std::move(value)}; }
  static MsgPackValue array();
  static MsgPackValue array(std::vector<MsgPackValue> values);
  static MsgPackValue map();
  static MsgPackValue map(std::vector<MsgPackMapEntry> values);
  static MsgPackValue ext(std::int8_t type, Bin payload) {
    return MsgPackValue{MsgPackExt{type, std::move(payload)}};
  }

  bool is_nil() const noexcept { return std::holds_alternative<std::monostate>(data); }
  bool is_bool() const noexcept { return std::holds_alternative<bool>(data); }
  bool is_int64() const noexcept { return std::holds_alternative<std::int64_t>(data); }
  bool is_uint64() const noexcept {
    return std::holds_alternative<std::uint64_t>(data);
  }
  bool is_double() const noexcept { return std::holds_alternative<double>(data); }
  bool is_string() const noexcept { return std::holds_alternative<std::string>(data); }
  bool is_bin() const noexcept { return std::holds_alternative<Bin>(data); }
  bool is_array() const noexcept { return std::holds_alternative<MsgPackArray>(data); }
  bool is_map() const noexcept { return std::holds_alternative<MsgPackMap>(data); }
  bool is_ext() const noexcept { return std::holds_alternative<MsgPackExt>(data); }

  std::optional<bool> as_bool() const noexcept;
  std::optional<std::int64_t> as_int64() const noexcept;
  std::optional<std::uint64_t> as_uint64() const noexcept;
  std::optional<double> as_double() const noexcept;
  const std::string *as_string() const noexcept;
  const Bin *as_bin() const noexcept;
  const MsgPackArray *as_array() const noexcept;
  const MsgPackMap *as_map() const noexcept;
  const MsgPackExt *as_ext() const noexcept;

  bool operator==(const MsgPackValue &other) const = default;
};

struct MsgPackMapEntry {
  MsgPackValue key;
  MsgPackValue value;

  bool operator==(const MsgPackMapEntry &) const = default;
};

struct MsgPackDecodeStep {
  MsgPackValue value;
  std::size_t consumed = 0;
};

// Encodes a MsgPackValue to canonical compact MessagePack wire bytes.
Result<std::vector<std::uint8_t>> encode_msgpack(const MsgPackValue &value,
                                                 MsgPackLimits limits = {});

// Decodes a single complete MessagePack value from bytes (rejects trailing bytes).
Result<MsgPackValue> decode_msgpack(std::span<const std::uint8_t> bytes,
                                    MsgPackLimits limits = {});

// Decodes the first MessagePack value from a stream prefix, reporting exact bytes
// consumed. Returns ErrorCode::incomplete (NvimRpcError::msgpack_incomplete) when
// more bytes are needed.
Result<MsgPackDecodeStep> decode_msgpack_next(std::span<const std::uint8_t> bytes,
                                              MsgPackLimits limits = {});

struct NvimProbeOptions {
  std::string executable = "nvim";
  std::chrono::milliseconds timeout{5000};
  std::vector<std::filesystem::path> extra_runtimepaths;
};

struct NvimCapabilities {
  bool available = false;
  std::string executable_path;
  std::string version_string;
  int version_major = 0;
  int version_minor = 0;
  int version_patch = 0;
  bool has_treesitter = false;
  bool has_vim_diff = false;
  std::vector<std::string> treesitter_parsers;
  std::string diagnostic;

  bool operator==(const NvimCapabilities &) const = default;
};

// Passive capability probe: spawns a short-lived `nvim --headless --embed --clean -n`,
// inspects version, vim.treesitter, vim.diff, and bundled parsers, and shuts down
// cleanly with zero disk writes. Returns available=false gracefully if nvim is absent.
NvimCapabilities probe_nvim_capabilities(const NvimProbeOptions &options = {});

struct NvimScriptValidation {
  bool allowed = false;
  std::string reason;
};

// Validates a scratch_edit Lua or Ex script against the audit-safety policy before
// sending it to headless Neovim.
NvimScriptValidation validate_scratch_script(std::string_view script, bool is_lua);

struct NvimAstCapture {
  std::string capture_name;
  std::string node_type;
  std::uint32_t start_row = 0;
  std::uint32_t start_col = 0;
  std::uint32_t end_row = 0;
  std::uint32_t end_col = 0;
  std::string text;

  bool operator==(const NvimAstCapture &) const = default;
};

struct NvimAstQueryRequest {
  std::string language;
  std::string source_text;
  std::string treesitter_query;
  std::size_t max_captures = 4096U;
  std::optional<std::chrono::milliseconds> timeout;
};

struct NvimScratchEditRequest {
  std::string source_text;
  std::string script;
  bool is_lua = true;
  std::optional<std::chrono::milliseconds> timeout;
};

struct NvimEditProposal {
  std::size_t original_lines_count = 0;
  std::string proposed_text;
  std::string unified_diff;
  bool changed = false;

  bool operator==(const NvimEditProposal &) const = default;
};

struct NvimNotification {
  std::string method;
  std::vector<MsgPackValue> params;

  bool operator==(const NvimNotification &) const = default;
};

struct NvimClientOptions {
  std::string executable = "nvim";
  std::optional<std::filesystem::path> working_directory;
  std::chrono::milliseconds default_timeout{5000};
  std::chrono::milliseconds shutdown_grace{1000};
  MsgPackLimits msgpack_limits{};
  std::vector<std::filesystem::path> extra_runtimepaths;
};

// Owned C++23 MsgPack-RPC v1 client driving `nvim --headless --embed --clean -n` over
// stdin/stdout pipes. Never mutates files on disk; edits are staged in isolated
// buftype=nofile scratch buffers and returned as unified-diff proposals.
class NvimRpcClient {
public:
  static Result<NvimRpcClient> spawn(NvimClientOptions options = {});

  NvimRpcClient(const NvimRpcClient &) = delete;
  NvimRpcClient &operator=(const NvimRpcClient &) = delete;
  NvimRpcClient(NvimRpcClient &&other) noexcept;
  NvimRpcClient &operator=(NvimRpcClient &&other) noexcept;
  ~NvimRpcClient();

  bool is_open() const noexcept;
  std::int64_t child_pid() const noexcept;
  const std::string &last_error_message() const noexcept;

  Result<MsgPackValue>
  call(std::string_view method, std::vector<MsgPackValue> params = {},
       std::optional<std::chrono::milliseconds> timeout = std::nullopt);

  Result<void> notify(std::string_view method, std::vector<MsgPackValue> params = {},
                      std::optional<std::chrono::milliseconds> timeout = std::nullopt);

  Result<MsgPackValue>
  nvim_eval(std::string_view expr,
            std::optional<std::chrono::milliseconds> timeout = std::nullopt);

  Result<MsgPackValue>
  nvim_exec_lua(std::string_view code, std::vector<MsgPackValue> args = {},
                std::optional<std::chrono::milliseconds> timeout = std::nullopt);

  Result<void>
  nvim_command(std::string_view command,
               std::optional<std::chrono::milliseconds> timeout = std::nullopt);

  Result<std::vector<NvimAstCapture>> ast_query(const NvimAstQueryRequest &request);

  Result<NvimEditProposal> scratch_edit(const NvimScratchEditRequest &request);

  std::vector<NvimNotification> drain_notifications();

  void close() noexcept;

private:
  struct Impl;
  explicit NvimRpcClient(std::unique_ptr<Impl> impl) noexcept;

  std::unique_ptr<Impl> impl_;
};

} // namespace blackbird
