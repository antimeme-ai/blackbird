#include "blackbird/nvim_rpc.hpp"
#include "blackbird/process_lifetime.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <poll.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#ifndef F_SETNOSIGPIPE
#include <pthread.h>
#endif

extern char **environ;

namespace blackbird {

namespace {

using SteadyClock = std::chrono::steady_clock;

constexpr std::size_t kMaxScriptBytes = 256U * 1024U;
constexpr std::size_t kMaxQueuedNotifications = 256U;
constexpr std::size_t kReadChunkBytes = 16384U;
constexpr std::size_t kCompactThresholdBytes = 4096U;
constexpr std::size_t kMaxLanguageNameBytes = 64U;

Error make_rpc_error(ErrorCode code, NvimRpcError detail) noexcept {
  return Error{code, static_cast<std::int64_t>(detail)};
}

#ifndef F_SETNOSIGPIPE
class PipeSignalGuard {
public:
  PipeSignalGuard() noexcept {
    sigemptyset(&blocked_);
    sigaddset(&blocked_, SIGPIPE);
    if (::pthread_sigmask(SIG_BLOCK, &blocked_, &previous_) == 0) {
      active_ = true;
      sigset_t pending{};
      if (::sigpending(&pending) == 0) {
        was_pending_ = (::sigismember(&pending, SIGPIPE) == 1);
      }
    }
  }

  PipeSignalGuard(const PipeSignalGuard &) = delete;
  PipeSignalGuard &operator=(const PipeSignalGuard &) = delete;

  ~PipeSignalGuard() {
    if (!active_) {
      return;
    }
    if (!was_pending_) {
      timespec zero{};
      while (::sigtimedwait(&blocked_, nullptr, &zero) < 0 && errno == EINTR) {
      }
    }
    (void)::pthread_sigmask(SIG_SETMASK, &previous_, nullptr);
  }

private:
  sigset_t blocked_{};
  sigset_t previous_{};
  bool active_ = false;
  bool was_pending_ = false;
};
#endif

// ============================================================================
// MsgPack Encoder
// ============================================================================

struct EncodeState {
  std::vector<std::uint8_t> out;
  MsgPackLimits limits;
  std::size_t depth = 0;
  std::size_t elements = 0;

  Result<void> reserve_extra(std::size_t count) {
    if (count > limits.max_bytes || out.size() > limits.max_bytes - count) {
      return Result<void>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
    }
    return Result<void>::success();
  }

  Result<void> push_u8(std::uint8_t value) {
    auto ok = reserve_extra(1U);
    if (!ok.has_value()) {
      return ok;
    }
    out.push_back(value);
    return Result<void>::success();
  }

  Result<void> push_u16_be(std::uint16_t value) {
    auto ok = reserve_extra(2U);
    if (!ok.has_value()) {
      return ok;
    }
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
    return Result<void>::success();
  }

  Result<void> push_u32_be(std::uint32_t value) {
    auto ok = reserve_extra(4U);
    if (!ok.has_value()) {
      return ok;
    }
    out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
    return Result<void>::success();
  }

  Result<void> push_u64_be(std::uint64_t value) {
    auto ok = reserve_extra(8U);
    if (!ok.has_value()) {
      return ok;
    }
    for (int shift = 56; shift >= 0; shift -= 8) {
      out.push_back(
          static_cast<std::uint8_t>((value >> static_cast<unsigned>(shift)) & 0xffU));
    }
    return Result<void>::success();
  }

  Result<void> push_bytes(std::span<const std::uint8_t> bytes) {
    auto ok = reserve_extra(bytes.size());
    if (!ok.has_value()) {
      return ok;
    }
    out.insert(out.end(), bytes.begin(), bytes.end());
    return Result<void>::success();
  }

  Result<void> encode_uint(std::uint64_t value) {
    if (value <= 0x7fU) {
      return push_u8(static_cast<std::uint8_t>(value));
    }
    if (value <= 0xffU) {
      auto r = push_u8(0xccU);
      if (!r.has_value()) {
        return r;
      }
      return push_u8(static_cast<std::uint8_t>(value));
    }
    if (value <= 0xffffU) {
      auto r = push_u8(0xcdU);
      if (!r.has_value()) {
        return r;
      }
      return push_u16_be(static_cast<std::uint16_t>(value));
    }
    if (value <= 0xffffffffULL) {
      auto r = push_u8(0xceU);
      if (!r.has_value()) {
        return r;
      }
      return push_u32_be(static_cast<std::uint32_t>(value));
    }
    auto r = push_u8(0xcfU);
    if (!r.has_value()) {
      return r;
    }
    return push_u64_be(value);
  }

  Result<void> encode_int(std::int64_t value) {
    if (value >= 0) {
      return encode_uint(static_cast<std::uint64_t>(value));
    }
    if (value >= -32) {
      const auto narrow = static_cast<std::int8_t>(value);
      return push_u8(std::bit_cast<std::uint8_t>(narrow));
    }
    if (value >= -128) {
      auto r = push_u8(0xd0U);
      if (!r.has_value()) {
        return r;
      }
      const auto narrow = static_cast<std::int8_t>(value);
      return push_u8(std::bit_cast<std::uint8_t>(narrow));
    }
    if (value >= -32768) {
      auto r = push_u8(0xd1U);
      if (!r.has_value()) {
        return r;
      }
      const auto narrow = static_cast<std::int16_t>(value);
      return push_u16_be(std::bit_cast<std::uint16_t>(narrow));
    }
    if (value >= -2147483648LL) {
      auto r = push_u8(0xd2U);
      if (!r.has_value()) {
        return r;
      }
      const auto narrow = static_cast<std::int32_t>(value);
      return push_u32_be(std::bit_cast<std::uint32_t>(narrow));
    }
    auto r = push_u8(0xd3U);
    if (!r.has_value()) {
      return r;
    }
    return push_u64_be(std::bit_cast<std::uint64_t>(value));
  }

  Result<void> encode_value(const MsgPackValue &value) {
    if (elements >= limits.max_elements) {
      return Result<void>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_elements_exceeded));
    }
    ++elements;

    if (value.is_nil()) {
      return push_u8(0xc0U);
    }
    if (const auto b = value.as_bool(); b.has_value()) {
      return push_u8(*b ? 0xc3U : 0xc2U);
    }
    if (value.is_int64()) {
      return encode_int(std::get<std::int64_t>(value.data));
    }
    if (value.is_uint64()) {
      return encode_uint(std::get<std::uint64_t>(value.data));
    }
    if (value.is_double()) {
      auto r = push_u8(0xcbU);
      if (!r.has_value()) {
        return r;
      }
      return push_u64_be(std::bit_cast<std::uint64_t>(std::get<double>(value.data)));
    }
    if (const auto *str = value.as_string(); str != nullptr) {
      const std::size_t len = str->size();
      if (len <= 31U) {
        auto r = push_u8(static_cast<std::uint8_t>(0xa0U | len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffU) {
        auto r = push_u8(0xd9U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u8(static_cast<std::uint8_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffffU) {
        auto r = push_u8(0xdaU);
        if (!r.has_value()) {
          return r;
        }
        r = push_u16_be(static_cast<std::uint16_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffffffffULL) {
        auto r = push_u8(0xdbU);
        if (!r.has_value()) {
          return r;
        }
        r = push_u32_be(static_cast<std::uint32_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else {
        return Result<void>::failure(
            make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
      }
      auto ok = reserve_extra(len);
      if (!ok.has_value()) {
        return ok;
      }
      for (const char ch : *str) {
        out.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(ch)));
      }
      return Result<void>::success();
    }
    if (const auto *bin = value.as_bin(); bin != nullptr) {
      const std::size_t len = bin->size();
      if (len <= 0xffU) {
        auto r = push_u8(0xc4U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u8(static_cast<std::uint8_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffffU) {
        auto r = push_u8(0xc5U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u16_be(static_cast<std::uint16_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffffffffULL) {
        auto r = push_u8(0xc6U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u32_be(static_cast<std::uint32_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else {
        return Result<void>::failure(
            make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
      }
      return push_bytes(*bin);
    }
    if (const auto *ext = value.as_ext(); ext != nullptr) {
      const std::size_t len = ext->data.size();
      const auto type_byte = std::bit_cast<std::uint8_t>(ext->type);
      if (len == 1U) {
        auto r = push_u8(0xd4U);
        if (!r.has_value()) {
          return r;
        }
      } else if (len == 2U) {
        auto r = push_u8(0xd5U);
        if (!r.has_value()) {
          return r;
        }
      } else if (len == 4U) {
        auto r = push_u8(0xd6U);
        if (!r.has_value()) {
          return r;
        }
      } else if (len == 8U) {
        auto r = push_u8(0xd7U);
        if (!r.has_value()) {
          return r;
        }
      } else if (len == 16U) {
        auto r = push_u8(0xd8U);
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffU) {
        auto r = push_u8(0xc7U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u8(static_cast<std::uint8_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffffU) {
        auto r = push_u8(0xc8U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u16_be(static_cast<std::uint16_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else if (len <= 0xffffffffULL) {
        auto r = push_u8(0xc9U);
        if (!r.has_value()) {
          return r;
        }
        r = push_u32_be(static_cast<std::uint32_t>(len));
        if (!r.has_value()) {
          return r;
        }
      } else {
        return Result<void>::failure(
            make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
      }
      auto r = push_u8(type_byte);
      if (!r.has_value()) {
        return r;
      }
      return push_bytes(ext->data);
    }
    if (const auto *arr = value.as_array(); arr != nullptr) {
      if (depth >= limits.max_depth) {
        return Result<void>::failure(
            make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_depth_exceeded));
      }
      const std::size_t count = arr->items.size();
      if (count <= 15U) {
        auto r = push_u8(static_cast<std::uint8_t>(0x90U | count));
        if (!r.has_value()) {
          return r;
        }
      } else if (count <= 0xffffU) {
        auto r = push_u8(0xdcU);
        if (!r.has_value()) {
          return r;
        }
        r = push_u16_be(static_cast<std::uint16_t>(count));
        if (!r.has_value()) {
          return r;
        }
      } else if (count <= 0xffffffffULL) {
        auto r = push_u8(0xddU);
        if (!r.has_value()) {
          return r;
        }
        r = push_u32_be(static_cast<std::uint32_t>(count));
        if (!r.has_value()) {
          return r;
        }
      } else {
        return Result<void>::failure(make_rpc_error(
            ErrorCode::capacity, NvimRpcError::msgpack_elements_exceeded));
      }
      ++depth;
      for (const auto &item : arr->items) {
        auto r = encode_value(item);
        if (!r.has_value()) {
          --depth;
          return r;
        }
      }
      --depth;
      return Result<void>::success();
    }
    if (const auto *map = value.as_map(); map != nullptr) {
      if (depth >= limits.max_depth) {
        return Result<void>::failure(
            make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_depth_exceeded));
      }
      const std::size_t count = map->entries.size();
      if (count <= 15U) {
        auto r = push_u8(static_cast<std::uint8_t>(0x80U | count));
        if (!r.has_value()) {
          return r;
        }
      } else if (count <= 0xffffU) {
        auto r = push_u8(0xdeU);
        if (!r.has_value()) {
          return r;
        }
        r = push_u16_be(static_cast<std::uint16_t>(count));
        if (!r.has_value()) {
          return r;
        }
      } else if (count <= 0xffffffffULL) {
        auto r = push_u8(0xdfU);
        if (!r.has_value()) {
          return r;
        }
        r = push_u32_be(static_cast<std::uint32_t>(count));
        if (!r.has_value()) {
          return r;
        }
      } else {
        return Result<void>::failure(make_rpc_error(
            ErrorCode::capacity, NvimRpcError::msgpack_elements_exceeded));
      }
      ++depth;
      for (const auto &entry : map->entries) {
        auto kr = encode_value(entry.key);
        if (!kr.has_value()) {
          --depth;
          return kr;
        }
        auto vr = encode_value(entry.value);
        if (!vr.has_value()) {
          --depth;
          return vr;
        }
      }
      --depth;
      return Result<void>::success();
    }

    return Result<void>::failure(
        make_rpc_error(ErrorCode::corrupt, NvimRpcError::msgpack_invalid_format));
  }
};

// ============================================================================
// MsgPack Decoder (Fuzz-Hardened)
// ============================================================================

struct DecodeState {
  std::span<const std::uint8_t> bytes;
  MsgPackLimits limits;
  std::size_t pos = 0;
  std::size_t depth = 0;
  std::size_t elements = 0;

  std::size_t remaining() const noexcept { return bytes.size() - pos; }

  Result<void> check_byte_budget(std::size_t needed) const noexcept {
    if (needed > limits.max_bytes || pos > limits.max_bytes - needed) {
      return Result<void>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
    }
    if (needed > remaining()) {
      return Result<void>::failure(
          make_rpc_error(ErrorCode::incomplete, NvimRpcError::msgpack_incomplete));
    }
    return Result<void>::success();
  }

  Result<std::uint8_t> read_u8() noexcept {
    auto ok = check_byte_budget(1U);
    if (!ok.has_value()) {
      return Result<std::uint8_t>::failure(ok.error());
    }
    return Result<std::uint8_t>::success(bytes[pos++]);
  }

  Result<std::uint16_t> read_u16_be() noexcept {
    auto ok = check_byte_budget(2U);
    if (!ok.has_value()) {
      return Result<std::uint16_t>::failure(ok.error());
    }
    const auto b0 = static_cast<std::uint16_t>(bytes[pos]);
    const auto b1 = static_cast<std::uint16_t>(bytes[pos + 1U]);
    pos += 2U;
    return Result<std::uint16_t>::success(static_cast<std::uint16_t>((b0 << 8U) | b1));
  }

  Result<std::uint32_t> read_u32_be() noexcept {
    auto ok = check_byte_budget(4U);
    if (!ok.has_value()) {
      return Result<std::uint32_t>::failure(ok.error());
    }
    const auto value = (static_cast<std::uint32_t>(bytes[pos]) << 24U) |
                       (static_cast<std::uint32_t>(bytes[pos + 1U]) << 16U) |
                       (static_cast<std::uint32_t>(bytes[pos + 2U]) << 8U) |
                       static_cast<std::uint32_t>(bytes[pos + 3U]);
    pos += 4U;
    return Result<std::uint32_t>::success(value);
  }

  Result<std::uint64_t> read_u64_be() noexcept {
    auto ok = check_byte_budget(8U);
    if (!ok.has_value()) {
      return Result<std::uint64_t>::failure(ok.error());
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8U; ++i) {
      value = (value << 8U) | static_cast<std::uint64_t>(bytes[pos + i]);
    }
    pos += 8U;
    return Result<std::uint64_t>::success(value);
  }

  Result<std::string> read_string_payload(std::size_t len) {
    auto ok = check_byte_budget(len);
    if (!ok.has_value()) {
      return Result<std::string>::failure(ok.error());
    }
    std::string out;
    out.resize(len);
    if (len > 0U) {
      std::memcpy(out.data(), bytes.data() + pos, len);
      pos += len;
    }
    return Result<std::string>::success(std::move(out));
  }

  Result<MsgPackValue::Bin> read_bin_payload(std::size_t len) {
    auto ok = check_byte_budget(len);
    if (!ok.has_value()) {
      return Result<MsgPackValue::Bin>::failure(ok.error());
    }
    MsgPackValue::Bin out;
    out.resize(len);
    if (len > 0U) {
      std::memcpy(out.data(), bytes.data() + pos, len);
      pos += len;
    }
    return Result<MsgPackValue::Bin>::success(std::move(out));
  }

  Result<MsgPackValue> read_ext(std::size_t len) {
    if (limits.max_bytes == 0U || pos >= limits.max_bytes ||
        len > limits.max_bytes - pos - 1U) {
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
    }
    auto type_res = read_u8();
    if (!type_res.has_value()) {
      return Result<MsgPackValue>::failure(type_res.error());
    }
    auto payload_res = read_bin_payload(len);
    if (!payload_res.has_value()) {
      return Result<MsgPackValue>::failure(payload_res.error());
    }
    return Result<MsgPackValue>::success(MsgPackValue::ext(
        std::bit_cast<std::int8_t>(type_res.value()), std::move(payload_res.value())));
  }

  Result<MsgPackValue> read_array(std::size_t count) {
    if (depth >= limits.max_depth) {
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_depth_exceeded));
    }
    if (count > limits.max_elements - elements) {
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_elements_exceeded));
    }
    std::vector<MsgPackValue> items;
    items.reserve(std::min<std::size_t>(count, remaining()));
    ++depth;
    for (std::size_t i = 0; i < count; ++i) {
      auto item = decode_value();
      if (!item.has_value()) {
        --depth;
        return Result<MsgPackValue>::failure(item.error());
      }
      items.push_back(std::move(item.value()));
    }
    --depth;
    return Result<MsgPackValue>::success(MsgPackValue::array(std::move(items)));
  }

  Result<MsgPackValue> read_map(std::size_t count) {
    if (depth >= limits.max_depth) {
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_depth_exceeded));
    }
    if (count > (limits.max_elements - elements) / 2U) {
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_elements_exceeded));
    }
    std::vector<MsgPackMapEntry> entries;
    entries.reserve(std::min<std::size_t>(count, remaining() / 2U));
    ++depth;
    for (std::size_t i = 0; i < count; ++i) {
      auto key = decode_value();
      if (!key.has_value()) {
        --depth;
        return Result<MsgPackValue>::failure(key.error());
      }
      auto val = decode_value();
      if (!val.has_value()) {
        --depth;
        return Result<MsgPackValue>::failure(val.error());
      }
      entries.push_back(
          MsgPackMapEntry{std::move(key.value()), std::move(val.value())});
    }
    --depth;
    return Result<MsgPackValue>::success(MsgPackValue::map(std::move(entries)));
  }

  Result<MsgPackValue> decode_value() {
    if (elements >= limits.max_elements) {
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_elements_exceeded));
    }
    ++elements;

    auto tag_res = read_u8();
    if (!tag_res.has_value()) {
      return Result<MsgPackValue>::failure(tag_res.error());
    }
    const std::uint8_t tag = tag_res.value();

    // Positive fixint: 0x00 .. 0x7f
    if (tag <= 0x7fU) {
      return Result<MsgPackValue>::success(
          MsgPackValue::uint64(static_cast<std::uint64_t>(tag)));
    }
    // Fixmap: 0x80 .. 0x8f
    if (tag <= 0x8fU) {
      return read_map(static_cast<std::size_t>(tag & 0x0fU));
    }
    // Fixarray: 0x90 .. 0x9f
    if (tag <= 0x9fU) {
      return read_array(static_cast<std::size_t>(tag & 0x0fU));
    }
    // Fixstr: 0xa0 .. 0xbf
    if (tag <= 0xbfU) {
      auto str = read_string_payload(static_cast<std::size_t>(tag & 0x1fU));
      if (!str.has_value()) {
        return Result<MsgPackValue>::failure(str.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::string(std::move(str.value())));
    }
    // Negative fixint: 0xe0 .. 0xff
    if (tag >= 0xe0U) {
      const auto signed_val = std::bit_cast<std::int8_t>(tag);
      return Result<MsgPackValue>::success(
          MsgPackValue::int64(static_cast<std::int64_t>(signed_val)));
    }

    switch (tag) {
    case 0xc0U:
      return Result<MsgPackValue>::success(MsgPackValue::nil());
    case 0xc1U:
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::corrupt, NvimRpcError::msgpack_invalid_format));
    case 0xc2U:
      return Result<MsgPackValue>::success(MsgPackValue::boolean(false));
    case 0xc3U:
      return Result<MsgPackValue>::success(MsgPackValue::boolean(true));
    case 0xc4U: {
      auto len = read_u8();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      auto bin = read_bin_payload(len.value());
      if (!bin.has_value()) {
        return Result<MsgPackValue>::failure(bin.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::bin(std::move(bin.value())));
    }
    case 0xc5U: {
      auto len = read_u16_be();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      auto bin = read_bin_payload(len.value());
      if (!bin.has_value()) {
        return Result<MsgPackValue>::failure(bin.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::bin(std::move(bin.value())));
    }
    case 0xc6U: {
      auto len = read_u32_be();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      auto bin = read_bin_payload(len.value());
      if (!bin.has_value()) {
        return Result<MsgPackValue>::failure(bin.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::bin(std::move(bin.value())));
    }
    case 0xc7U: {
      auto len = read_u8();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      return read_ext(len.value());
    }
    case 0xc8U: {
      auto len = read_u16_be();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      return read_ext(len.value());
    }
    case 0xc9U: {
      auto len = read_u32_be();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      return read_ext(len.value());
    }
    case 0xcaU: {
      auto bits = read_u32_be();
      if (!bits.has_value()) {
        return Result<MsgPackValue>::failure(bits.error());
      }
      const float f = std::bit_cast<float>(bits.value());
      return Result<MsgPackValue>::success(
          MsgPackValue::number(static_cast<double>(f)));
    }
    case 0xcbU: {
      auto bits = read_u64_be();
      if (!bits.has_value()) {
        return Result<MsgPackValue>::failure(bits.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::number(std::bit_cast<double>(bits.value())));
    }
    case 0xccU: {
      auto v = read_u8();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::uint64(static_cast<std::uint64_t>(v.value())));
    }
    case 0xcdU: {
      auto v = read_u16_be();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::uint64(static_cast<std::uint64_t>(v.value())));
    }
    case 0xceU: {
      auto v = read_u32_be();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::uint64(static_cast<std::uint64_t>(v.value())));
    }
    case 0xcfU: {
      auto v = read_u64_be();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::uint64(v.value()));
    }
    case 0xd0U: {
      auto v = read_u8();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::int64(
          static_cast<std::int64_t>(std::bit_cast<std::int8_t>(v.value()))));
    }
    case 0xd1U: {
      auto v = read_u16_be();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::int64(
          static_cast<std::int64_t>(std::bit_cast<std::int16_t>(v.value()))));
    }
    case 0xd2U: {
      auto v = read_u32_be();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(MsgPackValue::int64(
          static_cast<std::int64_t>(std::bit_cast<std::int32_t>(v.value()))));
    }
    case 0xd3U: {
      auto v = read_u64_be();
      if (!v.has_value()) {
        return Result<MsgPackValue>::failure(v.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::int64(std::bit_cast<std::int64_t>(v.value())));
    }
    case 0xd4U:
      return read_ext(1U);
    case 0xd5U:
      return read_ext(2U);
    case 0xd6U:
      return read_ext(4U);
    case 0xd7U:
      return read_ext(8U);
    case 0xd8U:
      return read_ext(16U);
    case 0xd9U: {
      auto len = read_u8();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      auto str = read_string_payload(len.value());
      if (!str.has_value()) {
        return Result<MsgPackValue>::failure(str.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::string(std::move(str.value())));
    }
    case 0xdaU: {
      auto len = read_u16_be();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      auto str = read_string_payload(len.value());
      if (!str.has_value()) {
        return Result<MsgPackValue>::failure(str.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::string(std::move(str.value())));
    }
    case 0xdbU: {
      auto len = read_u32_be();
      if (!len.has_value()) {
        return Result<MsgPackValue>::failure(len.error());
      }
      auto str = read_string_payload(len.value());
      if (!str.has_value()) {
        return Result<MsgPackValue>::failure(str.error());
      }
      return Result<MsgPackValue>::success(
          MsgPackValue::string(std::move(str.value())));
    }
    case 0xdcU: {
      auto count = read_u16_be();
      if (!count.has_value()) {
        return Result<MsgPackValue>::failure(count.error());
      }
      return read_array(count.value());
    }
    case 0xddU: {
      auto count = read_u32_be();
      if (!count.has_value()) {
        return Result<MsgPackValue>::failure(count.error());
      }
      return read_array(count.value());
    }
    case 0xdeU: {
      auto count = read_u16_be();
      if (!count.has_value()) {
        return Result<MsgPackValue>::failure(count.error());
      }
      return read_map(count.value());
    }
    case 0xdfU: {
      auto count = read_u32_be();
      if (!count.has_value()) {
        return Result<MsgPackValue>::failure(count.error());
      }
      return read_map(count.value());
    }
    default:
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::corrupt, NvimRpcError::msgpack_invalid_format));
    }
  }
};

// ============================================================================
// Audit-Safety Script Validation (Lua + Ex)
// ============================================================================

bool is_ident_char(char ch) noexcept {
  const auto u = static_cast<unsigned char>(ch);
  return std::isalnum(u) != 0 || ch == '_';
}

bool is_ascii_alpha(char ch) noexcept {
  const auto u = static_cast<unsigned char>(ch);
  return std::isalpha(u) != 0;
}

bool is_ascii_digit(char ch) noexcept {
  const auto u = static_cast<unsigned char>(ch);
  return std::isdigit(u) != 0;
}

struct SubstringSearch {
  std::string_view haystack;
  std::string_view needle;
};

bool contains_identifier_token(const SubstringSearch &search) noexcept {
  if (search.needle.empty() || search.needle.size() > search.haystack.size()) {
    return false;
  }
  std::size_t pos = 0;
  while ((pos = search.haystack.find(search.needle, pos)) != std::string_view::npos) {
    const bool left_ok = (pos == 0U) || !is_ident_char(search.haystack[pos - 1U]);
    const std::size_t end = pos + search.needle.size();
    const bool right_ok =
        (end >= search.haystack.size()) || !is_ident_char(search.haystack[end]);
    if (left_ok && right_ok) {
      return true;
    }
    ++pos;
  }
  return false;
}

std::string_view trim_ascii(std::string_view input) noexcept {
  while (!input.empty() && (input.front() == ' ' || input.front() == '\t')) {
    input.remove_prefix(1U);
  }
  while (!input.empty() && (input.back() == ' ' || input.back() == '\t')) {
    input.remove_suffix(1U);
  }
  return input;
}

bool validate_language_name(std::string_view language) noexcept {
  if (language.empty() || language.size() > kMaxLanguageNameBytes) {
    return false;
  }
  for (const char ch : language) {
    if (!is_ident_char(ch) && ch != '-') {
      return false;
    }
  }
  return true;
}

NvimScriptValidation validate_lua_scratch_script(std::string_view script) {
  if (script.empty()) {
    return {false, "scratch_edit Lua script must not be empty"};
  }
  if (script.size() > kMaxScriptBytes) {
    return {false, "scratch_edit Lua script exceeds maximum size"};
  }
  if (script.find('\0') != std::string_view::npos) {
    return {false, "scratch_edit Lua script must not contain NUL bytes"};
  }
  if (static_cast<unsigned char>(script.front()) == 0x1bU) {
    return {false, "scratch_edit rejects Lua bytecode chunks"};
  }

  // Exact dangerous substring checks (escape vectors & Neovim command bridges).
  static constexpr std::array<std::string_view, 23> kForbiddenSubstrings = {
      ":!",
      "io.open",
      "io.popen",
      "io.lines",
      "io.input",
      "io.output",
      "io.tmpfile",
      "os.execute",
      "os.remove",
      "os.rename",
      "os.exit",
      "os.tmpname",
      "vim.cmd",
      "vim.uv",
      "vim.loop",
      "vim.system",
      "vim.fs",
      "vim.fn",
      "nvim_command",
      "nvim_exec",
      "nvim_eval",
      "nvim_buf_set_name",
      "nvim_call_function",
  };
  for (const auto pattern : kForbiddenSubstrings) {
    if (script.find(pattern) != std::string_view::npos) {
      return {false, "scratch_edit Lua script contains forbidden escape: " +
                         std::string{pattern}};
    }
  }

  // Identifier-bounded checks for Lua globals / sandbox escapes.
  static constexpr std::array<std::string_view, 18> kForbiddenIdentifiers = {
      "os",      "io",     "debug",    "ffi",        "jit",          "package",
      "require", "dofile", "loadfile", "loadstring", "load",         "getfenv",
      "setfenv", "rawget", "rawset",   "_G",         "getmetatable", "setmetatable",
  };
  for (const auto ident : kForbiddenIdentifiers) {
    if (contains_identifier_token({script, ident})) {
      return {false, "scratch_edit Lua script references restricted identifier: " +
                         std::string{ident}};
    }
  }

  // Explicit check for `system(` with optional whitespace before `(`.
  std::size_t pos = 0;
  while ((pos = script.find("system", pos)) != std::string_view::npos) {
    const bool left_ok = (pos == 0U) || !is_ident_char(script[pos - 1U]);
    std::size_t after = pos + 6U;
    if (left_ok && (after >= script.size() || !is_ident_char(script[after]))) {
      while (after < script.size() && (script[after] == ' ' || script[after] == '\t')) {
        ++after;
      }
      if (after < script.size() && script[after] == '(') {
        return {false, "scratch_edit Lua script must not call system()"};
      }
    }
    ++pos;
  }

  return {true, {}};
}

// Strict allowlist validator for a single Ex command line (and recursive subcommands
// inside :g/:v). Rejects shell escapes, file I/O, Lua/Vimscript eval, and chained
// commands.
NvimScriptValidation validate_ex_command_line(std::string_view raw_line,
                                              std::size_t recursion_depth) {
  if (recursion_depth > 2U) {
    return {false, "Ex command nesting depth exceeded"};
  }

  std::string_view line = trim_ascii(raw_line);
  if (line.empty() || line.front() == '"') {
    return {true, {}};
  }

  // Strip leading colons.
  while (!line.empty() && line.front() == ':') {
    line.remove_prefix(1U);
    line = trim_ascii(line);
  }
  if (line.empty() || line.front() == '"') {
    return {true, {}};
  }

  // Reject any bare shell/filter bang right at command start.
  if (line.front() == '!') {
    return {false, "Ex shell escape (:!) is forbidden"};
  }

  // Parse optional safe Ex range prefix: %, ., $, digits, +, -, comma, semicolon.
  std::size_t idx = 0;
  while (idx < line.size()) {
    const char ch = line[idx];
    if (ch == '%' || ch == '.' || ch == '$' || ch == ',' || ch == ';' || ch == '+' ||
        ch == '-' || is_ascii_digit(ch) || ch == ' ' || ch == '\t') {
      ++idx;
      continue;
    }
    break;
  }
  std::string_view rest = trim_ascii(line.substr(idx));
  if (rest.empty()) {
    return {false, "Ex line contains range without an allowlisted command"};
  }
  if (rest.front() == '!') {
    return {false, "Ex external filter (:range!) is forbidden"};
  }

  // Allow shift commands `<` and `>`.
  if (rest.front() == '<' || rest.front() == '>') {
    for (const char ch : rest) {
      if (ch != '<' && ch != '>' && ch != ' ' && ch != '\t' && !is_ascii_digit(ch)) {
        return {false, "Ex shift command contains disallowed trailing characters"};
      }
    }
    return {true, {}};
  }

  // Extract ASCII command name.
  std::size_t cmd_len = 0;
  while (cmd_len < rest.size() && is_ascii_alpha(rest[cmd_len])) {
    ++cmd_len;
  }
  if (cmd_len == 0U) {
    return {false, "Ex command must start with an allowlisted command name"};
  }
  const std::string_view cmd = rest.substr(0U, cmd_len);
  const std::string_view args = rest.substr(cmd_len);

  // 1. Substitute: s / substitute
  if (cmd == "s" || cmd == "substitute") {
    if (args.empty()) {
      return {false, "Ex substitute requires delimiter and pattern"};
    }
    const char delim = args.front();
    if (is_ident_char(delim) || delim == ' ' || delim == '\t' || delim == '!' ||
        delim == '|' || delim == '"' || delim == '\\' || delim == '=') {
      return {false, "Ex substitute uses disallowed delimiter"};
    }
    // Parse pattern up to unescaped delim.
    std::size_t p = 1U;
    bool escaped = false;
    bool found_pat_end = false;
    while (p < args.size()) {
      const char ch = args[p++];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch == '\\') {
        escaped = true;
        continue;
      }
      if (ch == delim) {
        found_pat_end = true;
        break;
      }
    }
    if (!found_pat_end) {
      return {false, "Ex substitute missing pattern closing delimiter"};
    }
    // Reject \= expression replacement immediately!
    if (p + 1U < args.size() && args[p] == '\\' && args[p + 1U] == '=') {
      return {false, "Ex substitute expression replacement (\\=) is forbidden"};
    }
    // Parse replacement up to optional unescaped delim.
    escaped = false;
    bool found_repl_end = false;
    while (p < args.size()) {
      const char ch = args[p++];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch == '\\') {
        escaped = true;
        continue;
      }
      if (ch == delim) {
        found_repl_end = true;
        break;
      }
    }
    if (found_repl_end) {
      // Only allow safe substitute flags after closing delimiter (zero `|` chaining!).
      const std::string_view flags = trim_ascii(args.substr(p));
      for (const char ch : flags) {
        switch (ch) {
        case 'g':
        case 'e':
        case 'i':
        case 'I':
        case 'n':
        case 'p':
        case '&':
        case '#':
        case 'r':
        case ' ':
        case '\t':
          break;
        default:
          return {false, "Ex substitute contains disallowed flag or trailing command"};
        }
      }
    }
    return {true, {}};
  }

  // 2. Global / Vglobal: g / global / v / vglobal
  if (cmd == "g" || cmd == "global" || cmd == "v" || cmd == "vglobal") {
    std::string_view tail = args;
    if (!tail.empty() && tail.front() == '!') {
      tail.remove_prefix(1U);
    }
    if (tail.empty()) {
      return {false, "Ex global requires delimiter and pattern"};
    }
    const char delim = tail.front();
    if (is_ident_char(delim) || delim == ' ' || delim == '\t' || delim == '!' ||
        delim == '|' || delim == '"' || delim == '\\') {
      return {false, "Ex global uses disallowed delimiter"};
    }
    std::size_t p = 1U;
    bool escaped = false;
    bool found_end = false;
    while (p < tail.size()) {
      const char ch = tail[p++];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (ch == '\\') {
        escaped = true;
        continue;
      }
      if (ch == delim) {
        found_end = true;
        break;
      }
    }
    if (!found_end) {
      return {false, "Ex global missing closing pattern delimiter"};
    }
    const std::string_view subcmd = trim_ascii(tail.substr(p));
    if (subcmd.empty()) {
      return {false, "Ex global requires an explicit allowlisted subcommand"};
    }
    return validate_ex_command_line(subcmd, recursion_depth + 1U);
  }

  // 3. Delete: d / delete
  if (cmd == "d" || cmd == "delete") {
    const std::string_view tail = trim_ascii(args);
    for (const char ch : tail) {
      if (!is_ascii_digit(ch) && ch != ' ' && ch != '\t') {
        return {false, "Ex delete allows only optional numeric count"};
      }
    }
    return {true, {}};
  }

  // 4. Move / Copy: m / move / t / co / copy
  if (cmd == "m" || cmd == "move" || cmd == "t" || cmd == "co" || cmd == "copy") {
    const std::string_view tail = trim_ascii(args);
    if (tail.empty()) {
      return {false, "Ex move/copy requires target line address"};
    }
    for (const char ch : tail) {
      if (!is_ascii_digit(ch) && ch != '.' && ch != '$' && ch != '+' && ch != '-' &&
          ch != ' ' && ch != '\t') {
        return {false, "Ex move/copy target contains disallowed characters"};
      }
    }
    return {true, {}};
  }

  // 5. Join: j / join
  if (cmd == "j" || cmd == "join") {
    std::string_view tail = args;
    if (!tail.empty() && tail.front() == '!') {
      tail.remove_prefix(1U);
    }
    tail = trim_ascii(tail);
    for (const char ch : tail) {
      if (!is_ascii_digit(ch) && ch != ' ' && ch != '\t') {
        return {false, "Ex join allows only optional ! and count"};
      }
    }
    return {true, {}};
  }

  // 6. Sort: sor / sort
  if (cmd == "sor" || cmd == "sort") {
    std::string_view tail = args;
    if (!tail.empty() && tail.front() == '!') {
      tail.remove_prefix(1U);
    }
    tail = trim_ascii(tail);
    for (const char ch : tail) {
      switch (ch) {
      case 'i':
      case 'u':
      case 'n':
      case 'f':
      case 'x':
      case 'o':
      case 'b':
      case ' ':
      case '\t':
        break;
      default:
        return {false, "Ex sort allows only safe ordering flags (i,u,n,f,x,o,b)"};
      }
    }
    return {true, {}};
  }

  // 7. Retab / Left / Right / Center
  if (cmd == "ret" || cmd == "retab" || cmd == "le" || cmd == "left" || cmd == "ri" ||
      cmd == "right" || cmd == "ce" || cmd == "center") {
    std::string_view tail = args;
    if ((cmd == "ret" || cmd == "retab") && !tail.empty() && tail.front() == '!') {
      tail.remove_prefix(1U);
    }
    tail = trim_ascii(tail);
    for (const char ch : tail) {
      if (!is_ascii_digit(ch) && ch != ' ' && ch != '\t') {
        return {false, "Ex formatting command allows only optional numeric width"};
      }
    }
    return {true, {}};
  }

  return {false,
          "Ex command is not in the in-memory edit allowlist: " + std::string{cmd}};
}

NvimScriptValidation validate_ex_scratch_script(std::string_view script) {
  if (script.empty()) {
    return {false, "scratch_edit Ex script must not be empty"};
  }
  if (script.size() > kMaxScriptBytes) {
    return {false, "scratch_edit Ex script exceeds maximum size"};
  }
  for (const char ch : script) {
    const auto u = static_cast<unsigned char>(ch);
    if (ch == '\0' || ch == '\r' || (u < 0x20U && ch != '\n' && ch != '\t') ||
        u == 0x7fU) {
      return {false, "scratch_edit Ex script contains disallowed control characters"};
    }
  }

  bool saw_command = false;
  std::size_t line_start = 0;
  while (line_start <= script.size()) {
    const std::size_t nl = script.find('\n', line_start);
    const std::string_view line = (nl == std::string_view::npos)
                                      ? script.substr(line_start)
                                      : script.substr(line_start, nl - line_start);
    const std::string_view trimmed = trim_ascii(line);
    if (!trimmed.empty() && trimmed.front() != '"') {
      saw_command = true;
      auto res = validate_ex_command_line(trimmed, 0U);
      if (!res.allowed) {
        return res;
      }
    }
    if (nl == std::string_view::npos) {
      break;
    }
    line_start = nl + 1U;
  }

  if (!saw_command) {
    return {false, "scratch_edit Ex script contains no executable commands"};
  }
  return {true, {}};
}

// ============================================================================
// Embedded Lua Helpers Sent Over MsgPack-RPC
// ============================================================================

constexpr std::string_view kInitSessionLua = R"lua(
local extra_rtp = ...
vim.o.secure = true
vim.o.exrc = false
vim.o.modeline = false
vim.o.swapfile = false
vim.o.undofile = false
vim.o.shada = ""
vim.o.shell = "/nonexistent"
if type(extra_rtp) == "table" then
  for _, p in ipairs(extra_rtp) do
    if type(p) == "string" and #p > 0 then
      vim.opt.runtimepath:append(p)
    end
  end
end
return true
)lua";

constexpr std::string_view kProbeCapabilitiesLua = R"lua(
local v = vim.version()
local files = vim.api.nvim_get_runtime_file("parser/*", true)
local seen = {}
local parsers = {}
for _, path in ipairs(files) do
  local base = path:match("([^/\\]+)$") or path
  local name = base:gsub("%.[a-zA-Z0-9_]+$", "")
  if #name > 0 and not seen[name] then
    seen[name] = true
    parsers[#parsers + 1] = name
  end
end
table.sort(parsers)
return {
  progpath = vim.v.progpath or "",
  major = v.major or 0,
  minor = v.minor or 0,
  patch = v.patch or 0,
  version_string = string.format("NVIM v%d.%d.%d", v.major or 0, v.minor or 0, v.patch or 0),
  has_treesitter = (vim.treesitter ~= nil),
  has_vim_diff = (type(vim.diff) == "function"),
  parsers = parsers,
}
)lua";

constexpr std::string_view kAstQueryLua = R"lua(
local lang, src, query_src, max_captures = ...
local buf = vim.api.nvim_create_buf(false, true)
local function cleanup()
  if vim.api.nvim_buf_is_valid(buf) then
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
  end
end
local ok, result = pcall(function()
  vim.bo[buf].buftype = "nofile"
  vim.bo[buf].bufhidden = "wipe"
  vim.bo[buf].swapfile = false
  vim.bo[buf].undofile = false
  vim.bo[buf].modifiable = true
  local lines = vim.split(src, "\n", { plain = true })
  if #src > 0 and src:sub(-1) == "\n" then
    table.remove(lines, #lines)
  end
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modifiable = false
  local parser = vim.treesitter.get_string_parser(src, lang)
  local trees = parser:parse()
  if not trees or not trees[1] then
    error("failed to parse source with language: " .. tostring(lang))
  end
  local root = trees[1]:root()
  local query = vim.treesitter.query.parse(lang, query_src)
  local captures = {}
  for id, node in query:iter_captures(root, src, 0, -1) do
    if #captures >= max_captures then
      break
    end
    local sr, sc, er, ec = node:range()
    captures[#captures + 1] = {
      query.captures[id] or "",
      node:type() or "",
      sr,
      sc,
      er,
      ec,
      vim.treesitter.get_node_text(node, src) or "",
    }
  end
  return captures
end)
cleanup()
if not ok then
  return { ok = false, err = tostring(result) }
end
return { ok = true, captures = result }
)lua";

constexpr std::string_view kScratchEditLua = R"lua(
local src, script, is_lua = ...
local buf = vim.api.nvim_create_buf(false, true)
local prev_buf = vim.api.nvim_get_current_buf()
local function cleanup()
  if prev_buf and prev_buf ~= buf and vim.api.nvim_buf_is_valid(prev_buf) then
    pcall(vim.api.nvim_set_current_buf, prev_buf)
  end
  if vim.api.nvim_buf_is_valid(buf) then
    pcall(vim.api.nvim_buf_delete, buf, { force = true })
  end
end
local ok, result = pcall(function()
  vim.bo[buf].buftype = "nofile"
  vim.bo[buf].bufhidden = "wipe"
  vim.bo[buf].swapfile = false
  vim.bo[buf].undofile = false
  vim.bo[buf].modifiable = true
  local had_trailing_nl = (#src > 0 and src:sub(-1) == "\n")
  local orig_lines = {}
  local orig_count = 0
  if #src > 0 then
    orig_lines = vim.split(src, "\n", { plain = true })
    if had_trailing_nl then
      table.remove(orig_lines, #orig_lines)
    end
    orig_count = #orig_lines
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, orig_lines)
  else
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, { "" })
  end
  vim.api.nvim_set_current_buf(buf)

  if is_lua then
    if script:sub(1, 1) == "\27" then
      error("lua bytecode is forbidden in scratch_edit")
    end
    local chunk, load_err = loadstring(script, "=blackbird_scratch")
    if not chunk then
      error("lua syntax error: " .. tostring(load_err))
    end
    local function check_buf(b)
      if b ~= 0 and b ~= buf then
        error("scratch_edit may only access its isolated scratch buffer")
      end
      return buf
    end
    local function shallow_copy(tbl, omit)
      local out = {}
      for k, v in pairs(tbl) do
        if not (omit and omit[k]) then
          out[k] = v
        end
      end
      return out
    end
    local safe_string = shallow_copy(string, { dump = true })
    local safe_api = {
      nvim_buf_get_lines = function(b, s, e, strict)
        return vim.api.nvim_buf_get_lines(check_buf(b), s, e, strict)
      end,
      nvim_buf_set_lines = function(b, s, e, strict, repl)
        return vim.api.nvim_buf_set_lines(check_buf(b), s, e, strict, repl)
      end,
      nvim_buf_get_text = function(b, sr, sc, er, ec, opts)
        return vim.api.nvim_buf_get_text(check_buf(b), sr, sc, er, ec, opts)
      end,
      nvim_buf_set_text = function(b, sr, sc, er, ec, repl)
        return vim.api.nvim_buf_set_text(check_buf(b), sr, sc, er, ec, repl)
      end,
      nvim_buf_line_count = function(b)
        return vim.api.nvim_buf_line_count(check_buf(b))
      end,
      nvim_buf_get_offset = function(b, idx)
        return vim.api.nvim_buf_get_offset(check_buf(b), idx)
      end,
    }
    local safe_ts = nil
    if vim.treesitter ~= nil then
      safe_ts = {
        get_string_parser = vim.treesitter.get_string_parser,
        get_node_text = vim.treesitter.get_node_text,
        query = {
          parse = vim.treesitter.query.parse,
        },
      }
    end
    local safe_vim = {
      api = safe_api,
      treesitter = safe_ts,
      split = vim.split,
      trim = vim.trim,
      pesc = vim.pesc,
      startswith = vim.startswith,
      endswith = vim.endswith,
      deepcopy = vim.deepcopy,
      tbl_count = vim.tbl_count,
      tbl_contains = vim.tbl_contains,
      tbl_keys = vim.tbl_keys,
      tbl_values = vim.tbl_values,
      tbl_map = vim.tbl_map,
      tbl_filter = vim.tbl_filter,
      list_extend = vim.list_extend,
      list_slice = vim.list_slice,
    }
    local env = {
      buf = buf,
      vim = safe_vim,
      string = safe_string,
      table = shallow_copy(table),
      math = shallow_copy(math),
      ipairs = ipairs,
      pairs = pairs,
      next = next,
      select = select,
      tonumber = tonumber,
      tostring = tostring,
      type = type,
      unpack = unpack,
      pcall = pcall,
      xpcall = xpcall,
      error = error,
      assert = assert,
    }
    setfenv(chunk, env)
    chunk()
  else
    for _, raw_line in ipairs(vim.split(script, "\n", { plain = true })) do
      local trimmed = vim.trim(raw_line)
      if #trimmed > 0 and trimmed:sub(1, 1) ~= '"' then
        vim.api.nvim_exec2(trimmed, { output = false })
      end
    end
  end

  local after_lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
  local proposed = ""
  if #after_lines == 1 and after_lines[1] == "" and src ~= "\n" then
    proposed = ""
  else
    proposed = table.concat(after_lines, "\n")
    if had_trailing_nl then
      proposed = proposed .. "\n"
    end
  end
  local changed = (proposed ~= src)
  local diff = ""
  if changed then
    diff = vim.diff(src, proposed, { result_type = "unified" }) or ""
  end
  return {
    ok = true,
    original_lines_count = orig_count,
    proposed_text = proposed,
    unified_diff = diff,
    changed = changed,
  }
end)
cleanup()
if not ok then
  return { ok = false, err = tostring(result) }
end
return result
)lua";

// ============================================================================
// Formatting Helper for Remote RPC Error Values
// ============================================================================

std::string describe_rpc_error(const MsgPackValue &err) {
  if (const auto *s = err.as_string(); s != nullptr) {
    return *s;
  }
  if (const auto *arr = err.as_array(); arr != nullptr) {
    if (arr->size() >= 2U) {
      if (const auto *msg = (*arr)[1U].as_string(); msg != nullptr) {
        return *msg;
      }
    }
    if (!arr->empty()) {
      if (const auto *msg = (*arr)[0U].as_string(); msg != nullptr) {
        return *msg;
      }
    }
  }
  return "remote Neovim RPC error";
}

// ============================================================================
// Pipe Creation Helper (F_DUPFD_CLOEXEC >= 3)
// ============================================================================

bool create_cloexec_pipe(int (&fds)[2]) noexcept {
  fds[0] = -1;
  fds[1] = -1;
  if (::pipe(fds) != 0) {
    return false;
  }
  for (int &fd : fds) {
    const int duped = ::fcntl(fd, F_DUPFD_CLOEXEC, 3);
    if (duped < 0) {
      for (int &existing : fds) {
        if (existing >= 0) {
          (void)::close(existing);
          existing = -1;
        }
      }
      return false;
    }
    (void)::close(fd);
    fd = duped;
  }
  return true;
}

void close_fd_if_open(int &fd) noexcept {
  if (fd >= 0) {
    (void)::close(fd);
    fd = -1;
  }
}

int remaining_poll_ms(SteadyClock::time_point deadline) noexcept {
  const auto now = SteadyClock::now();
  if (now >= deadline) {
    return 0;
  }
  const auto ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
  if (ms <= 0) {
    return 1;
  }
  return static_cast<int>(std::min<std::int64_t>(ms, 100));
}

} // namespace

// ============================================================================
// Public Error Names
// ============================================================================

std::string_view nvim_rpc_error_name(NvimRpcError detail) noexcept {
  switch (detail) {
  case NvimRpcError::none:
    return "none";
  case NvimRpcError::msgpack_incomplete:
    return "msgpack_incomplete";
  case NvimRpcError::msgpack_corrupt:
    return "msgpack_corrupt";
  case NvimRpcError::msgpack_trailing_bytes:
    return "msgpack_trailing_bytes";
  case NvimRpcError::msgpack_depth_exceeded:
    return "msgpack_depth_exceeded";
  case NvimRpcError::msgpack_bytes_exceeded:
    return "msgpack_bytes_exceeded";
  case NvimRpcError::msgpack_elements_exceeded:
    return "msgpack_elements_exceeded";
  case NvimRpcError::msgpack_invalid_format:
    return "msgpack_invalid_format";
  case NvimRpcError::invalid_argument:
    return "invalid_argument";
  case NvimRpcError::unsafe_script_rejected:
    return "unsafe_script_rejected";
  case NvimRpcError::spawn_failed:
    return "spawn_failed";
  case NvimRpcError::pipe_failed:
    return "pipe_failed";
  case NvimRpcError::not_connected:
    return "not_connected";
  case NvimRpcError::io_failed:
    return "io_failed";
  case NvimRpcError::timeout:
    return "timeout";
  case NvimRpcError::eof:
    return "eof";
  case NvimRpcError::protocol_violation:
    return "protocol_violation";
  case NvimRpcError::rpc_remote_error:
    return "rpc_remote_error";
  case NvimRpcError::treesitter_error:
    return "treesitter_error";
  }
  return "unknown";
}

// ============================================================================
// MsgPackArray / MsgPackMap / MsgPackValue Definitions
// ============================================================================

MsgPackArray::MsgPackArray() = default;
MsgPackArray::MsgPackArray(std::vector<MsgPackValue> values)
    : items(std::move(values)) {}
MsgPackArray::MsgPackArray(const MsgPackArray &other) = default;
MsgPackArray &MsgPackArray::operator=(const MsgPackArray &other) = default;
MsgPackArray::MsgPackArray(MsgPackArray &&other) noexcept = default;
MsgPackArray &MsgPackArray::operator=(MsgPackArray &&other) noexcept = default;
MsgPackArray::~MsgPackArray() = default;

std::size_t MsgPackArray::size() const noexcept { return items.size(); }
bool MsgPackArray::empty() const noexcept { return items.empty(); }
void MsgPackArray::push_back(MsgPackValue value) { items.push_back(std::move(value)); }
MsgPackValue &MsgPackArray::operator[](std::size_t index) { return items[index]; }
const MsgPackValue &MsgPackArray::operator[](std::size_t index) const {
  return items[index];
}
bool MsgPackArray::operator==(const MsgPackArray &other) const {
  return items == other.items;
}

MsgPackMap::MsgPackMap() = default;
MsgPackMap::MsgPackMap(std::vector<MsgPackMapEntry> values)
    : entries(std::move(values)) {}
MsgPackMap::MsgPackMap(const MsgPackMap &other) = default;
MsgPackMap &MsgPackMap::operator=(const MsgPackMap &other) = default;
MsgPackMap::MsgPackMap(MsgPackMap &&other) noexcept = default;
MsgPackMap &MsgPackMap::operator=(MsgPackMap &&other) noexcept = default;
MsgPackMap::~MsgPackMap() = default;

std::size_t MsgPackMap::size() const noexcept { return entries.size(); }
bool MsgPackMap::empty() const noexcept { return entries.empty(); }
void MsgPackMap::push_back(MsgPackMapEntry entry) {
  entries.push_back(std::move(entry));
}
const MsgPackValue *MsgPackMap::find(std::string_view key) const noexcept {
  for (const auto &entry : entries) {
    const auto *k = entry.key.as_string();
    if (k != nullptr && *k == key) {
      return &entry.value;
    }
  }
  return nullptr;
}
bool MsgPackMap::operator==(const MsgPackMap &other) const {
  return entries == other.entries;
}

MsgPackValue MsgPackValue::array() { return MsgPackValue{MsgPackArray{}}; }
MsgPackValue MsgPackValue::array(std::vector<MsgPackValue> values) {
  return MsgPackValue{MsgPackArray{std::move(values)}};
}
MsgPackValue MsgPackValue::map() { return MsgPackValue{MsgPackMap{}}; }
MsgPackValue MsgPackValue::map(std::vector<MsgPackMapEntry> values) {
  return MsgPackValue{MsgPackMap{std::move(values)}};
}

std::optional<bool> MsgPackValue::as_bool() const noexcept {
  if (const auto *v = std::get_if<bool>(&data); v != nullptr) {
    return *v;
  }
  return std::nullopt;
}

std::optional<std::int64_t> MsgPackValue::as_int64() const noexcept {
  if (const auto *v = std::get_if<std::int64_t>(&data); v != nullptr) {
    return *v;
  }
  if (const auto *u = std::get_if<std::uint64_t>(&data); u != nullptr) {
    if (*u <= static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
      return static_cast<std::int64_t>(*u);
    }
  }
  return std::nullopt;
}

std::optional<std::uint64_t> MsgPackValue::as_uint64() const noexcept {
  if (const auto *u = std::get_if<std::uint64_t>(&data); u != nullptr) {
    return *u;
  }
  if (const auto *v = std::get_if<std::int64_t>(&data); v != nullptr) {
    if (*v >= 0) {
      return static_cast<std::uint64_t>(*v);
    }
  }
  return std::nullopt;
}

std::optional<double> MsgPackValue::as_double() const noexcept {
  if (const auto *d = std::get_if<double>(&data); d != nullptr) {
    return *d;
  }
  return std::nullopt;
}

const std::string *MsgPackValue::as_string() const noexcept {
  return std::get_if<std::string>(&data);
}

const MsgPackValue::Bin *MsgPackValue::as_bin() const noexcept {
  return std::get_if<Bin>(&data);
}

const MsgPackArray *MsgPackValue::as_array() const noexcept {
  return std::get_if<MsgPackArray>(&data);
}

const MsgPackMap *MsgPackValue::as_map() const noexcept {
  return std::get_if<MsgPackMap>(&data);
}

const MsgPackExt *MsgPackValue::as_ext() const noexcept {
  return std::get_if<MsgPackExt>(&data);
}

// ============================================================================
// Public MsgPack Codec Entry Points
// ============================================================================

Result<std::vector<std::uint8_t>> encode_msgpack(const MsgPackValue &value,
                                                 MsgPackLimits limits) {
  EncodeState state;
  state.limits = limits;
  auto res = state.encode_value(value);
  if (!res.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(res.error());
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(state.out));
}

Result<MsgPackDecodeStep> decode_msgpack_next(std::span<const std::uint8_t> bytes,
                                              MsgPackLimits limits) {
  if (bytes.empty()) {
    return Result<MsgPackDecodeStep>::failure(
        make_rpc_error(ErrorCode::incomplete, NvimRpcError::msgpack_incomplete));
  }
  DecodeState state;
  state.bytes = bytes;
  state.limits = limits;
  auto res = state.decode_value();
  if (!res.has_value()) {
    return Result<MsgPackDecodeStep>::failure(res.error());
  }
  return Result<MsgPackDecodeStep>::success(
      MsgPackDecodeStep{std::move(res.value()), state.pos});
}

Result<MsgPackValue> decode_msgpack(std::span<const std::uint8_t> bytes,
                                    MsgPackLimits limits) {
  if (bytes.size() > limits.max_bytes) {
    return Result<MsgPackValue>::failure(
        make_rpc_error(ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
  }
  auto step = decode_msgpack_next(bytes, limits);
  if (!step.has_value()) {
    return Result<MsgPackValue>::failure(step.error());
  }
  if (step.value().consumed != bytes.size()) {
    return Result<MsgPackValue>::failure(
        make_rpc_error(ErrorCode::corrupt, NvimRpcError::msgpack_trailing_bytes));
  }
  return Result<MsgPackValue>::success(std::move(step.value().value));
}

// ============================================================================
// Public Script Validation
// ============================================================================

NvimScriptValidation validate_scratch_script(std::string_view script, bool is_lua) {
  return is_lua ? validate_lua_scratch_script(script)
                : validate_ex_scratch_script(script);
}

// ============================================================================
// NvimRpcClient::Impl
// ============================================================================

struct NvimRpcClient::Impl {
  NvimClientOptions options;
  pid_t pid = -1;
  bool child_active = false;
  int stdin_fd = -1;
  int stdout_fd = -1;
  bool stdout_eof = false;
  std::uint32_t next_msgid = 1U;
  std::vector<std::uint8_t> read_buf;
  std::size_t read_offset = 0;
  std::deque<NvimNotification> notifications;
  std::string last_error;

  ~Impl() { shutdown_cleanly(); }

  std::span<const std::uint8_t> readable_bytes() const noexcept {
    if (read_offset >= read_buf.size()) {
      return {};
    }
    return std::span<const std::uint8_t>{read_buf.data() + read_offset,
                                         read_buf.size() - read_offset};
  }

  void consume_read_bytes(std::size_t count) noexcept {
    read_offset += count;
    if (read_offset >= read_buf.size()) {
      read_buf.clear();
      read_offset = 0;
    } else if (read_offset >= kCompactThresholdBytes) {
      read_buf.erase(read_buf.begin(),
                     read_buf.begin() + static_cast<std::ptrdiff_t>(read_offset));
      read_offset = 0;
    }
  }

  Result<void> read_available_nonblocking() {
    if (stdout_fd < 0 || stdout_eof) {
      return Result<void>::success();
    }
    std::array<std::uint8_t, kReadChunkBytes> chunk{};
    while (true) {
      const ssize_t n = ::read(stdout_fd, chunk.data(), chunk.size());
      if (n > 0) {
        const auto count = static_cast<std::size_t>(n);
        const std::size_t unread = read_buf.size() - read_offset;
        if (count > options.msgpack_limits.max_bytes ||
            unread > options.msgpack_limits.max_bytes - count) {
          last_error = "Neovim RPC read buffer exceeded max_bytes";
          return Result<void>::failure(make_rpc_error(
              ErrorCode::capacity, NvimRpcError::msgpack_bytes_exceeded));
        }
        if (read_offset > 0U &&
            read_buf.size() + count > options.msgpack_limits.max_bytes) {
          read_buf.erase(read_buf.begin(),
                         read_buf.begin() + static_cast<std::ptrdiff_t>(read_offset));
          read_offset = 0;
        }
        read_buf.insert(read_buf.end(), chunk.begin(),
                        chunk.begin() + static_cast<std::ptrdiff_t>(count));
        continue;
      }
      if (n == 0) {
        stdout_eof = true;
        return Result<void>::success();
      }
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return Result<void>::success();
      }
      last_error = "read() from Neovim stdout failed";
      return Result<void>::failure(
          make_rpc_error(ErrorCode::io, NvimRpcError::io_failed));
    }
  }

  Result<void> write_all_with_drain(std::span<const std::uint8_t> payload,
                                    SteadyClock::time_point deadline) {
    if (stdin_fd < 0) {
      last_error = "Neovim client is not connected";
      return Result<void>::failure(
          make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
    }
#ifndef F_SETNOSIGPIPE
    PipeSignalGuard sigpipe_guard;
#endif
    std::size_t sent = 0;
    while (sent < payload.size()) {
      if (SteadyClock::now() >= deadline) {
        last_error = "timed out writing MsgPack-RPC frame to Neovim";
        return Result<void>::failure(
            make_rpc_error(ErrorCode::io, NvimRpcError::timeout));
      }
      std::array<pollfd, 2> pfds{};
      nfds_t nfds = 0;
      pfds[nfds++] = pollfd{stdin_fd, POLLOUT, 0};
      const bool watch_stdout = (stdout_fd >= 0 && !stdout_eof);
      if (watch_stdout) {
        pfds[nfds++] = pollfd{stdout_fd, POLLIN, 0};
      }
      const int wait_ms = remaining_poll_ms(deadline);
      const int rc = ::poll(pfds.data(), nfds, wait_ms);
      if (rc < 0) {
        if (errno == EINTR) {
          continue;
        }
        last_error = "poll() failed while writing to Neovim";
        return Result<void>::failure(
            make_rpc_error(ErrorCode::io, NvimRpcError::io_failed));
      }
      if (rc == 0) {
        continue;
      }
      // Drain stdout concurrently to prevent pipe deadlock on large requests.
      if (watch_stdout && (pfds[1].revents & (POLLIN | POLLHUP)) != 0) {
        auto drain = read_available_nonblocking();
        if (!drain.has_value()) {
          return drain;
        }
      }
      if ((pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        last_error = "Neovim stdin pipe closed";
        return Result<void>::failure(make_rpc_error(ErrorCode::io, NvimRpcError::eof));
      }
      if ((pfds[0].revents & POLLOUT) != 0) {
        const ssize_t n =
            ::write(stdin_fd, payload.data() + sent, payload.size() - sent);
        if (n > 0) {
          sent += static_cast<std::size_t>(n);
        } else if (n < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
          last_error = "write() to Neovim stdin failed";
          return Result<void>::failure(
              make_rpc_error(ErrorCode::io, errno == EPIPE ? NvimRpcError::eof
                                                           : NvimRpcError::io_failed));
        }
      }
    }
    return Result<void>::success();
  }

  Result<MsgPackValue> read_next_frame(SteadyClock::time_point deadline) {
    while (true) {
      const auto avail = readable_bytes();
      if (!avail.empty()) {
        auto decoded = decode_msgpack_next(avail, options.msgpack_limits);
        if (decoded.has_value()) {
          consume_read_bytes(decoded.value().consumed);
          return Result<MsgPackValue>::success(std::move(decoded.value().value));
        }
        if (nvim_rpc_error_of(decoded.error()) != NvimRpcError::msgpack_incomplete) {
          last_error = "malformed MsgPack frame from Neovim";
          return Result<MsgPackValue>::failure(decoded.error());
        }
      }

      if (stdout_eof) {
        last_error = "unexpected EOF from Neovim stdout";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::incomplete, NvimRpcError::eof));
      }
      if (stdout_fd < 0) {
        last_error = "Neovim client is not connected";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
      }
      if (SteadyClock::now() >= deadline) {
        last_error = "timed out waiting for Neovim MsgPack-RPC response";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::io, NvimRpcError::timeout));
      }

      pollfd pfd{stdout_fd, POLLIN, 0};
      const int rc = ::poll(&pfd, 1, remaining_poll_ms(deadline));
      if (rc < 0) {
        if (errno == EINTR) {
          continue;
        }
        last_error = "poll() failed while reading from Neovim";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::io, NvimRpcError::io_failed));
      }
      if (rc == 0) {
        continue;
      }
      if ((pfd.revents & POLLNVAL) != 0) {
        last_error = "Neovim stdout fd invalid";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::io, NvimRpcError::io_failed));
      }
      auto read_res = read_available_nonblocking();
      if (!read_res.has_value()) {
        return Result<MsgPackValue>::failure(read_res.error());
      }
    }
  }

  void push_notification(NvimNotification notif) {
    if (notifications.size() >= kMaxQueuedNotifications) {
      notifications.pop_front();
    }
    notifications.push_back(std::move(notif));
  }

  Result<void> send_notification(std::string_view method,
                                 std::vector<MsgPackValue> params,
                                 SteadyClock::time_point deadline) {
    std::vector<MsgPackValue> frame;
    frame.reserve(3U);
    frame.push_back(MsgPackValue::uint64(2U));
    frame.push_back(MsgPackValue::string(std::string{method}));
    frame.push_back(MsgPackValue::array(std::move(params)));
    auto encoded =
        encode_msgpack(MsgPackValue::array(std::move(frame)), options.msgpack_limits);
    if (!encoded.has_value()) {
      return Result<void>::failure(encoded.error());
    }
    return write_all_with_drain(encoded.value(), deadline);
  }

  Result<MsgPackValue> call_rpc(std::string_view method,
                                std::vector<MsgPackValue> params,
                                std::chrono::milliseconds timeout) {
    last_error.clear();
    if (!child_active || stdin_fd < 0 || stdout_fd < 0) {
      last_error = "Neovim client is not connected";
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
    }

    const std::uint32_t msgid = next_msgid++;
    if (next_msgid == 0U) {
      next_msgid = 1U;
    }

    std::vector<MsgPackValue> req;
    req.reserve(4U);
    req.push_back(MsgPackValue::uint64(0U));
    req.push_back(MsgPackValue::uint64(msgid));
    req.push_back(MsgPackValue::string(std::string{method}));
    req.push_back(MsgPackValue::array(std::move(params)));

    auto encoded =
        encode_msgpack(MsgPackValue::array(std::move(req)), options.msgpack_limits);
    if (!encoded.has_value()) {
      last_error = "failed to encode MsgPack-RPC request";
      return Result<MsgPackValue>::failure(encoded.error());
    }

    const auto deadline = SteadyClock::now() + timeout;
    auto write_res = write_all_with_drain(encoded.value(), deadline);
    if (!write_res.has_value()) {
      return Result<MsgPackValue>::failure(write_res.error());
    }

    while (true) {
      auto frame_res = read_next_frame(deadline);
      if (!frame_res.has_value()) {
        return Result<MsgPackValue>::failure(frame_res.error());
      }
      const auto *arr = frame_res.value().as_array();
      if (arr == nullptr || arr->size() < 3U) {
        last_error = "MsgPack-RPC frame is not a valid message array";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
      }
      const auto msg_type = (*arr)[0U].as_uint64();
      if (!msg_type.has_value()) {
        last_error = "MsgPack-RPC frame missing integer message type";
        return Result<MsgPackValue>::failure(
            make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
      }

      if (*msg_type == 2U) {
        // Notification: [2, method, params]
        const auto *notif_method = (*arr)[1U].as_string();
        const auto *notif_params = (*arr)[2U].as_array();
        if (notif_method != nullptr && notif_params != nullptr) {
          push_notification(NvimNotification{*notif_method, notif_params->items});
        }
        continue;
      }

      if (*msg_type == 0U && arr->size() >= 4U) {
        // Reverse request from server: [0, req_id, method, params]
        // Respond cleanly with unsupported so Neovim never stalls.
        const auto req_id = (*arr)[1U].as_uint64();
        if (req_id.has_value()) {
          std::vector<MsgPackValue> reply;
          reply.reserve(4U);
          reply.push_back(MsgPackValue::uint64(1U));
          reply.push_back(MsgPackValue::uint64(*req_id));
          reply.push_back(MsgPackValue::string("unsupported"));
          reply.push_back(MsgPackValue::nil());
          auto encoded_reply = encode_msgpack(MsgPackValue::array(std::move(reply)),
                                              options.msgpack_limits);
          if (encoded_reply.has_value()) {
            (void)write_all_with_drain(encoded_reply.value(), deadline);
          }
        }
        continue;
      }

      if (*msg_type == 1U) {
        // Response: [1, msgid, error, result]
        if (arr->size() < 4U) {
          last_error = "MsgPack-RPC response has fewer than 4 elements";
          return Result<MsgPackValue>::failure(
              make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
        }
        const auto resp_id = (*arr)[1U].as_uint64();
        if (!resp_id.has_value()) {
          last_error = "MsgPack-RPC response has non-integer msgid";
          return Result<MsgPackValue>::failure(
              make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
        }
        if (*resp_id != static_cast<std::uint64_t>(msgid)) {
          // Stale response from an earlier timed-out request; discard and continue.
          continue;
        }
        if (!(*arr)[2U].is_nil()) {
          last_error = describe_rpc_error((*arr)[2U]);
          return Result<MsgPackValue>::failure(
              make_rpc_error(ErrorCode::io, NvimRpcError::rpc_remote_error));
        }
        return Result<MsgPackValue>::success((*arr)[3U]);
      }

      last_error = "unexpected MsgPack-RPC message type";
      return Result<MsgPackValue>::failure(
          make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
    }
  }

  void shutdown_cleanly() noexcept {
    if (child_active && stdin_fd >= 0) {
      // Best-effort graceful exit via nvim_command("qa!") notification.
      std::vector<MsgPackValue> qa_args;
      qa_args.push_back(MsgPackValue::string("qa!"));
      const auto qa_deadline = SteadyClock::now() + std::chrono::milliseconds{200};
      (void)send_notification("nvim_command", std::move(qa_args), qa_deadline);
    }

    close_fd_if_open(stdin_fd);
    close_fd_if_open(stdout_fd);
    stdout_eof = true;

    if (!child_active || pid <= 0) {
      pid = -1;
      child_active = false;
      return;
    }

    auto wait_until = [this](SteadyClock::time_point deadline) noexcept -> bool {
      while (true) {
        int status = 0;
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid || (r < 0 && errno == ECHILD)) {
          return true;
        }
        if (r < 0 && errno == EINTR) {
          continue;
        }
        if (SteadyClock::now() >= deadline) {
          return false;
        }
        (void)::poll(nullptr, 0, 5);
      }
    };

    const auto grace = options.shutdown_grace.count() > 0
                           ? options.shutdown_grace
                           : std::chrono::milliseconds{200};
    bool reaped = wait_until(SteadyClock::now() + grace);
    if (!reaped) {
      (void)::kill(-pid, SIGTERM);
      (void)::kill(pid, SIGTERM);
      reaped = wait_until(SteadyClock::now() + std::chrono::milliseconds{500});
    }
    if (!reaped) {
      (void)::kill(-pid, SIGKILL);
      (void)::kill(pid, SIGKILL);
      int status = 0;
      pid_t r = -1;
      do {
        r = ::waitpid(pid, &status, 0);
      } while (r < 0 && errno == EINTR);
    }

    pid = -1;
    child_active = false;
    --blackbird::detail::owned_children;
  }
};

// ============================================================================
// NvimRpcClient Methods
// ============================================================================

NvimRpcClient::NvimRpcClient(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

NvimRpcClient::NvimRpcClient(NvimRpcClient &&other) noexcept = default;
NvimRpcClient &NvimRpcClient::operator=(NvimRpcClient &&other) noexcept = default;
NvimRpcClient::~NvimRpcClient() = default;

Result<NvimRpcClient> NvimRpcClient::spawn(NvimClientOptions options) {
  if (options.executable.empty() ||
      options.executable.find('\0') != std::string::npos) {
    return Result<NvimRpcClient>::failure(
        make_rpc_error(ErrorCode::invalid_range, NvimRpcError::invalid_argument));
  }
  if (options.default_timeout.count() <= 0) {
    options.default_timeout = std::chrono::milliseconds{5000};
  }

  int in_pipe[2]{-1, -1};
  int out_pipe[2]{-1, -1};
  pid_t spawned_pid = -1;
  int spawn_rc = 0;

  {
    const std::lock_guard<std::mutex> lock{blackbird::detail::process_spawn_mutex};

    if (!create_cloexec_pipe(in_pipe)) {
      return Result<NvimRpcClient>::failure(
          make_rpc_error(ErrorCode::io, NvimRpcError::pipe_failed));
    }
    if (!create_cloexec_pipe(out_pipe)) {
      close_fd_if_open(in_pipe[0]);
      close_fd_if_open(in_pipe[1]);
      return Result<NvimRpcClient>::failure(
          make_rpc_error(ErrorCode::io, NvimRpcError::pipe_failed));
    }

    std::vector<std::string> args = {
        options.executable, "--headless", "--embed", "--clean", "-n",
    };
    std::vector<char *> argv;
    argv.reserve(args.size() + 1U);
    for (auto &arg : args) {
      argv.push_back(arg.data());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attr;
    bool actions_init = false;
    bool attr_init = false;

    spawn_rc = ::posix_spawn_file_actions_init(&actions);
    if (spawn_rc == 0) {
      actions_init = true;
      spawn_rc = ::posix_spawnattr_init(&attr);
    }
    if (spawn_rc == 0) {
      attr_init = true;
      spawn_rc = ::posix_spawn_file_actions_adddup2(&actions, in_pipe[0], STDIN_FILENO);
    }
    if (spawn_rc == 0) {
      spawn_rc =
          ::posix_spawn_file_actions_adddup2(&actions, out_pipe[1], STDOUT_FILENO);
    }
    if (spawn_rc == 0) {
      spawn_rc = ::posix_spawn_file_actions_addopen(&actions, STDERR_FILENO,
                                                    "/dev/null", O_WRONLY, 0);
    }
    if (spawn_rc == 0 && options.working_directory.has_value() &&
        !options.working_directory->empty()) {
#if defined(__APPLE__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) &&    \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 260000
      spawn_rc = ::posix_spawn_file_actions_addchdir(
          &actions, options.working_directory->c_str());
#else
      spawn_rc = ::posix_spawn_file_actions_addchdir_np(
          &actions, options.working_directory->c_str());
#endif
    }
    if (spawn_rc == 0) {
      spawn_rc = ::posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP |
                                                       POSIX_SPAWN_SETSIGMASK);
    }
    if (spawn_rc == 0) {
      spawn_rc = ::posix_spawnattr_setpgroup(&attr, 0);
    }
    if (spawn_rc == 0) {
      sigset_t empty_mask{};
      sigemptyset(&empty_mask);
      spawn_rc = ::posix_spawnattr_setsigmask(&attr, &empty_mask);
    }
    if (spawn_rc == 0) {
      if (options.executable.find('/') != std::string::npos) {
        spawn_rc =
            ::posix_spawn(&spawned_pid, argv[0], &actions, &attr, argv.data(), environ);
      } else {
        spawn_rc = ::posix_spawnp(&spawned_pid, argv[0], &actions, &attr, argv.data(),
                                  environ);
      }
    }

    if (attr_init) {
      (void)::posix_spawnattr_destroy(&attr);
    }
    if (actions_init) {
      (void)::posix_spawn_file_actions_destroy(&actions);
    }

    // Close child-side pipe ends in parent unconditionally.
    close_fd_if_open(in_pipe[0]);
    close_fd_if_open(out_pipe[1]);

    if (spawn_rc != 0) {
      close_fd_if_open(in_pipe[1]);
      close_fd_if_open(out_pipe[0]);
      return Result<NvimRpcClient>::failure(
          make_rpc_error(ErrorCode::io, NvimRpcError::spawn_failed));
    }

    ++blackbird::detail::owned_children;
  }

  auto impl = std::make_unique<Impl>();
  impl->options = std::move(options);
  impl->pid = spawned_pid;
  impl->child_active = true;
  impl->stdin_fd = in_pipe[1];
  impl->stdout_fd = out_pipe[0];

#ifdef F_SETNOSIGPIPE
  if (::fcntl(impl->stdin_fd, F_SETNOSIGPIPE, 1) < 0) {
    impl->shutdown_cleanly();
    return Result<NvimRpcClient>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::pipe_failed));
  }
#endif
  if (::fcntl(impl->stdin_fd, F_SETFL, O_NONBLOCK) < 0 ||
      ::fcntl(impl->stdout_fd, F_SETFL, O_NONBLOCK) < 0) {
    impl->shutdown_cleanly();
    return Result<NvimRpcClient>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::pipe_failed));
  }

  NvimRpcClient client{std::move(impl)};

  // Harden the embedded Neovim session immediately and confirm MsgPack-RPC liveness.
  std::vector<MsgPackValue> rtp_list;
  rtp_list.reserve(client.impl_->options.extra_runtimepaths.size());
  for (const auto &path : client.impl_->options.extra_runtimepaths) {
    rtp_list.push_back(MsgPackValue::string(path.string()));
  }
  std::vector<MsgPackValue> init_args;
  init_args.push_back(MsgPackValue::array(std::move(rtp_list)));
  auto init_res = client.nvim_exec_lua(kInitSessionLua, std::move(init_args));
  if (!init_res.has_value()) {
    const Error err = init_res.error();
    client.close();
    return Result<NvimRpcClient>::failure(err);
  }

  return Result<NvimRpcClient>::success(std::move(client));
}

bool NvimRpcClient::is_open() const noexcept {
  return impl_ != nullptr && impl_->child_active && impl_->stdin_fd >= 0 &&
         impl_->stdout_fd >= 0;
}

std::int64_t NvimRpcClient::child_pid() const noexcept {
  return (impl_ != nullptr && impl_->child_active)
             ? static_cast<std::int64_t>(impl_->pid)
             : -1;
}

const std::string &NvimRpcClient::last_error_message() const noexcept {
  static const std::string kEmpty;
  const Impl *ptr = impl_.get();
  if (ptr != nullptr) {
    return ptr->last_error;
  }
  return kEmpty;
}

Result<MsgPackValue>
NvimRpcClient::call(std::string_view method, std::vector<MsgPackValue> params,
                    std::optional<std::chrono::milliseconds> timeout) {
  if (impl_ == nullptr) {
    return Result<MsgPackValue>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
  }
  const auto effective_timeout = timeout.value_or(impl_->options.default_timeout);
  return impl_->call_rpc(method, std::move(params), effective_timeout);
}

Result<void> NvimRpcClient::notify(std::string_view method,
                                   std::vector<MsgPackValue> params,
                                   std::optional<std::chrono::milliseconds> timeout) {
  if (impl_ == nullptr || !impl_->child_active) {
    return Result<void>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
  }
  const auto effective_timeout = timeout.value_or(impl_->options.default_timeout);
  return impl_->send_notification(method, std::move(params),
                                  SteadyClock::now() + effective_timeout);
}

Result<MsgPackValue>
NvimRpcClient::nvim_eval(std::string_view expr,
                         std::optional<std::chrono::milliseconds> timeout) {
  std::vector<MsgPackValue> params;
  params.push_back(MsgPackValue::string(std::string{expr}));
  return call("nvim_eval", std::move(params), timeout);
}

Result<MsgPackValue>
NvimRpcClient::nvim_exec_lua(std::string_view code, std::vector<MsgPackValue> args,
                             std::optional<std::chrono::milliseconds> timeout) {
  std::vector<MsgPackValue> params;
  params.reserve(2U);
  params.push_back(MsgPackValue::string(std::string{code}));
  params.push_back(MsgPackValue::array(std::move(args)));
  return call("nvim_exec_lua", std::move(params), timeout);
}

Result<void>
NvimRpcClient::nvim_command(std::string_view command,
                            std::optional<std::chrono::milliseconds> timeout) {
  std::vector<MsgPackValue> params;
  params.push_back(MsgPackValue::string(std::string{command}));
  auto res = call("nvim_command", std::move(params), timeout);
  if (!res.has_value()) {
    return Result<void>::failure(res.error());
  }
  return Result<void>::success();
}

Result<std::vector<NvimAstCapture>>
NvimRpcClient::ast_query(const NvimAstQueryRequest &request) {
  if (impl_ == nullptr || !impl_->child_active) {
    return Result<std::vector<NvimAstCapture>>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
  }
  if (!validate_language_name(request.language) || request.treesitter_query.empty() ||
      request.max_captures == 0U) {
    impl_->last_error = "invalid ast_query language, query, or max_captures";
    return Result<std::vector<NvimAstCapture>>::failure(
        make_rpc_error(ErrorCode::invalid_range, NvimRpcError::invalid_argument));
  }

  std::vector<MsgPackValue> args;
  args.reserve(4U);
  args.push_back(MsgPackValue::string(request.language));
  args.push_back(MsgPackValue::string(request.source_text));
  args.push_back(MsgPackValue::string(request.treesitter_query));
  args.push_back(MsgPackValue::uint64(request.max_captures));

  auto res = nvim_exec_lua(kAstQueryLua, std::move(args), request.timeout);
  if (!res.has_value()) {
    return Result<std::vector<NvimAstCapture>>::failure(res.error());
  }

  const auto *map = res.value().as_map();
  if (map == nullptr) {
    impl_->last_error = "ast_query returned non-map payload";
    return Result<std::vector<NvimAstCapture>>::failure(
        make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
  }
  const auto *ok_val = map->find("ok");
  const auto ok_bool = ok_val != nullptr ? ok_val->as_bool() : std::nullopt;
  if (!ok_bool.has_value() || !*ok_bool) {
    const auto *err_val = map->find("err");
    if (err_val != nullptr && err_val->as_string() != nullptr) {
      impl_->last_error = *err_val->as_string();
    } else {
      impl_->last_error = "Tree-sitter query failed";
    }
    return Result<std::vector<NvimAstCapture>>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::treesitter_error));
  }

  const auto *caps_val = map->find("captures");
  if (caps_val == nullptr) {
    return Result<std::vector<NvimAstCapture>>::success({});
  }
  // Empty Lua table `{}` encodes as empty map or empty array in Neovim MsgPack-RPC.
  if (const auto *empty_map = caps_val->as_map();
      empty_map != nullptr && empty_map->empty()) {
    return Result<std::vector<NvimAstCapture>>::success({});
  }
  const auto *caps_arr = caps_val->as_array();
  if (caps_arr == nullptr) {
    impl_->last_error = "ast_query captures field is not an array";
    return Result<std::vector<NvimAstCapture>>::failure(
        make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
  }

  std::vector<NvimAstCapture> out;
  out.reserve(caps_arr->size());
  for (const auto &entry : caps_arr->items) {
    const auto *row = entry.as_array();
    if (row == nullptr || row->size() < 7U) {
      impl_->last_error = "ast_query capture entry malformed";
      return Result<std::vector<NvimAstCapture>>::failure(
          make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
    }
    const auto *cap_name = (*row)[0U].as_string();
    const auto *node_type = (*row)[1U].as_string();
    const auto sr = (*row)[2U].as_uint64();
    const auto sc = (*row)[3U].as_uint64();
    const auto er = (*row)[4U].as_uint64();
    const auto ec = (*row)[5U].as_uint64();
    const auto *text = (*row)[6U].as_string();
    if (cap_name == nullptr || node_type == nullptr || !sr.has_value() ||
        !sc.has_value() || !er.has_value() || !ec.has_value() || text == nullptr) {
      impl_->last_error = "ast_query capture fields had unexpected types";
      return Result<std::vector<NvimAstCapture>>::failure(
          make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
    }
    NvimAstCapture capture;
    capture.capture_name = *cap_name;
    capture.node_type = *node_type;
    capture.start_row = static_cast<std::uint32_t>(*sr);
    capture.start_col = static_cast<std::uint32_t>(*sc);
    capture.end_row = static_cast<std::uint32_t>(*er);
    capture.end_col = static_cast<std::uint32_t>(*ec);
    capture.text = *text;
    out.push_back(std::move(capture));
  }

  return Result<std::vector<NvimAstCapture>>::success(std::move(out));
}

Result<NvimEditProposal>
NvimRpcClient::scratch_edit(const NvimScratchEditRequest &request) {
  if (impl_ == nullptr || !impl_->child_active) {
    return Result<NvimEditProposal>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::not_connected));
  }

  const auto validation = validate_scratch_script(request.script, request.is_lua);
  if (!validation.allowed) {
    impl_->last_error = validation.reason;
    return Result<NvimEditProposal>::failure(
        make_rpc_error(ErrorCode::unsupported, NvimRpcError::unsafe_script_rejected));
  }

  std::vector<MsgPackValue> args;
  args.reserve(3U);
  args.push_back(MsgPackValue::string(request.source_text));
  args.push_back(MsgPackValue::string(request.script));
  args.push_back(MsgPackValue::boolean(request.is_lua));

  auto res = nvim_exec_lua(kScratchEditLua, std::move(args), request.timeout);
  if (!res.has_value()) {
    return Result<NvimEditProposal>::failure(res.error());
  }

  const auto *map = res.value().as_map();
  if (map == nullptr) {
    impl_->last_error = "scratch_edit returned non-map payload";
    return Result<NvimEditProposal>::failure(
        make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
  }
  const auto *ok_val = map->find("ok");
  const auto ok_bool = ok_val != nullptr ? ok_val->as_bool() : std::nullopt;
  if (!ok_bool.has_value() || !*ok_bool) {
    const auto *err_val = map->find("err");
    if (err_val != nullptr && err_val->as_string() != nullptr) {
      impl_->last_error = *err_val->as_string();
    } else {
      impl_->last_error = "scratch_edit failed in Neovim";
    }
    return Result<NvimEditProposal>::failure(
        make_rpc_error(ErrorCode::io, NvimRpcError::rpc_remote_error));
  }

  const auto *orig_count_val = map->find("original_lines_count");
  const auto *proposed_val = map->find("proposed_text");
  const auto *diff_val = map->find("unified_diff");
  const auto *changed_val = map->find("changed");

  const auto orig_count =
      orig_count_val != nullptr ? orig_count_val->as_uint64() : std::nullopt;
  const auto *proposed = proposed_val != nullptr ? proposed_val->as_string() : nullptr;
  const auto *diff = diff_val != nullptr ? diff_val->as_string() : nullptr;
  const auto changed = changed_val != nullptr ? changed_val->as_bool() : std::nullopt;

  if (!orig_count.has_value() || proposed == nullptr || diff == nullptr ||
      !changed.has_value()) {
    impl_->last_error = "scratch_edit returned incomplete proposal fields";
    return Result<NvimEditProposal>::failure(
        make_rpc_error(ErrorCode::corrupt, NvimRpcError::protocol_violation));
  }

  NvimEditProposal proposal;
  proposal.original_lines_count = static_cast<std::size_t>(*orig_count);
  proposal.proposed_text = *proposed;
  proposal.unified_diff = *diff;
  proposal.changed = *changed;
  return Result<NvimEditProposal>::success(std::move(proposal));
}

std::vector<NvimNotification> NvimRpcClient::drain_notifications() {
  std::vector<NvimNotification> out;
  if (impl_ == nullptr) {
    return out;
  }
  out.reserve(impl_->notifications.size());
  while (!impl_->notifications.empty()) {
    out.push_back(std::move(impl_->notifications.front()));
    impl_->notifications.pop_front();
  }
  return out;
}

void NvimRpcClient::close() noexcept {
  if (impl_ != nullptr) {
    impl_->shutdown_cleanly();
  }
}

// ============================================================================
// Passive Capability Probe
// ============================================================================

NvimCapabilities probe_nvim_capabilities(const NvimProbeOptions &options) {
  NvimCapabilities caps;
  NvimClientOptions client_opts;
  client_opts.executable = options.executable;
  client_opts.default_timeout = options.timeout;
  client_opts.shutdown_grace = std::chrono::milliseconds{500};
  client_opts.extra_runtimepaths = options.extra_runtimepaths;

  auto spawned = NvimRpcClient::spawn(std::move(client_opts));
  if (!spawned.has_value()) {
    caps.available = false;
    caps.diagnostic =
        std::string{nvim_rpc_error_name(nvim_rpc_error_of(spawned.error()))};
    return caps;
  }

  auto &client = spawned.value();
  auto res = client.nvim_exec_lua(kProbeCapabilitiesLua, {}, options.timeout);
  if (!res.has_value()) {
    caps.available = false;
    caps.diagnostic =
        client.last_error_message().empty()
            ? std::string{nvim_rpc_error_name(nvim_rpc_error_of(res.error()))}
            : client.last_error_message();
    client.close();
    return caps;
  }

  const auto *map = res.value().as_map();
  if (map == nullptr) {
    caps.available = false;
    caps.diagnostic = "probe returned non-map payload";
    client.close();
    return caps;
  }

  caps.available = true;
  if (const auto *p = map->find("progpath");
      p != nullptr && p->as_string() != nullptr) {
    caps.executable_path = *p->as_string();
  }
  if (const auto *v = map->find("version_string");
      v != nullptr && v->as_string() != nullptr) {
    caps.version_string = *v->as_string();
  }
  if (const auto *maj = map->find("major"); maj != nullptr) {
    if (const auto n = maj->as_int64(); n.has_value()) {
      caps.version_major = static_cast<int>(*n);
    }
  }
  if (const auto *min = map->find("minor"); min != nullptr) {
    if (const auto n = min->as_int64(); n.has_value()) {
      caps.version_minor = static_cast<int>(*n);
    }
  }
  if (const auto *pat = map->find("patch"); pat != nullptr) {
    if (const auto n = pat->as_int64(); n.has_value()) {
      caps.version_patch = static_cast<int>(*n);
    }
  }
  if (const auto *ts = map->find("has_treesitter"); ts != nullptr) {
    caps.has_treesitter = ts->as_bool().value_or(false);
  }
  if (const auto *vd = map->find("has_vim_diff"); vd != nullptr) {
    caps.has_vim_diff = vd->as_bool().value_or(false);
  }
  if (const auto *parsers = map->find("parsers"); parsers != nullptr) {
    if (const auto *arr = parsers->as_array(); arr != nullptr) {
      caps.treesitter_parsers.reserve(arr->size());
      for (const auto &item : arr->items) {
        if (const auto *name = item.as_string(); name != nullptr && !name->empty()) {
          caps.treesitter_parsers.push_back(*name);
        }
      }
    }
  }

  client.close();
  return caps;
}

} // namespace blackbird
