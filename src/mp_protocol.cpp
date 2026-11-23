#include "blackbird/mp_protocol.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace blackbird::mp {

namespace {

constexpr std::uint8_t kDummyEmptyByte = 0U;

const unsigned char *non_null_bytes(std::span<const std::uint8_t> data) noexcept {
  return data.empty() ? &kDummyEmptyByte : data.data();
}

template <typename T> Result<T> fail(ErrorCode code, MpError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, MpError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

struct EvpPkeyDeleter {
  void operator()(EVP_PKEY *key) const noexcept {
    if (key != nullptr) {
      EVP_PKEY_free(key);
    }
  }
};

struct EvpMdCtxDeleter {
  void operator()(EVP_MD_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      EVP_MD_CTX_free(ctx);
    }
  }
};

struct BnCtxDeleter {
  void operator()(BN_CTX *ctx) const noexcept {
    if (ctx != nullptr) {
      BN_CTX_free(ctx);
    }
  }
};

using UniqueEvpPkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniqueEvpMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
using UniqueBnCtx = std::unique_ptr<BN_CTX, BnCtxDeleter>;

class BnCtxScope {
public:
  explicit BnCtxScope(BN_CTX *ctx) noexcept : ctx_(ctx) { BN_CTX_start(ctx_); }
  BnCtxScope(const BnCtxScope &) = delete;
  BnCtxScope &operator=(const BnCtxScope &) = delete;
  ~BnCtxScope() { BN_CTX_end(ctx_); }

private:
  BN_CTX *ctx_;
};

constexpr bool is_ascii_digit(char ch) noexcept { return ch >= '0' && ch <= '9'; }
constexpr bool is_ascii_lower(char ch) noexcept { return ch >= 'a' && ch <= 'z'; }
constexpr bool is_ascii_upper(char ch) noexcept { return ch >= 'A' && ch <= 'Z'; }
constexpr bool is_ascii_alnum(char ch) noexcept {
  return is_ascii_digit(ch) || is_ascii_lower(ch) || is_ascii_upper(ch);
}

constexpr char to_ascii_lower(char ch) noexcept {
  return is_ascii_upper(ch) ? static_cast<char>(ch + ('a' - 'A')) : ch;
}

constexpr std::string_view trim_http_ows(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1U);
  }
  return text;
}

constexpr std::string_view trim_ascii_ws(std::string_view text) noexcept {
  auto is_ws = [](char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\v' ||
           ch == '\f';
  };
  while (!text.empty() && is_ws(text.front())) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && is_ws(text.back())) {
    text.remove_suffix(1U);
  }
  return text;
}

constexpr std::optional<std::int64_t> checked_sub_i64(std::int64_t lhs,
                                                      std::int64_t rhs) noexcept {
  std::int64_t out = 0;
  if (__builtin_sub_overflow(lhs, rhs, &out)) {
    return std::nullopt;
  }
  return out;
}

constexpr std::int64_t saturating_add_i64(std::int64_t lhs, std::int64_t rhs) noexcept {
  std::int64_t out = 0;
  if (__builtin_add_overflow(lhs, rhs, &out)) {
    return rhs >= 0 ? std::numeric_limits<std::int64_t>::max()
                    : std::numeric_limits<std::int64_t>::min();
  }
  return out;
}

constexpr std::int64_t saturating_sub_i64(std::int64_t lhs, std::int64_t rhs) noexcept {
  std::int64_t out = 0;
  if (__builtin_sub_overflow(lhs, rhs, &out)) {
    return rhs >= 0 ? std::numeric_limits<std::int64_t>::min()
                    : std::numeric_limits<std::int64_t>::max();
  }
  return out;
}

constexpr std::int64_t saturating_mul_i64(std::int64_t lhs, std::int64_t rhs) noexcept {
  std::int64_t out = 0;
  if (__builtin_mul_overflow(lhs, rhs, &out)) {
    const bool negative = (lhs < 0) != (rhs < 0);
    return negative ? std::numeric_limits<std::int64_t>::min()
                    : std::numeric_limits<std::int64_t>::max();
  }
  return out;
}

// ---------------------------------------------------------------------------
// Strict RFC 8032 / Chalkias et al. Ed25519 boundary checks
// ---------------------------------------------------------------------------

// Rejects non-canonical Edwards Y coordinate >= p = 2^255 - 19 (little-endian).
bool is_non_canonical_field_elem(
    const std::array<std::uint8_t, 32> &le_bytes) noexcept {
  if (le_bytes[31] != 0x7fU) {
    return false;
  }
  for (std::size_t i = 1U; i < 31U; ++i) {
    if (le_bytes[i] != 0xffU) {
      return false;
    }
  }
  return le_bytes[0] >= 0xedU;
}

// Group order L = 2^252 + 27742317777372353535851937790883648493 (little-endian).
inline constexpr std::array<std::uint8_t, 32> kEd25519GroupOrderL = {
    0xedU, 0xd3U, 0xf5U, 0x5cU, 0x1aU, 0x63U, 0x12U, 0x58U, 0xd6U, 0x9cU, 0xf7U,
    0xa2U, 0xdeU, 0xf9U, 0xdeU, 0x14U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
    0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x10U,
};

bool is_non_canonical_scalar(std::span<const std::uint8_t, 32> scalar_le) noexcept {
  for (std::size_t i = 32U; i > 0U; --i) {
    const std::size_t idx = i - 1U;
    if (scalar_le[idx] > kEd25519GroupOrderL[idx]) {
      return true;
    }
    if (scalar_le[idx] < kEd25519GroupOrderL[idx]) {
      return false;
    }
  }
  return true; // scalar == L is non-canonical
}

// All 8 Ed25519 small-order torsion points share 5 canonical Y coordinates (sign bit
// cleared). Checking against these 5 Y values with CRYPTO_memcmp rejects all 8
// small-order points plus the 2 non-canonical sign-bit variants of (0, +/-1).
inline constexpr std::array<std::array<std::uint8_t, 32>, 5> kSmallOrderTorsionYs = {{
    // Order 1: (0, 1)
    {0x01U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
     0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
     0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U},
    // Order 2: (0, -1)
    {0xecU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
     0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
     0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x7fU},
    // Order 4: (+/- sqrt(-1), 0)
    {0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
     0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
     0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U},
    // Order 8 pair A
    {0x26U, 0xe8U, 0x95U, 0x8fU, 0xc2U, 0xb2U, 0x27U, 0xb0U, 0x45U, 0xc3U, 0xf4U,
     0x89U, 0xf2U, 0xefU, 0x98U, 0xf0U, 0xd5U, 0xdfU, 0xacU, 0x05U, 0xd3U, 0xc6U,
     0x33U, 0x39U, 0xb1U, 0x38U, 0x02U, 0x88U, 0x6dU, 0x53U, 0xfcU, 0x05U},
    // Order 8 pair B
    {0xc7U, 0x17U, 0x6aU, 0x70U, 0x3dU, 0x4dU, 0xd8U, 0x4fU, 0xbaU, 0x3cU, 0x0bU,
     0x76U, 0x0dU, 0x10U, 0x67U, 0x0fU, 0x2aU, 0x20U, 0x53U, 0xfaU, 0x2cU, 0x39U,
     0xccU, 0xc6U, 0x4eU, 0xc7U, 0xfdU, 0x77U, 0x92U, 0xacU, 0x03U, 0x7aU},
}};

bool is_small_order_point_y(const std::array<std::uint8_t, 32> &y_cleared) noexcept {
  for (const auto &weak_y : kSmallOrderTorsionYs) {
    if (CRYPTO_memcmp(y_cleared.data(), weak_y.data(), weak_y.size()) == 0) {
      return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Strict RFC 4648 Base64 (standard & base64url) text codecs
// ---------------------------------------------------------------------------

std::string base64_std_encode(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                                 static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[triple & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t triple = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::string base64_url_encode_nopad(std::span<const std::uint8_t> bytes) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                                 static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[triple & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t triple = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
  } else if (rem == 2U) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                                 (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
  }
  return out;
}

std::optional<std::uint8_t> base64_std_value(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z') {
    return static_cast<std::uint8_t>(ch - 'A');
  }
  if (ch >= 'a' && ch <= 'z') {
    return static_cast<std::uint8_t>(ch - 'a' + 26);
  }
  if (ch >= '0' && ch <= '9') {
    return static_cast<std::uint8_t>(ch - '0' + 52);
  }
  if (ch == '+') {
    return 62U;
  }
  if (ch == '/') {
    return 63U;
  }
  return std::nullopt;
}

// Strict RFC 4648 standard Base64 decode: exact multiple of 4, canonical '=' padding,
// non-zero unused pad bits rejected.
std::optional<std::vector<std::uint8_t>> base64_std_decode(std::string_view text) {
  if (text.empty()) {
    return std::vector<std::uint8_t>{};
  }
  if ((text.size() % 4U) != 0U) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> out;
  out.reserve((text.size() / 4U) * 3U);
  for (std::size_t i = 0U; i < text.size(); i += 4U) {
    const bool is_last = (i + 4U == text.size());
    const char c0 = text[i];
    const char c1 = text[i + 1U];
    const char c2 = text[i + 2U];
    const char c3 = text[i + 3U];
    const auto v0 = base64_std_value(c0);
    const auto v1 = base64_std_value(c1);
    if (!v0.has_value() || !v1.has_value()) {
      return std::nullopt;
    }
    if (c2 == '=' && c3 == '=') {
      if (!is_last) {
        return std::nullopt;
      }
      if ((*v1 & 0x0fU) != 0U) {
        return std::nullopt;
      }
      out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
      continue;
    }
    const auto v2 = base64_std_value(c2);
    if (!v2.has_value()) {
      return std::nullopt;
    }
    if (c3 == '=') {
      if (!is_last) {
        return std::nullopt;
      }
      if ((*v2 & 0x03U) != 0U) {
        return std::nullopt;
      }
      out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
      out.push_back(static_cast<std::uint8_t>(((*v1 & 0x0fU) << 4U) | (*v2 >> 2U)));
      continue;
    }
    const auto v3 = base64_std_value(c3);
    if (!v3.has_value()) {
      return std::nullopt;
    }
    out.push_back(static_cast<std::uint8_t>((*v0 << 2U) | (*v1 >> 4U)));
    out.push_back(static_cast<std::uint8_t>(((*v1 & 0x0fU) << 4U) | (*v2 >> 2U)));
    out.push_back(static_cast<std::uint8_t>(((*v2 & 0x03U) << 6U) | *v3));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Strict UTF-8 validation (RFC 3629)
// ---------------------------------------------------------------------------

bool is_valid_utf8(std::span<const std::uint8_t> bytes) noexcept {
  std::size_t i = 0U;
  while (i < bytes.size()) {
    const std::uint8_t b0 = bytes[i];
    if (b0 <= 0x7fU) {
      ++i;
      continue;
    }
    if (b0 >= 0xc2U && b0 <= 0xdfU) {
      if (i + 1U >= bytes.size()) {
        return false;
      }
      const std::uint8_t b1 = bytes[i + 1U];
      if ((b1 & 0xc0U) != 0x80U) {
        return false;
      }
      i += 2U;
      continue;
    }
    if (b0 >= 0xe0U && b0 <= 0xefU) {
      if (i + 2U >= bytes.size()) {
        return false;
      }
      const std::uint8_t b1 = bytes[i + 1U];
      const std::uint8_t b2 = bytes[i + 2U];
      if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U) {
        return false;
      }
      if (b0 == 0xe0U && b1 < 0xa0U) {
        return false;
      }
      if (b0 == 0xedU && b1 >= 0xa0U) {
        return false; // UTF-16 surrogates
      }
      i += 3U;
      continue;
    }
    if (b0 >= 0xf0U && b0 <= 0xf4U) {
      if (i + 3U >= bytes.size()) {
        return false;
      }
      const std::uint8_t b1 = bytes[i + 1U];
      const std::uint8_t b2 = bytes[i + 2U];
      const std::uint8_t b3 = bytes[i + 3U];
      if ((b1 & 0xc0U) != 0x80U || (b2 & 0xc0U) != 0x80U || (b3 & 0xc0U) != 0x80U) {
        return false;
      }
      if (b0 == 0xf0U && b1 < 0x90U) {
        return false;
      }
      if (b0 == 0xf4U && b1 > 0x8fU) {
        return false;
      }
      i += 4U;
      continue;
    }
    return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Little-endian binary encoding/decoding helpers
// ---------------------------------------------------------------------------

void append_u16_le(std::vector<std::uint8_t> &out, std::uint16_t val) {
  out.push_back(static_cast<std::uint8_t>(val & 0xffU));
  out.push_back(static_cast<std::uint8_t>((val >> 8U) & 0xffU));
}

void append_u32_le(std::vector<std::uint8_t> &out, std::uint32_t val) {
  for (std::size_t i = 0U; i < 4U; ++i) {
    out.push_back(static_cast<std::uint8_t>((val >> (i * 8U)) & 0xffU));
  }
}

void append_u64_le(std::vector<std::uint8_t> &out, std::uint64_t val) {
  for (std::size_t i = 0U; i < 8U; ++i) {
    out.push_back(static_cast<std::uint8_t>((val >> (i * 8U)) & 0xffU));
  }
}

void append_bytes(std::vector<std::uint8_t> &out, std::span<const std::uint8_t> bytes) {
  out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_string_bytes(std::vector<std::uint8_t> &out, std::string_view text) {
  for (const char ch : text) {
    out.push_back(static_cast<std::uint8_t>(ch));
  }
}

class BinaryReader {
public:
  explicit BinaryReader(std::span<const std::uint8_t> buf) noexcept : buf_(buf) {}

  Result<std::span<const std::uint8_t>> take(std::size_t count) {
    if (count > buf_.size() - pos_) {
      return fail<std::span<const std::uint8_t>>(ErrorCode::corrupt,
                                                 MpError::mp1_truncated);
    }
    const auto slice = buf_.subspan(pos_, count);
    pos_ += count;
    return Result<std::span<const std::uint8_t>>::success(slice);
  }

  Result<std::uint8_t> read_u8() {
    const auto s = take(1U);
    if (!s.has_value()) {
      return Result<std::uint8_t>::failure(s.error());
    }
    return Result<std::uint8_t>::success(s.value()[0]);
  }

  Result<bool> read_bool() {
    const auto b = read_u8();
    if (!b.has_value()) {
      return Result<bool>::failure(b.error());
    }
    if (b.value() == 0U) {
      return Result<bool>::success(false);
    }
    if (b.value() == 1U) {
      return Result<bool>::success(true);
    }
    return fail<bool>(ErrorCode::corrupt, MpError::mp1_invalid_bool);
  }

  Result<std::uint16_t> read_u16() {
    const auto s = take(2U);
    if (!s.has_value()) {
      return Result<std::uint16_t>::failure(s.error());
    }
    const auto v =
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(s.value()[0]) |
                                   (static_cast<std::uint16_t>(s.value()[1]) << 8U));
    return Result<std::uint16_t>::success(v);
  }

  Result<std::uint32_t> read_u32() {
    const auto s = take(4U);
    if (!s.has_value()) {
      return Result<std::uint32_t>::failure(s.error());
    }
    std::uint32_t v = 0U;
    for (std::size_t i = 0U; i < 4U; ++i) {
      v |= static_cast<std::uint32_t>(s.value()[i]) << (i * 8U);
    }
    return Result<std::uint32_t>::success(v);
  }

  Result<std::uint64_t> read_u64_safe() {
    const auto s = take(8U);
    if (!s.has_value()) {
      return Result<std::uint64_t>::failure(s.error());
    }
    std::uint64_t v = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
      v |= static_cast<std::uint64_t>(s.value()[i]) << (i * 8U);
    }
    if (v > kMaxSafeId) {
      return fail<std::uint64_t>(ErrorCode::invalid_range,
                                 MpError::mp1_safe_int_exceeded);
    }
    return Result<std::uint64_t>::success(v);
  }

  Result<Ed25519PubKey> read_pubkey() {
    const auto s = take(32U);
    if (!s.has_value()) {
      return Result<Ed25519PubKey>::failure(s.error());
    }
    Ed25519PubKey out{};
    std::memcpy(out.data(), s.value().data(), out.size());
    return Result<Ed25519PubKey>::success(out);
  }

  Result<std::vector<std::uint8_t>> read_bytes_u16(std::size_t max_len) {
    const auto len = read_u16();
    if (!len.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(len.error());
    }
    if (static_cast<std::size_t>(len.value()) > max_len) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                             MpError::mp1_invalid_count);
    }
    const auto s = take(static_cast<std::size_t>(len.value()));
    if (!s.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(s.error());
    }
    return Result<std::vector<std::uint8_t>>::success(
        std::vector<std::uint8_t>(s.value().begin(), s.value().end()));
  }

  bool at_end() const noexcept { return pos_ == buf_.size(); }

private:
  std::span<const std::uint8_t> buf_;
  std::size_t pos_ = 0U;
};

Result<std::uint64_t> check_safe_u64(std::uint64_t value) {
  if (value > kMaxSafeId) {
    return fail<std::uint64_t>(ErrorCode::invalid_range,
                               MpError::mp1_safe_int_exceeded);
  }
  return Result<std::uint64_t>::success(value);
}

Result<std::uint64_t> check_positive_safe_u64(std::uint64_t value) {
  if (value == 0U) {
    return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_zero);
  }
  if (value > kMaxSafeId) {
    return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_exceeds_safe_int);
  }
  return Result<std::uint64_t>::success(value);
}

// ---------------------------------------------------------------------------
// EndpointDescriptor address & enum helpers
// ---------------------------------------------------------------------------

Result<TransportKind> transport_kind_from_u8(std::uint8_t raw) {
  if (raw == 1U) {
    return Result<TransportKind>::success(TransportKind::iroh_quic);
  }
  if (raw == 2U) {
    return Result<TransportKind>::success(TransportKind::direct_quic);
  }
  return fail<TransportKind>(ErrorCode::corrupt, MpError::invalid_transport_kind);
}

Result<RelayPolicy> relay_policy_from_u8(std::uint8_t raw) {
  if (raw == 0U) {
    return Result<RelayPolicy>::success(RelayPolicy::allow_relays);
  }
  if (raw == 1U) {
    return Result<RelayPolicy>::success(RelayPolicy::force_relays);
  }
  if (raw == 2U) {
    return Result<RelayPolicy>::success(RelayPolicy::no_relays);
  }
  return fail<RelayPolicy>(ErrorCode::corrupt, MpError::invalid_relay_policy);
}

std::uint16_t direct_addr_port(const DirectAddr &addr) noexcept {
  return std::visit([](const auto &a) noexcept { return a.port; }, addr);
}

std::size_t direct_addr_encoded_len(const DirectAddr &addr) noexcept {
  if (std::holds_alternative<DirectAddrV4>(addr)) {
    return 1U + 4U + 2U;
  }
  return 1U + 16U + 2U;
}

bool is_always_disallowed_addr(const DirectAddr &addr) noexcept {
  if (const auto *v4 = std::get_if<DirectAddrV4>(&addr)) {
    const std::uint8_t a = v4->ip[0];
    return a == 0U || a == 127U || a >= 224U;
  }
  const auto &v6 = std::get<DirectAddrV6>(addr);
  const auto &ip = v6.ip;
  const bool all_zero = std::all_of(ip.begin(), ip.end(),
                                    [](std::uint8_t b) noexcept { return b == 0U; });
  const bool prefix15_zero = std::all_of(
      ip.begin(), ip.begin() + 15, [](std::uint8_t b) noexcept { return b == 0U; });
  const bool is_loopback = prefix15_zero && ip[15] == 1U;
  const bool is_multicast = ip[0] == 0xffU;
  const bool prefix10_zero = std::all_of(
      ip.begin(), ip.begin() + 10, [](std::uint8_t b) noexcept { return b == 0U; });
  const bool is_v4_mapped = prefix10_zero && ip[10] == 0xffU && ip[11] == 0xffU;
  return all_zero || is_loopback || is_multicast || is_v4_mapped;
}

bool is_private_or_lan_addr(const DirectAddr &addr) noexcept {
  if (const auto *v4 = std::get_if<DirectAddrV4>(&addr)) {
    const std::uint8_t a = v4->ip[0];
    const std::uint8_t b = v4->ip[1];
    return a == 10U || (a == 172U && b >= 16U && b <= 31U) ||
           (a == 192U && b == 168U) || (a == 100U && b >= 64U && b <= 127U) ||
           (a == 169U && b == 254U);
  }
  const auto &v6 = std::get<DirectAddrV6>(addr);
  const std::uint8_t b0 = v6.ip[0];
  const std::uint8_t b1 = v6.ip[1];
  return (b0 & 0xfeU) == 0xfcU || (b0 == 0xfeU && (b1 & 0xc0U) == 0x80U);
}

// ---------------------------------------------------------------------------
// MP1 enum & record codecs
// ---------------------------------------------------------------------------

Result<Opcode> opcode_from_u16(std::uint16_t raw) {
  switch (raw) {
  case 0x0001U:
    return Result<Opcode>::success(Opcode::hello_ack);
  case 0x0002U:
    return Result<Opcode>::success(Opcode::error);
  case 0x0101U:
    return Result<Opcode>::success(Opcode::presence_set);
  case 0x0102U:
    return Result<Opcode>::success(Opcode::presence_snapshot);
  case 0x0103U:
    return Result<Opcode>::success(Opcode::presence_delta);
  case 0x0104U:
    return Result<Opcode>::success(Opcode::social_event);
  case 0x0105U:
    return Result<Opcode>::success(Opcode::party_invite_notify);
  case 0x0201U:
    return Result<Opcode>::success(Opcode::party_snapshot);
  case 0x0202U:
    return Result<Opcode>::success(Opcode::party_member_joined);
  case 0x0203U:
    return Result<Opcode>::success(Opcode::party_endpoint_update);
  case 0x0204U:
    return Result<Opcode>::success(Opcode::party_member_updated);
  case 0x0205U:
    return Result<Opcode>::success(Opcode::party_member_left);
  case 0x0206U:
    return Result<Opcode>::success(Opcode::party_leader_changed);
  case 0x0207U:
    return Result<Opcode>::success(Opcode::party_join_request_event);
  case 0x0208U:
    return Result<Opcode>::success(Opcode::party_disbanded);
  default:
    return fail<Opcode>(ErrorCode::unsupported, MpError::mp1_unknown_opcode);
  }
}

Result<PresenceVisibility> presence_visibility_from_u8(std::uint8_t raw) {
  if (raw <= 3U) {
    return Result<PresenceVisibility>::success(static_cast<PresenceVisibility>(raw));
  }
  return fail<PresenceVisibility>(ErrorCode::corrupt, MpError::mp1_invalid_enum_value);
}

Result<SocialEventKind> social_event_kind_from_u8(std::uint8_t raw) {
  if (raw >= 1U && raw <= 3U) {
    return Result<SocialEventKind>::success(static_cast<SocialEventKind>(raw));
  }
  return fail<SocialEventKind>(ErrorCode::corrupt, MpError::mp1_invalid_enum_value);
}

Result<PartyVisibility> party_visibility_from_u8(std::uint8_t raw) {
  if (raw <= 1U) {
    return Result<PartyVisibility>::success(static_cast<PartyVisibility>(raw));
  }
  return fail<PartyVisibility>(ErrorCode::corrupt, MpError::mp1_invalid_enum_value);
}

Result<PartyJoinMode> party_join_mode_from_u8(std::uint8_t raw) {
  if (raw <= 1U) {
    return Result<PartyJoinMode>::success(static_cast<PartyJoinMode>(raw));
  }
  return fail<PartyJoinMode>(ErrorCode::corrupt, MpError::mp1_invalid_enum_value);
}

Result<MemberLeaveReason> member_leave_reason_from_u8(std::uint8_t raw) {
  if (raw <= 4U) {
    return Result<MemberLeaveReason>::success(static_cast<MemberLeaveReason>(raw));
  }
  return fail<MemberLeaveReason>(ErrorCode::corrupt, MpError::mp1_invalid_enum_value);
}

Result<PartyLeaderChangeReason> party_leader_change_reason_from_u8(std::uint8_t raw) {
  if (raw <= 1U) {
    return Result<PartyLeaderChangeReason>::success(
        static_cast<PartyLeaderChangeReason>(raw));
  }
  return fail<PartyLeaderChangeReason>(ErrorCode::corrupt,
                                       MpError::mp1_invalid_enum_value);
}

Result<PartyDisbandReason> party_disband_reason_from_u8(std::uint8_t raw) {
  if (raw <= 1U) {
    return Result<PartyDisbandReason>::success(static_cast<PartyDisbandReason>(raw));
  }
  return fail<PartyDisbandReason>(ErrorCode::corrupt, MpError::mp1_invalid_enum_value);
}

Result<void> write_presence_entry(std::vector<std::uint8_t> &out,
                                  const PresenceEntry &entry) {
  const auto updated = check_safe_u64(entry.updated_ms);
  if (!updated.has_value()) {
    return Result<void>::failure(updated.error());
  }
  append_bytes(out, entry.account_id.to_le_bytes());
  out.push_back(static_cast<std::uint8_t>(entry.status));
  const std::uint64_t party_raw =
      entry.joinable_party_id.has_value() ? entry.joinable_party_id->value() : 0U;
  append_u64_le(out, party_raw);
  append_u64_le(out, updated.value());
  return Result<void>::success();
}

Result<PresenceEntry> read_presence_entry(BinaryReader &reader) {
  const auto acct_raw = reader.read_u64_safe();
  if (!acct_raw.has_value()) {
    return Result<PresenceEntry>::failure(acct_raw.error());
  }
  const auto account_id = AccountId::create(acct_raw.value());
  if (!account_id.has_value()) {
    return Result<PresenceEntry>::failure(account_id.error());
  }
  const auto status_raw = reader.read_u8();
  if (!status_raw.has_value()) {
    return Result<PresenceEntry>::failure(status_raw.error());
  }
  const auto status = presence_visibility_from_u8(status_raw.value());
  if (!status.has_value()) {
    return Result<PresenceEntry>::failure(status.error());
  }
  const auto party_raw = reader.read_u64_safe();
  if (!party_raw.has_value()) {
    return Result<PresenceEntry>::failure(party_raw.error());
  }
  std::optional<PartyId> joinable_party_id;
  if (party_raw.value() != 0U) {
    const auto pid = PartyId::create(party_raw.value());
    if (!pid.has_value()) {
      return Result<PresenceEntry>::failure(pid.error());
    }
    joinable_party_id = pid.value();
  }
  const auto updated_ms = reader.read_u64_safe();
  if (!updated_ms.has_value()) {
    return Result<PresenceEntry>::failure(updated_ms.error());
  }
  return Result<PresenceEntry>::success(PresenceEntry{
      account_id.value(),
      status.value(),
      joinable_party_id,
      updated_ms.value(),
  });
}

Result<void> validate_party_snapshot(const PartySnapshotMessage &snap) {
  if (snap.max_members < 2U ||
      static_cast<std::size_t>(snap.max_members) > kMaxPartyMembers) {
    return fail_void(ErrorCode::invalid_range, MpError::mp1_invalid_count);
  }
  if (snap.members.size() > static_cast<std::size_t>(snap.max_members)) {
    return fail_void(ErrorCode::invalid_range, MpError::mp1_invalid_count);
  }
  if (const auto ep = check_positive_safe_u64(snap.party_epoch); !ep.has_value()) {
    return Result<void>::failure(ep.error());
  }
  if (const auto r =
          validate_pinned_relay_url(snap.relay_policy, snap.pinned_relay_url);
      !r.has_value()) {
    return r;
  }
  std::set<DeviceId> seen_devices;
  for (const auto &member : snap.members) {
    if (const auto seq = check_positive_safe_u64(member.joined_seq); !seq.has_value()) {
      return Result<void>::failure(seq.error());
    }
    if (!seen_devices.insert(member.device_id).second) {
      return fail_void(ErrorCode::corrupt, MpError::mp1_invalid_count);
    }
    if (const auto ok = member.endpoint.validate_against_policy(snap.relay_policy,
                                                                snap.pinned_relay_url);
        !ok.has_value()) {
      return ok;
    }
  }
  return Result<void>::success();
}

Result<void> write_member_record(std::vector<std::uint8_t> &out,
                                 const PartyMemberRecord &member) {
  if (member.device_cwt.empty() || member.device_cwt.size() > kMaxCwtBytes) {
    return fail_void(ErrorCode::invalid_range, MpError::mp1_invalid_cwt_length);
  }
  const auto ep_bytes = member.endpoint.encode();
  if (!ep_bytes.has_value()) {
    return Result<void>::failure(ep_bytes.error());
  }
  const auto joined_seq = check_positive_safe_u64(member.joined_seq);
  if (!joined_seq.has_value()) {
    return Result<void>::failure(joined_seq.error());
  }
  append_bytes(out, member.device_id.to_le_bytes());
  append_bytes(out, member.account_id.to_le_bytes());
  append_bytes(out, member.root_pubkey);
  append_bytes(out, member.device_pubkey);
  append_u16_le(out, static_cast<std::uint16_t>(member.device_cwt.size()));
  append_bytes(out, member.device_cwt);
  append_u16_le(out, static_cast<std::uint16_t>(ep_bytes.value().size()));
  append_bytes(out, ep_bytes.value());
  append_u64_le(out, joined_seq.value());
  out.push_back(member.connected ? 1U : 0U);
  return Result<void>::success();
}

Result<PartyMemberRecord> read_member_record(BinaryReader &reader) {
  const auto dev_raw = reader.read_u64_safe();
  if (!dev_raw.has_value()) {
    return Result<PartyMemberRecord>::failure(dev_raw.error());
  }
  const auto device_id = DeviceId::create(dev_raw.value());
  if (!device_id.has_value()) {
    return Result<PartyMemberRecord>::failure(device_id.error());
  }
  const auto acct_raw = reader.read_u64_safe();
  if (!acct_raw.has_value()) {
    return Result<PartyMemberRecord>::failure(acct_raw.error());
  }
  const auto account_id = AccountId::create(acct_raw.value());
  if (!account_id.has_value()) {
    return Result<PartyMemberRecord>::failure(account_id.error());
  }
  const auto root_pk = reader.read_pubkey();
  if (!root_pk.has_value()) {
    return Result<PartyMemberRecord>::failure(root_pk.error());
  }
  const auto dev_pk = reader.read_pubkey();
  if (!dev_pk.has_value()) {
    return Result<PartyMemberRecord>::failure(dev_pk.error());
  }
  const auto cwt_bytes = reader.read_bytes_u16(kMaxCwtBytes);
  if (!cwt_bytes.has_value()) {
    return Result<PartyMemberRecord>::failure(cwt_bytes.error());
  }
  if (cwt_bytes.value().empty()) {
    return fail<PartyMemberRecord>(ErrorCode::corrupt, MpError::mp1_invalid_cwt_length);
  }
  const auto ep_bytes = reader.read_bytes_u16(kMaxEndpointDescriptorBytes);
  if (!ep_bytes.has_value()) {
    return Result<PartyMemberRecord>::failure(ep_bytes.error());
  }
  const auto endpoint = EndpointDescriptor::decode(ep_bytes.value());
  if (!endpoint.has_value()) {
    return Result<PartyMemberRecord>::failure(endpoint.error());
  }
  const auto joined_seq = reader.read_u64_safe();
  if (!joined_seq.has_value()) {
    return Result<PartyMemberRecord>::failure(joined_seq.error());
  }
  const auto connected = reader.read_bool();
  if (!connected.has_value()) {
    return Result<PartyMemberRecord>::failure(connected.error());
  }
  return Result<PartyMemberRecord>::success(PartyMemberRecord{
      device_id.value(),
      account_id.value(),
      root_pk.value(),
      dev_pk.value(),
      cwt_bytes.value(),
      endpoint.value(),
      joined_seq.value(),
      connected.value(),
  });
}

// ---------------------------------------------------------------------------
// RFC 9421 helpers
// ---------------------------------------------------------------------------

Result<std::uint8_t> hex_nibble_lower(char ch) {
  if (ch >= '0' && ch <= '9') {
    return Result<std::uint8_t>::success(static_cast<std::uint8_t>(ch - '0'));
  }
  if (ch >= 'a' && ch <= 'f') {
    return Result<std::uint8_t>::success(static_cast<std::uint8_t>(ch - 'a' + 10));
  }
  return fail<std::uint8_t>(ErrorCode::invalid_identity,
                            MpError::rfc9421_invalid_key_id);
}

bool is_party_requests_path(std::string_view path) {
  // Exact match: "/v1/parties/<decimal PartyId>/requests"
  static constexpr std::string_view kPrefix = "/v1/parties/";
  static constexpr std::string_view kSuffix = "/requests";
  if (!path.starts_with(kPrefix) || !path.ends_with(kSuffix)) {
    return false;
  }
  if (path.size() <= kPrefix.size() + kSuffix.size()) {
    return false;
  }
  const std::string_view id_str =
      path.substr(kPrefix.size(), path.size() - kPrefix.size() - kSuffix.size());
  if (id_str.find('/') != std::string_view::npos) {
    return false;
  }
  return PartyId::parse_decimal(id_str).has_value();
}

Result<std::int64_t> parse_sf_int(std::string_view raw) {
  if (raw.empty() || raw.size() > 15U) {
    return fail<std::int64_t>(ErrorCode::corrupt,
                              MpError::rfc9421_invalid_signature_input);
  }
  std::int64_t value = 0;
  for (const char ch : raw) {
    if (!is_ascii_digit(ch)) {
      return fail<std::int64_t>(ErrorCode::corrupt,
                                MpError::rfc9421_invalid_signature_input);
    }
    value = (value * 10) + static_cast<std::int64_t>(ch - '0');
  }
  return Result<std::int64_t>::success(value);
}

Result<std::string> parse_sf_string(std::string_view raw) {
  if (raw.size() < 2U || raw.front() != '"' || raw.back() != '"') {
    return fail<std::string>(ErrorCode::corrupt,
                             MpError::rfc9421_invalid_signature_input);
  }
  const std::string_view inner = raw.substr(1U, raw.size() - 2U);
  for (const char ch : inner) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (ch == '"' || ch == '\\' || byte < 0x20U || byte > 0x7eU) {
      return fail<std::string>(ErrorCode::corrupt,
                               MpError::rfc9421_invalid_signature_input);
    }
  }
  return Result<std::string>::success(std::string{inner});
}

Result<void> validate_nonce(std::string_view nonce) {
  if (nonce.size() < kMinNonceLen || nonce.size() > kMaxNonceLen) {
    return fail_void(ErrorCode::invalid_range, MpError::rfc9421_invalid_nonce);
  }
  for (const char ch : nonce) {
    if (!is_ascii_alnum(ch) && ch != '-' && ch != '_') {
      return fail_void(ErrorCode::invalid_range, MpError::rfc9421_invalid_nonce);
    }
  }
  return Result<void>::success();
}

// ---------------------------------------------------------------------------
// RFC 8949 Deterministic CBOR encoder & strict decoder (for COSE_Sign1 / CWT)
// ---------------------------------------------------------------------------

inline constexpr std::uint64_t kCoseSign1Tag = 18U;
inline constexpr std::int64_t kCwtClaimIss = 1;
inline constexpr std::int64_t kCwtClaimExp = 4;
inline constexpr std::int64_t kCwtClaimIat = 6;
inline constexpr std::int64_t kCwtClaimCnf = 8;

inline constexpr std::int64_t kCnfCoseKey = 1;
inline constexpr std::int64_t kCoseKeyKty = 1;
inline constexpr std::int64_t kCoseKeyAlg = 3;
inline constexpr std::int64_t kCoseKeyCrv = -1;
inline constexpr std::int64_t kCoseKeyX = -2;

inline constexpr std::int64_t kKtyOkp = 1;
inline constexpr std::int64_t kAlgEd25519 = -19;
inline constexpr std::int64_t kCrvEd25519 = 6;

// Exact canonical definite-length COSE_Sign1 prefix:
// 0xd2 (Tag 18) || 0x84 (4-elem array) || 0x43 a1 01 32 ({1: -19}) || 0xa0 ({})
inline constexpr std::array<std::uint8_t, 7> kCanonicalSign1Prefix = {
    0xd2U, 0x84U, 0x43U, 0xa1U, 0x01U, 0x32U, 0xa0U};

enum class CborMajor : std::uint8_t {
  uint = 0U,
  negint = 1U,
  bstr = 2U,
  tstr = 3U,
  array = 4U,
  map = 5U,
  tag = 6U,
};

void cbor_append_head(std::vector<std::uint8_t> &out, CborMajor major,
                      std::uint64_t arg) {
  const auto prefix = static_cast<std::uint8_t>(static_cast<std::uint8_t>(major) << 5U);
  if (arg < 24U) {
    out.push_back(static_cast<std::uint8_t>(prefix | static_cast<std::uint8_t>(arg)));
  } else if (arg <= 0xffU) {
    out.push_back(static_cast<std::uint8_t>(prefix | 24U));
    out.push_back(static_cast<std::uint8_t>(arg));
  } else if (arg <= 0xffffU) {
    out.push_back(static_cast<std::uint8_t>(prefix | 25U));
    out.push_back(static_cast<std::uint8_t>((arg >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(arg & 0xffU));
  } else if (arg <= 0xffffffffULL) {
    out.push_back(static_cast<std::uint8_t>(prefix | 26U));
    for (std::size_t shift = 24U; shift <= 24U; shift -= 8U) {
      out.push_back(static_cast<std::uint8_t>((arg >> shift) & 0xffU));
      if (shift == 0U) {
        break;
      }
    }
  } else {
    out.push_back(static_cast<std::uint8_t>(prefix | 27U));
    for (std::size_t shift = 56U; shift <= 56U; shift -= 8U) {
      out.push_back(static_cast<std::uint8_t>((arg >> shift) & 0xffU));
      if (shift == 0U) {
        break;
      }
    }
  }
}

void cbor_append_int(std::vector<std::uint8_t> &out, std::int64_t value) {
  if (value >= 0) {
    cbor_append_head(out, CborMajor::uint, static_cast<std::uint64_t>(value));
  } else {
    // CBOR negative int encodes -1 - n as major type 1 with argument n.
    // Avoid signed overflow on INT64_MIN via unsigned arithmetic.
    const std::uint64_t n =
        static_cast<std::uint64_t>(-(value + 1)); // safe for all value < 0
    cbor_append_head(out, CborMajor::negint, n);
  }
}

void cbor_append_bstr(std::vector<std::uint8_t> &out,
                      std::span<const std::uint8_t> bytes) {
  cbor_append_head(out, CborMajor::bstr, static_cast<std::uint64_t>(bytes.size()));
  append_bytes(out, bytes);
}

void cbor_append_tstr(std::vector<std::uint8_t> &out, std::string_view text) {
  cbor_append_head(out, CborMajor::tstr, static_cast<std::uint64_t>(text.size()));
  append_string_bytes(out, text);
}

struct CborHead {
  std::uint8_t major = 0U;
  std::uint64_t arg = 0U;
};

class StrictCborReader {
public:
  explicit StrictCborReader(std::span<const std::uint8_t> bytes) noexcept
      : bytes_(bytes) {}

  Result<CborHead> read_head(MpError error_detail) {
    if (pos_ >= bytes_.size()) {
      return fail<CborHead>(ErrorCode::corrupt, error_detail);
    }
    const std::uint8_t initial = bytes_[pos_++];
    const auto major = static_cast<std::uint8_t>(initial >> 5U);
    const auto ai = static_cast<std::uint8_t>(initial & 0x1fU);
    if (ai < 24U) {
      return Result<CborHead>::success(CborHead{major, ai});
    }
    if (ai == 24U) {
      if (bytes_.size() - pos_ < 1U) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      const std::uint64_t val = bytes_[pos_++];
      if (val < 24U) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      return Result<CborHead>::success(CborHead{major, val});
    }
    if (ai == 25U) {
      if (bytes_.size() - pos_ < 2U) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      const std::uint64_t val = (static_cast<std::uint64_t>(bytes_[pos_]) << 8U) |
                                static_cast<std::uint64_t>(bytes_[pos_ + 1U]);
      pos_ += 2U;
      if (val <= 0xffU) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      return Result<CborHead>::success(CborHead{major, val});
    }
    if (ai == 26U) {
      if (bytes_.size() - pos_ < 4U) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      std::uint64_t val = 0U;
      for (std::size_t i = 0U; i < 4U; ++i) {
        val = (val << 8U) | static_cast<std::uint64_t>(bytes_[pos_ + i]);
      }
      pos_ += 4U;
      if (val <= 0xffffU) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      return Result<CborHead>::success(CborHead{major, val});
    }
    if (ai == 27U) {
      if (bytes_.size() - pos_ < 8U) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      std::uint64_t val = 0U;
      for (std::size_t i = 0U; i < 8U; ++i) {
        val = (val << 8U) | static_cast<std::uint64_t>(bytes_[pos_ + i]);
      }
      pos_ += 8U;
      if (val <= 0xffffffffULL) {
        return fail<CborHead>(ErrorCode::corrupt, error_detail);
      }
      return Result<CborHead>::success(CborHead{major, val});
    }
    // Reject ai == 28..30 (reserved) and ai == 31 (indefinite length).
    return fail<CborHead>(ErrorCode::corrupt, error_detail);
  }

  Result<std::int64_t> read_i64(MpError error_detail) {
    const auto head = read_head(error_detail);
    if (!head.has_value()) {
      return Result<std::int64_t>::failure(head.error());
    }
    const std::uint64_t max_i64 =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    if (head.value().major == 0U) {
      if (head.value().arg > max_i64) {
        return fail<std::int64_t>(ErrorCode::corrupt, error_detail);
      }
      return Result<std::int64_t>::success(static_cast<std::int64_t>(head.value().arg));
    }
    if (head.value().major == 1U) {
      if (head.value().arg > max_i64) {
        return fail<std::int64_t>(ErrorCode::corrupt, error_detail);
      }
      const auto val = -1 - static_cast<std::int64_t>(head.value().arg);
      return Result<std::int64_t>::success(val);
    }
    return fail<std::int64_t>(ErrorCode::corrupt, error_detail);
  }

  Result<std::span<const std::uint8_t>> read_bstr(MpError error_detail) {
    const auto head = read_head(error_detail);
    if (!head.has_value()) {
      return Result<std::span<const std::uint8_t>>::failure(head.error());
    }
    if (head.value().major != 2U) {
      return fail<std::span<const std::uint8_t>>(ErrorCode::corrupt, error_detail);
    }
    if (head.value().arg > bytes_.size() - pos_) {
      return fail<std::span<const std::uint8_t>>(ErrorCode::corrupt, error_detail);
    }
    const auto len = static_cast<std::size_t>(head.value().arg);
    const auto slice = bytes_.subspan(pos_, len);
    pos_ += len;
    return Result<std::span<const std::uint8_t>>::success(slice);
  }

  Result<std::string> read_tstr(MpError error_detail) {
    const auto head = read_head(error_detail);
    if (!head.has_value()) {
      return Result<std::string>::failure(head.error());
    }
    if (head.value().major != 3U) {
      return fail<std::string>(ErrorCode::corrupt, error_detail);
    }
    if (head.value().arg > bytes_.size() - pos_) {
      return fail<std::string>(ErrorCode::corrupt, error_detail);
    }
    const auto len = static_cast<std::size_t>(head.value().arg);
    const auto slice = bytes_.subspan(pos_, len);
    if (!is_valid_utf8(slice)) {
      return fail<std::string>(ErrorCode::corrupt, error_detail);
    }
    pos_ += len;
    std::string out;
    out.reserve(len);
    for (const std::uint8_t b : slice) {
      out.push_back(static_cast<char>(b));
    }
    return Result<std::string>::success(std::move(out));
  }

  bool at_end() const noexcept { return pos_ == bytes_.size(); }

private:
  std::span<const std::uint8_t> bytes_;
  std::size_t pos_ = 0U;
};

struct CoseSigInput {
  std::span<const std::uint8_t> protected_bytes;
  std::span<const std::uint8_t> payload_bytes;
};

// RFC 9052 section 4.4 Sig_structure = ["Signature1", body_protected, external_aad,
// payload]
std::vector<std::uint8_t> build_cose_sig_structure(const CoseSigInput &input) {
  std::vector<std::uint8_t> out;
  out.reserve(input.protected_bytes.size() + input.payload_bytes.size() + 32U);
  cbor_append_head(out, CborMajor::array, 4U); // 4-element definite array
  cbor_append_tstr(out, "Signature1");
  cbor_append_bstr(out, input.protected_bytes);
  cbor_append_bstr(out, {}); // empty external_aad
  cbor_append_bstr(out, input.payload_bytes);
  return out;
}

struct CwtTimeBounds {
  std::int64_t issued_at_s = 0;
  std::int64_t expires_at_s = 0;
};

Result<void> validate_cwt_ttl(const CwtTimeBounds &bounds) {
  if (bounds.issued_at_s < 0) {
    return fail_void(ErrorCode::invalid_range, MpError::cwt_invalid_claims);
  }
  const auto ttl = checked_sub_i64(bounds.expires_at_s, bounds.issued_at_s);
  if (!ttl.has_value() || *ttl <= 0 || *ttl > kMaxCwtTtlSecs) {
    return fail_void(ErrorCode::invalid_range, MpError::cwt_ttl_exceeded);
  }
  return Result<void>::success();
}

Result<Ed25519PubKey> parse_cnf_ed25519(StrictCborReader &reader) {
  const auto cnf_head = reader.read_head(MpError::cwt_invalid_claims);
  if (!cnf_head.has_value()) {
    return Result<Ed25519PubKey>::failure(cnf_head.error());
  }
  if (cnf_head.value().major != 5U || cnf_head.value().arg != 1U) {
    return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  const auto cnf_key = reader.read_i64(MpError::cwt_invalid_claims);
  if (!cnf_key.has_value() || cnf_key.value() != kCnfCoseKey) {
    return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  const auto key_map_head = reader.read_head(MpError::cwt_invalid_claims);
  if (!key_map_head.has_value()) {
    return Result<Ed25519PubKey>::failure(key_map_head.error());
  }
  if (key_map_head.value().major != 5U || key_map_head.value().arg > 16U) {
    return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }

  std::optional<std::int64_t> kty;
  std::optional<std::int64_t> alg;
  std::optional<std::int64_t> crv;
  std::optional<Ed25519PubKey> x;

  for (std::uint64_t i = 0U; i < key_map_head.value().arg; ++i) {
    const auto mk = reader.read_i64(MpError::cwt_invalid_claims);
    if (!mk.has_value()) {
      return Result<Ed25519PubKey>::failure(mk.error());
    }
    switch (mk.value()) {
    case kCoseKeyKty: {
      if (kty.has_value()) {
        return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_i64(MpError::cwt_invalid_claims);
      if (!mv.has_value()) {
        return Result<Ed25519PubKey>::failure(mv.error());
      }
      kty = mv.value();
      break;
    }
    case kCoseKeyAlg: {
      if (alg.has_value()) {
        return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_i64(MpError::cwt_invalid_claims);
      if (!mv.has_value()) {
        return Result<Ed25519PubKey>::failure(mv.error());
      }
      alg = mv.value();
      break;
    }
    case kCoseKeyCrv: {
      if (crv.has_value()) {
        return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_i64(MpError::cwt_invalid_claims);
      if (!mv.has_value()) {
        return Result<Ed25519PubKey>::failure(mv.error());
      }
      crv = mv.value();
      break;
    }
    case kCoseKeyX: {
      if (x.has_value()) {
        return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto mv = reader.read_bstr(MpError::cwt_invalid_claims);
      if (!mv.has_value() || mv.value().size() != 32U) {
        return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      Ed25519PubKey pub{};
      std::memcpy(pub.data(), mv.value().data(), pub.size());
      x = pub;
      break;
    }
    default:
      return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
    }
  }

  if (!kty.has_value() || *kty != kKtyOkp || !crv.has_value() || *crv != kCrvEd25519 ||
      !alg.has_value() || *alg != kAlgEd25519 || !x.has_value()) {
    return fail<Ed25519PubKey>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  return Result<Ed25519PubKey>::success(*x);
}

inline constexpr std::array<std::string_view, 27> kReservedHandles = {
    "admin",    "administrator", "antimeme", "api",       "auth",        "blackbird",
    "help",     "lobby",         "mod",      "moderator", "multiplayer", "neon",
    "official", "operator",      "party",    "privacy",   "relay",       "root",
    "security", "staff",         "status",   "support",   "sys",         "system",
    "team",     "waitlist",      "www",
};

} // namespace

// ---------------------------------------------------------------------------
// Error names
// ---------------------------------------------------------------------------

const char *mp_error_name(MpError detail) noexcept {
  switch (detail) {
  case MpError::none:
    return "none";
  case MpError::id_zero:
    return "id_zero";
  case MpError::id_exceeds_safe_int:
    return "id_exceeds_safe_int";
  case MpError::id_invalid_decimal:
    return "id_invalid_decimal";
  case MpError::invalid_public_key:
    return "invalid_public_key";
  case MpError::weak_public_key:
    return "weak_public_key";
  case MpError::invalid_signature:
    return "invalid_signature";
  case MpError::invalid_handle:
    return "invalid_handle";
  case MpError::reserved_handle:
    return "reserved_handle";
  case MpError::crypto_internal:
    return "crypto_internal";
  case MpError::endpoint_too_large:
    return "endpoint_too_large";
  case MpError::endpoint_truncated:
    return "endpoint_truncated";
  case MpError::endpoint_trailing_bytes:
    return "endpoint_trailing_bytes";
  case MpError::invalid_transport_kind:
    return "invalid_transport_kind";
  case MpError::invalid_relay_policy:
    return "invalid_relay_policy";
  case MpError::invalid_relay_url:
    return "invalid_relay_url";
  case MpError::too_many_direct_addrs:
    return "too_many_direct_addrs";
  case MpError::invalid_addr_family:
    return "invalid_addr_family";
  case MpError::invalid_port:
    return "invalid_port";
  case MpError::disallowed_direct_addr:
    return "disallowed_direct_addr";
  case MpError::force_relays_violation:
    return "force_relays_violation";
  case MpError::no_relays_violation:
    return "no_relays_violation";
  case MpError::cwt_too_large:
    return "cwt_too_large";
  case MpError::cwt_invalid_cbor:
    return "cwt_invalid_cbor";
  case MpError::cwt_invalid_envelope_shape:
    return "cwt_invalid_envelope_shape";
  case MpError::cwt_invalid_protected_header:
    return "cwt_invalid_protected_header";
  case MpError::cwt_non_empty_unprotected_header:
    return "cwt_non_empty_unprotected_header";
  case MpError::cwt_invalid_signature_length:
    return "cwt_invalid_signature_length";
  case MpError::cwt_invalid_claims:
    return "cwt_invalid_claims";
  case MpError::cwt_issuer_mismatch:
    return "cwt_issuer_mismatch";
  case MpError::cwt_device_key_mismatch:
    return "cwt_device_key_mismatch";
  case MpError::cwt_future_issued_at:
    return "cwt_future_issued_at";
  case MpError::cwt_expired:
    return "cwt_expired";
  case MpError::cwt_ttl_exceeded:
    return "cwt_ttl_exceeded";
  case MpError::rfc9421_unsupported_method:
    return "rfc9421_unsupported_method";
  case MpError::rfc9421_invalid_authority:
    return "rfc9421_invalid_authority";
  case MpError::rfc9421_invalid_path:
    return "rfc9421_invalid_path";
  case MpError::rfc9421_query_not_allowed:
    return "rfc9421_query_not_allowed";
  case MpError::rfc9421_unexpected_body_on_get:
    return "rfc9421_unexpected_body_on_get";
  case MpError::rfc9421_content_encoding_forbidden:
    return "rfc9421_content_encoding_forbidden";
  case MpError::rfc9421_missing_content_type:
    return "rfc9421_missing_content_type";
  case MpError::rfc9421_invalid_content_digest:
    return "rfc9421_invalid_content_digest";
  case MpError::rfc9421_content_digest_mismatch:
    return "rfc9421_content_digest_mismatch";
  case MpError::rfc9421_invalid_signature_input:
    return "rfc9421_invalid_signature_input";
  case MpError::rfc9421_invalid_covered_components:
    return "rfc9421_invalid_covered_components";
  case MpError::rfc9421_invalid_algorithm:
    return "rfc9421_invalid_algorithm";
  case MpError::rfc9421_invalid_tag:
    return "rfc9421_invalid_tag";
  case MpError::rfc9421_invalid_key_id:
    return "rfc9421_invalid_key_id";
  case MpError::rfc9421_invalid_nonce:
    return "rfc9421_invalid_nonce";
  case MpError::rfc9421_invalid_window:
    return "rfc9421_invalid_window";
  case MpError::rfc9421_clock_skew:
    return "rfc9421_clock_skew";
  case MpError::rfc9421_expired:
    return "rfc9421_expired";
  case MpError::rfc9421_invalid_signature_header:
    return "rfc9421_invalid_signature_header";
  case MpError::mp1_frame_too_large:
    return "mp1_frame_too_large";
  case MpError::mp1_truncated:
    return "mp1_truncated";
  case MpError::mp1_trailing_bytes:
    return "mp1_trailing_bytes";
  case MpError::mp1_unsupported_version:
    return "mp1_unsupported_version";
  case MpError::mp1_non_zero_flags:
    return "mp1_non_zero_flags";
  case MpError::mp1_non_zero_reserved:
    return "mp1_non_zero_reserved";
  case MpError::mp1_unknown_opcode:
    return "mp1_unknown_opcode";
  case MpError::mp1_length_mismatch:
    return "mp1_length_mismatch";
  case MpError::mp1_invalid_enum_value:
    return "mp1_invalid_enum_value";
  case MpError::mp1_invalid_bool:
    return "mp1_invalid_bool";
  case MpError::mp1_invalid_count:
    return "mp1_invalid_count";
  case MpError::mp1_safe_int_exceeded:
    return "mp1_safe_int_exceeded";
  case MpError::mp1_invalid_cwt_length:
    return "mp1_invalid_cwt_length";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// 1. Safe integer ID helpers
// ---------------------------------------------------------------------------

Result<std::uint64_t> parse_safe_decimal_id(std::string_view text) {
  if (text.empty() || text.size() > 16U || text.front() == '0') {
    return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_invalid_decimal);
  }
  std::uint64_t value = 0U;
  for (const char ch : text) {
    if (!is_ascii_digit(ch)) {
      return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_invalid_decimal);
    }
    const auto digit = static_cast<std::uint64_t>(ch - '0');
    if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10U) {
      return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_invalid_decimal);
    }
    value = (value * 10U) + digit;
  }
  if (value == 0U) {
    return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_zero);
  }
  if (value > kMaxSafeId) {
    return fail<std::uint64_t>(ErrorCode::invalid_range, MpError::id_exceeds_safe_int);
  }
  return Result<std::uint64_t>::success(value);
}

Result<std::uint64_t> generate_random_global_id() {
  for (int attempt = 0; attempt < 32; ++attempt) {
    std::array<std::uint8_t, 8> raw{};
    if (const auto ok = random_bytes(raw); !ok.has_value()) {
      return Result<std::uint64_t>::failure(ok.error());
    }
    std::uint64_t value = 0U;
    for (std::size_t i = 0U; i < 8U; ++i) {
      value |= static_cast<std::uint64_t>(raw[i]) << (i * 8U);
    }
    value &= kMaxRandomGlobalId;
    if (value != 0U) {
      return Result<std::uint64_t>::success(value);
    }
  }
  return fail<std::uint64_t>(ErrorCode::external_unknown, MpError::crypto_internal);
}

// ---------------------------------------------------------------------------
// 2. OpenSSL 3 cryptography primitives & handles
// ---------------------------------------------------------------------------

Result<Sha256Digest> sha256(std::span<const std::uint8_t> data) {
  Sha256Digest digest{};
  unsigned int digest_len = 0U;
  if (EVP_Digest(non_null_bytes(data), data.size(), digest.data(), &digest_len,
                 EVP_sha256(), nullptr) != 1 ||
      digest_len != digest.size()) {
    return fail<Sha256Digest>(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  return Result<Sha256Digest>::success(digest);
}

std::string hex_lower(std::span<const std::uint8_t> bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2U);
  for (const std::uint8_t byte : bytes) {
    out.push_back(kHex[(byte >> 4U) & 0x0fU]);
    out.push_back(kHex[byte & 0x0fU]);
  }
  return out;
}

Result<void> random_bytes(std::span<std::uint8_t> out) {
  if (out.empty()) {
    return Result<void>::success();
  }
  if (out.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return fail_void(ErrorCode::invalid_range, MpError::crypto_internal);
  }
  if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  return Result<void>::success();
}

Result<std::string> generate_nonce_b64url(std::size_t raw_bytes) {
  if (raw_bytes < 17U || raw_bytes > 48U) {
    return fail<std::string>(ErrorCode::invalid_range, MpError::rfc9421_invalid_nonce);
  }
  std::vector<std::uint8_t> buf(raw_bytes);
  if (const auto ok = random_bytes(buf); !ok.has_value()) {
    return Result<std::string>::failure(ok.error());
  }
  std::string encoded = base64_url_encode_nopad(buf);
  OPENSSL_cleanse(buf.data(), buf.size());
  if (const auto valid = validate_nonce(encoded); !valid.has_value()) {
    return Result<std::string>::failure(valid.error());
  }
  return Result<std::string>::success(std::move(encoded));
}

bool constant_time_equal(const ConstantTimeCompare &cmp) noexcept {
  if (cmp.lhs.size() != cmp.rhs.size()) {
    return false;
  }
  if (cmp.lhs.empty()) {
    return true;
  }
  return CRYPTO_memcmp(cmp.lhs.data(), cmp.rhs.data(), cmp.lhs.size()) == 0;
}

// Field prime p = 2^255 - 19 (little-endian).
inline constexpr std::array<std::uint8_t, 32> kEd25519PrimeP = {
    0xedU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
    0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0x7fU,
};

struct EdwardsPoint {
  BIGNUM *x = nullptr;
  BIGNUM *y = nullptr;
  BIGNUM *z = nullptr;
  BIGNUM *t = nullptr;
};

struct EdwardsMathCtx {
  const BIGNUM *p = nullptr;
  const BIGNUM *two_d = nullptr;
  BN_CTX *bn_ctx = nullptr;
};

struct EdwardsAddInput {
  const EdwardsPoint *lhs = nullptr;
  const EdwardsPoint *rhs = nullptr;
};

// Complete unified extended twisted Edwards addition (Hisil et al. add-2008-hwcd-3,
// a = -1): valid for all points including doubling (P == Q), identity, and inverses.
bool edwards_add(EdwardsPoint &out, const EdwardsAddInput &in,
                 const EdwardsMathCtx &m) {
  BnCtxScope scope{m.bn_ctx};
  BIGNUM *a = BN_CTX_get(m.bn_ctx);
  BIGNUM *b = BN_CTX_get(m.bn_ctx);
  BIGNUM *c = BN_CTX_get(m.bn_ctx);
  BIGNUM *d = BN_CTX_get(m.bn_ctx);
  BIGNUM *e = BN_CTX_get(m.bn_ctx);
  BIGNUM *f = BN_CTX_get(m.bn_ctx);
  BIGNUM *g = BN_CTX_get(m.bn_ctx);
  BIGNUM *h = BN_CTX_get(m.bn_ctx);
  BIGNUM *t1 = BN_CTX_get(m.bn_ctx);
  BIGNUM *t2 = BN_CTX_get(m.bn_ctx);
  if (t2 == nullptr) {
    return false;
  }

  // A = (Y1 - X1) * (Y2 - X2) mod p
  if (BN_mod_sub(t1, in.lhs->y, in.lhs->x, m.p, m.bn_ctx) != 1 ||
      BN_mod_sub(t2, in.rhs->y, in.rhs->x, m.p, m.bn_ctx) != 1 ||
      BN_mod_mul(a, t1, t2, m.p, m.bn_ctx) != 1) {
    return false;
  }
  // B = (Y1 + X1) * (Y2 + X2) mod p
  if (BN_mod_add(t1, in.lhs->y, in.lhs->x, m.p, m.bn_ctx) != 1 ||
      BN_mod_add(t2, in.rhs->y, in.rhs->x, m.p, m.bn_ctx) != 1 ||
      BN_mod_mul(b, t1, t2, m.p, m.bn_ctx) != 1) {
    return false;
  }
  // C = T1 * (2*d) * T2 mod p
  if (BN_mod_mul(t1, in.lhs->t, m.two_d, m.p, m.bn_ctx) != 1 ||
      BN_mod_mul(c, t1, in.rhs->t, m.p, m.bn_ctx) != 1) {
    return false;
  }
  // D = 2 * Z1 * Z2 mod p
  if (BN_mod_mul(t1, in.lhs->z, in.rhs->z, m.p, m.bn_ctx) != 1 ||
      BN_mod_add(d, t1, t1, m.p, m.bn_ctx) != 1) {
    return false;
  }
  // E = B - A, F = D - C, G = D + C, H = B + A (all mod p)
  if (BN_mod_sub(e, b, a, m.p, m.bn_ctx) != 1 ||
      BN_mod_sub(f, d, c, m.p, m.bn_ctx) != 1 ||
      BN_mod_add(g, d, c, m.p, m.bn_ctx) != 1 ||
      BN_mod_add(h, b, a, m.p, m.bn_ctx) != 1) {
    return false;
  }
  // X3 = E * F, Y3 = G * H, T3 = E * H, Z3 = F * G (all mod p)
  return BN_mod_mul(out.x, e, f, m.p, m.bn_ctx) == 1 &&
         BN_mod_mul(out.y, g, h, m.p, m.bn_ctx) == 1 &&
         BN_mod_mul(out.t, e, h, m.p, m.bn_ctx) == 1 &&
         BN_mod_mul(out.z, f, g, m.p, m.bn_ctx) == 1;
}

bool is_application_json_content_type(std::string_view ct) noexcept {
  const std::size_t semi = ct.find(';');
  const std::string_view base =
      trim_http_ows(semi == std::string_view::npos ? ct : ct.substr(0U, semi));
  static constexpr std::string_view kExpected = "application/json";
  if (base.size() != kExpected.size()) {
    return false;
  }
  for (std::size_t i = 0U; i < kExpected.size(); ++i) {
    if (to_ascii_lower(base[i]) != kExpected[i]) {
      return false;
    }
  }
  return true;
}

Result<void> validate_ed25519_pubkey_strict(const Ed25519PubKey &pubkey) {
  std::array<std::uint8_t, 32> y_cleared = pubkey;
  y_cleared[31] = static_cast<std::uint8_t>(y_cleared[31] & 0x7fU);
  if (is_non_canonical_field_elem(y_cleared)) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
  }

  // RFC 8032 section 5.1.3 decompression + prime-order torsion-freeness ([L]A == O)
  // over OpenSSL 3 BIGNUM. Rejects off-curve bytes, non-canonical -0, all 8
  // small-order points, and all mixed-order P + T points.
  UniqueBnCtx bn_ctx{BN_CTX_new()};
  if (!bn_ctx) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  BnCtxScope scope{bn_ctx.get()};

  BIGNUM *p = BN_CTX_get(bn_ctx.get());
  BIGNUM *l_order = BN_CTX_get(bn_ctx.get());
  BIGNUM *y = BN_CTX_get(bn_ctx.get());
  BIGNUM *x = BN_CTX_get(bn_ctx.get());
  BIGNUM *d = BN_CTX_get(bn_ctx.get());
  BIGNUM *two_d = BN_CTX_get(bn_ctx.get());
  BIGNUM *y2 = BN_CTX_get(bn_ctx.get());
  BIGNUM *u = BN_CTX_get(bn_ctx.get());
  BIGNUM *v = BN_CTX_get(bn_ctx.get());
  BIGNUM *v2 = BN_CTX_get(bn_ctx.get());
  BIGNUM *v3 = BN_CTX_get(bn_ctx.get());
  BIGNUM *v4 = BN_CTX_get(bn_ctx.get());
  BIGNUM *v7 = BN_CTX_get(bn_ctx.get());
  BIGNUM *uv3 = BN_CTX_get(bn_ctx.get());
  BIGNUM *uv7 = BN_CTX_get(bn_ctx.get());
  BIGNUM *vx2 = BN_CTX_get(bn_ctx.get());
  BIGNUM *tmp = BN_CTX_get(bn_ctx.get());
  BIGNUM *exp_bn = BN_CTX_get(bn_ctx.get());
  BIGNUM *one = BN_CTX_get(bn_ctx.get());
  BIGNUM *zero = BN_CTX_get(bn_ctx.get());
  if (zero == nullptr) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }

  BN_zero(zero);
  if (BN_one(one) != 1 || BN_lebin2bn(kEd25519PrimeP.data(), 32, p) == nullptr ||
      BN_lebin2bn(kEd25519GroupOrderL.data(), 32, l_order) == nullptr ||
      BN_lebin2bn(y_cleared.data(), 32, y) == nullptr) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }

  // d = (-121665) * 121666^(-1) mod p
  if (BN_set_word(tmp, 121666U) != 1 ||
      BN_mod_inverse(d, tmp, p, bn_ctx.get()) == nullptr ||
      BN_set_word(tmp, 121665U) != 1 || BN_mod_sub(tmp, p, tmp, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(d, d, tmp, p, bn_ctx.get()) != 1 ||
      BN_mod_add(two_d, d, d, p, bn_ctx.get()) != 1) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }

  // u = (y^2 - 1) mod p, v = (d * y^2 + 1) mod p
  if (BN_mod_mul(y2, y, y, p, bn_ctx.get()) != 1 ||
      BN_mod_sub(u, y2, one, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(tmp, d, y2, p, bn_ctx.get()) != 1 ||
      BN_mod_add(v, tmp, one, p, bn_ctx.get()) != 1) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  if (BN_is_zero(v)) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
  }

  // Candidate x = u * v^3 * (u * v^7)^((p - 5) / 8) mod p
  if (BN_mod_mul(v2, v, v, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(v3, v2, v, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(v4, v2, v2, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(v7, v4, v3, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(uv3, u, v3, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(uv7, u, v7, p, bn_ctx.get()) != 1 || BN_copy(tmp, p) == nullptr ||
      BN_sub_word(tmp, 5U) != 1 || BN_rshift(exp_bn, tmp, 3) != 1 ||
      BN_mod_exp(tmp, uv7, exp_bn, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(x, uv3, tmp, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(tmp, x, x, p, bn_ctx.get()) != 1 ||
      BN_mod_mul(vx2, v, tmp, p, bn_ctx.get()) != 1) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }

  if (BN_cmp(vx2, u) != 0) {
    // Check v * x^2 == -u mod p -> multiply by sqrt(-1) = 2^((p - 1) / 4) mod p
    if (BN_mod_sub(tmp, zero, u, p, bn_ctx.get()) != 1) {
      return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
    }
    if (BN_cmp(vx2, tmp) != 0) {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
    }
    if (BN_copy(tmp, p) == nullptr || BN_sub_word(tmp, 1U) != 1 ||
        BN_rshift(exp_bn, tmp, 2) != 1 || BN_set_word(tmp, 2U) != 1 ||
        BN_mod_exp(tmp, tmp, exp_bn, p, bn_ctx.get()) != 1 ||
        BN_mod_mul(x, x, tmp, p, bn_ctx.get()) != 1 ||
        BN_mod_mul(tmp, x, x, p, bn_ctx.get()) != 1 ||
        BN_mod_mul(vx2, v, tmp, p, bn_ctx.get()) != 1) {
      return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
    }
    if (BN_cmp(vx2, u) != 0) {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
    }
  }

  const bool sign_bit = (pubkey[31] & 0x80U) != 0U;
  if (BN_is_zero(x)) {
    if (sign_bit) {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
    }
  } else if ((BN_is_odd(x) != 0) != sign_bit) {
    if (BN_sub(x, p, x) != 1) {
      return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
    }
  }

  if (is_small_order_point_y(y_cleared)) {
    return fail_void(ErrorCode::invalid_identity, MpError::weak_public_key);
  }

  // Prime-order subgroup / torsion-free gate: [L]A == O = (0 : Z : Z : 0).
  EdwardsPoint acc{BN_CTX_get(bn_ctx.get()), BN_CTX_get(bn_ctx.get()),
                   BN_CTX_get(bn_ctx.get()), BN_CTX_get(bn_ctx.get())};
  EdwardsPoint base{BN_CTX_get(bn_ctx.get()), BN_CTX_get(bn_ctx.get()),
                    BN_CTX_get(bn_ctx.get()), BN_CTX_get(bn_ctx.get())};
  if (base.t == nullptr) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  BN_zero(acc.x);
  BN_zero(acc.t);
  if (BN_one(acc.y) != 1 || BN_one(acc.z) != 1 || BN_copy(base.x, x) == nullptr ||
      BN_copy(base.y, y) == nullptr || BN_one(base.z) != 1 ||
      BN_mod_mul(base.t, x, y, p, bn_ctx.get()) != 1) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }

  const EdwardsMathCtx mctx{p, two_d, bn_ctx.get()};
  for (int bit = BN_num_bits(l_order) - 1; bit >= 0; --bit) {
    if (!edwards_add(acc, {&acc, &acc}, mctx)) {
      return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
    }
    if (BN_is_bit_set(l_order, bit) == 1) {
      if (!edwards_add(acc, {&acc, &base}, mctx)) {
        return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
      }
    }
  }
  if (!BN_is_zero(acc.x) || BN_is_zero(acc.z) || BN_cmp(acc.y, acc.z) != 0) {
    return fail_void(ErrorCode::invalid_identity, MpError::weak_public_key);
  }

  UniqueEvpPkey pkey{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                 pubkey.data(), pubkey.size())};
  if (!pkey) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
  }
  return Result<void>::success();
}

Result<void> verify_ed25519_strict(const Ed25519VerifyInput &input) {
  if (const auto key_ok = validate_ed25519_pubkey_strict(input.pubkey);
      !key_ok.has_value()) {
    return key_ok;
  }
  std::array<std::uint8_t, 32> r_y{};
  std::memcpy(r_y.data(), input.signature.data(), r_y.size());
  r_y[31] = static_cast<std::uint8_t>(r_y[31] & 0x7fU);
  if (is_non_canonical_field_elem(r_y) || is_small_order_point_y(r_y)) {
    return fail_void(ErrorCode::provider_auth, MpError::invalid_signature);
  }
  const std::span<const std::uint8_t, 32> scalar_s{input.signature.data() + 32, 32U};
  if (is_non_canonical_scalar(scalar_s)) {
    return fail_void(ErrorCode::provider_auth, MpError::invalid_signature);
  }

  UniqueEvpPkey pkey{EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr, input.pubkey.data(), input.pubkey.size())};
  if (!pkey) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_public_key);
  }
  UniqueEvpMdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
    return fail_void(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  const int rc =
      EVP_DigestVerify(ctx.get(), input.signature.data(), input.signature.size(),
                       non_null_bytes(input.message), input.message.size());
  if (rc != 1) {
    return fail_void(ErrorCode::provider_auth, MpError::invalid_signature);
  }
  return Result<void>::success();
}

Result<Ed25519SigningKey> Ed25519SigningKey::generate() {
  Ed25519Seed seed{};
  if (const auto ok = random_bytes(seed); !ok.has_value()) {
    return Result<Ed25519SigningKey>::failure(ok.error());
  }
  auto key = from_seed(seed);
  OPENSSL_cleanse(seed.data(), seed.size());
  return key;
}

Result<Ed25519SigningKey> Ed25519SigningKey::from_seed(const Ed25519Seed &seed) {
  UniqueEvpPkey pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                  seed.data(), seed.size())};
  if (!pkey) {
    return fail<Ed25519SigningKey>(ErrorCode::external_unknown,
                                   MpError::crypto_internal);
  }
  Ed25519PubKey pubkey{};
  std::size_t pub_len = pubkey.size();
  if (EVP_PKEY_get_raw_public_key(pkey.get(), pubkey.data(), &pub_len) != 1 ||
      pub_len != pubkey.size()) {
    return fail<Ed25519SigningKey>(ErrorCode::external_unknown,
                                   MpError::crypto_internal);
  }
  if (const auto valid = validate_ed25519_pubkey_strict(pubkey); !valid.has_value()) {
    return Result<Ed25519SigningKey>::failure(valid.error());
  }
  return Result<Ed25519SigningKey>::success(
      Ed25519SigningKey{KeyMaterial{seed, pubkey}});
}

Ed25519SigningKey::Ed25519SigningKey(Ed25519SigningKey &&other) noexcept
    : seed_(other.seed_), public_key_(other.public_key_), valid_(other.valid_) {
  other.cleanse();
}

Ed25519SigningKey &Ed25519SigningKey::operator=(Ed25519SigningKey &&other) noexcept {
  if (this != &other) {
    cleanse();
    seed_ = other.seed_;
    public_key_ = other.public_key_;
    valid_ = other.valid_;
    other.cleanse();
  }
  return *this;
}

Ed25519SigningKey::~Ed25519SigningKey() { cleanse(); }

void Ed25519SigningKey::cleanse() noexcept {
  OPENSSL_cleanse(seed_.data(), seed_.size());
  public_key_.fill(0U);
  valid_ = false;
}

Result<Ed25519Sig>
Ed25519SigningKey::sign(std::span<const std::uint8_t> message) const {
  if (!valid_) {
    return fail<Ed25519Sig>(ErrorCode::stale_handle, MpError::invalid_public_key);
  }
  UniqueEvpPkey pkey{EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
                                                  seed_.data(), seed_.size())};
  if (!pkey) {
    return fail<Ed25519Sig>(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  UniqueEvpMdCtx ctx{EVP_MD_CTX_new()};
  if (!ctx) {
    return fail<Ed25519Sig>(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) != 1) {
    return fail<Ed25519Sig>(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  Ed25519Sig sig{};
  std::size_t sig_len = sig.size();
  if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len, non_null_bytes(message),
                     message.size()) != 1 ||
      sig_len != sig.size()) {
    return fail<Ed25519Sig>(ErrorCode::external_unknown, MpError::crypto_internal);
  }
  return Result<Ed25519Sig>::success(sig);
}

Result<Sha256Digest>
hash_account_invite_secret(std::span<const std::uint8_t, 32> raw_secret) {
  std::array<std::uint8_t, 7U + 32U> buf{};
  static constexpr char kDomain[] = "mpinv1:";
  std::memcpy(buf.data(), kDomain, 7U);
  std::memcpy(buf.data() + 7U, raw_secret.data(), raw_secret.size());
  auto out = sha256(buf);
  OPENSSL_cleanse(buf.data(), buf.size());
  return out;
}

Result<Sha256Digest>
hash_party_invite_secret(PartyId party_id,
                         std::span<const std::uint8_t, 32> raw_secret) {
  std::array<std::uint8_t, 6U + 8U + 32U> buf{};
  static constexpr char kDomain[] = "mppi1:";
  const auto pid_le = party_id.to_le_bytes();
  std::memcpy(buf.data(), kDomain, 6U);
  std::memcpy(buf.data() + 6U, pid_le.data(), pid_le.size());
  std::memcpy(buf.data() + 14U, raw_secret.data(), raw_secret.size());
  auto out = sha256(buf);
  OPENSSL_cleanse(buf.data(), buf.size());
  return out;
}

Result<AccountHandle> AccountHandle::parse(std::string_view raw) {
  if (raw.size() < 3U || raw.size() > 32U) {
    return fail<AccountHandle>(ErrorCode::invalid_identity, MpError::invalid_handle);
  }
  if (!is_ascii_alnum(raw.front()) || !is_ascii_alnum(raw.back())) {
    return fail<AccountHandle>(ErrorCode::invalid_identity, MpError::invalid_handle);
  }
  bool prev_sep = false;
  std::string normalized;
  normalized.reserve(raw.size());
  for (const char ch : raw) {
    const bool is_sep = (ch == '-' || ch == '_');
    if (!is_ascii_alnum(ch) && !is_sep) {
      return fail<AccountHandle>(ErrorCode::invalid_identity, MpError::invalid_handle);
    }
    if (is_sep && prev_sep) {
      return fail<AccountHandle>(ErrorCode::invalid_identity, MpError::invalid_handle);
    }
    prev_sep = is_sep;
    normalized.push_back(to_ascii_lower(ch));
  }
  for (const std::string_view reserved : kReservedHandles) {
    if (normalized == reserved) {
      return fail<AccountHandle>(ErrorCode::invalid_identity, MpError::reserved_handle);
    }
  }
  return Result<AccountHandle>::success(
      AccountHandle{std::string{raw}, std::move(normalized)});
}

// ---------------------------------------------------------------------------
// 3. EndpointDescriptor validation & binary codec
// ---------------------------------------------------------------------------

Result<void> validate_relay_url(std::string_view url) {
  if (url.empty()) {
    return Result<void>::success();
  }
  if (url.size() > kMaxRelayUrlBytes) {
    return fail_void(ErrorCode::invalid_range, MpError::invalid_relay_url);
  }
  static constexpr std::string_view kHttpsPrefix = "https://";
  if (!url.starts_with(kHttpsPrefix)) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
  }
  const std::string_view rest = url.substr(kHttpsPrefix.size());
  if (rest.empty() || rest.find_first_of("/?#@\\") != std::string_view::npos) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
  }

  std::string_view host = rest;
  std::optional<std::string_view> port_opt;
  if (const std::size_t colon = rest.rfind(':'); colon != std::string_view::npos) {
    host = rest.substr(0U, colon);
    port_opt = rest.substr(colon + 1U);
  }

  if (host.empty() || host.front() == '.' || host.back() == '.' ||
      host.find("..") != std::string_view::npos) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
  }
  bool all_digits_or_dot = true;
  for (const char ch : host) {
    const bool ok = is_ascii_lower(ch) || is_ascii_digit(ch) || ch == '.' || ch == '-';
    if (!ok) {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
    }
    if (!is_ascii_digit(ch) && ch != '.') {
      all_digits_or_dot = false;
    }
  }
  if (all_digits_or_dot) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
  }

  std::size_t label_count = 0U;
  std::string_view last_label;
  std::size_t start = 0U;
  while (start <= host.size()) {
    const std::size_t dot = host.find('.', start);
    const std::string_view label = (dot == std::string_view::npos)
                                       ? host.substr(start)
                                       : host.substr(start, dot - start);
    if (label.empty() || label.size() > 63U || label.front() == '-' ||
        label.back() == '-' || label.starts_with("0x")) {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
    }
    ++label_count;
    last_label = label;
    if (dot == std::string_view::npos) {
      break;
    }
    start = dot + 1U;
  }
  if (label_count < 2U) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
  }
  const bool tld_has_alpha =
      std::any_of(last_label.begin(), last_label.end(),
                  [](char ch) noexcept { return is_ascii_lower(ch); });
  if (!tld_has_alpha) {
    return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
  }

  if (port_opt.has_value()) {
    const std::string_view p = *port_opt;
    if (p.empty() || p.size() > 5U || p.front() == '0') {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
    }
    std::uint32_t port = 0U;
    for (const char ch : p) {
      if (!is_ascii_digit(ch)) {
        return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
      }
      port = (port * 10U) + static_cast<std::uint32_t>(ch - '0');
    }
    if (port == 0U || port > 65535U || port == 443U) {
      return fail_void(ErrorCode::invalid_identity, MpError::invalid_relay_url);
    }
  }
  return Result<void>::success();
}

Result<void> validate_pinned_relay_url(RelayPolicy policy,
                                       std::string_view pinned_relay_url) {
  if (const auto ok = validate_relay_url(pinned_relay_url); !ok.has_value()) {
    return ok;
  }
  switch (policy) {
  case RelayPolicy::force_relays:
    if (pinned_relay_url.empty()) {
      return fail_void(ErrorCode::invalid_range, MpError::force_relays_violation);
    }
    break;
  case RelayPolicy::no_relays:
    if (!pinned_relay_url.empty()) {
      return fail_void(ErrorCode::invalid_range, MpError::no_relays_violation);
    }
    break;
  case RelayPolicy::allow_relays:
    break;
  }
  return Result<void>::success();
}

Result<void> EndpointDescriptor::validate() const {
  if (const auto ok = validate_relay_url(relay_url); !ok.has_value()) {
    return ok;
  }
  if (direct_addrs.size() > kMaxDirectAddrs) {
    return fail_void(ErrorCode::invalid_range, MpError::too_many_direct_addrs);
  }
  std::size_t total = 1U + 2U + relay_url.size() + 1U;
  for (const auto &addr : direct_addrs) {
    if (direct_addr_port(addr) == 0U) {
      return fail_void(ErrorCode::invalid_range, MpError::invalid_port);
    }
    if (is_always_disallowed_addr(addr)) {
      return fail_void(ErrorCode::invalid_range, MpError::disallowed_direct_addr);
    }
    total += direct_addr_encoded_len(addr);
  }
  if (total > kMaxEndpointDescriptorBytes) {
    return fail_void(ErrorCode::capacity, MpError::endpoint_too_large);
  }
  return Result<void>::success();
}

Result<void>
EndpointDescriptor::validate_against_policy(RelayPolicy policy,
                                            std::string_view pinned_relay_url) const {
  if (const auto ok = validate(); !ok.has_value()) {
    return ok;
  }
  if (const auto ok = validate_pinned_relay_url(policy, pinned_relay_url);
      !ok.has_value()) {
    return ok;
  }
  switch (policy) {
  case RelayPolicy::force_relays:
    if (transport_kind != TransportKind::iroh_quic || !direct_addrs.empty() ||
        relay_url != pinned_relay_url) {
      return fail_void(ErrorCode::invalid_range, MpError::force_relays_violation);
    }
    break;
  case RelayPolicy::no_relays:
    if (!relay_url.empty()) {
      return fail_void(ErrorCode::invalid_range, MpError::no_relays_violation);
    }
    break;
  case RelayPolicy::allow_relays:
    for (const auto &addr : direct_addrs) {
      if (is_private_or_lan_addr(addr)) {
        return fail_void(ErrorCode::invalid_range, MpError::disallowed_direct_addr);
      }
    }
    break;
  }
  return Result<void>::success();
}

Result<std::vector<std::uint8_t>> EndpointDescriptor::encode() const {
  if (const auto ok = validate(); !ok.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(ok.error());
  }
  std::vector<std::uint8_t> out;
  out.reserve(kMaxEndpointDescriptorBytes);
  out.push_back(static_cast<std::uint8_t>(transport_kind));
  append_u16_le(out, static_cast<std::uint16_t>(relay_url.size()));
  append_string_bytes(out, relay_url);
  out.push_back(static_cast<std::uint8_t>(direct_addrs.size()));
  for (const auto &addr : direct_addrs) {
    if (const auto *v4 = std::get_if<DirectAddrV4>(&addr)) {
      out.push_back(4U);
      append_bytes(out, v4->ip);
      append_u16_le(out, v4->port);
    } else {
      const auto &v6 = std::get<DirectAddrV6>(addr);
      out.push_back(6U);
      append_bytes(out, v6.ip);
      append_u16_le(out, v6.port);
    }
  }
  if (out.size() > kMaxEndpointDescriptorBytes) {
    return fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                           MpError::endpoint_too_large);
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

Result<EndpointDescriptor>
EndpointDescriptor::decode(std::span<const std::uint8_t> bytes) {
  if (bytes.size() > kMaxEndpointDescriptorBytes) {
    return fail<EndpointDescriptor>(ErrorCode::capacity, MpError::endpoint_too_large);
  }
  if (bytes.size() < 3U) {
    return fail<EndpointDescriptor>(ErrorCode::corrupt, MpError::endpoint_truncated);
  }
  const auto transport_kind = transport_kind_from_u8(bytes[0]);
  if (!transport_kind.has_value()) {
    return Result<EndpointDescriptor>::failure(transport_kind.error());
  }
  const std::size_t relay_len =
      static_cast<std::size_t>(bytes[1]) | (static_cast<std::size_t>(bytes[2]) << 8U);
  if (relay_len > kMaxRelayUrlBytes) {
    return fail<EndpointDescriptor>(ErrorCode::invalid_range,
                                    MpError::invalid_relay_url);
  }
  const std::size_t relay_end = 3U + relay_len;
  if (relay_end >= bytes.size()) {
    return fail<EndpointDescriptor>(ErrorCode::corrupt, MpError::endpoint_truncated);
  }
  const auto relay_slice = bytes.subspan(3U, relay_len);
  if (!is_valid_utf8(relay_slice)) {
    return fail<EndpointDescriptor>(ErrorCode::corrupt, MpError::invalid_relay_url);
  }
  std::string relay_url;
  relay_url.reserve(relay_len);
  for (const std::uint8_t b : relay_slice) {
    relay_url.push_back(static_cast<char>(b));
  }
  if (const auto ok = validate_relay_url(relay_url); !ok.has_value()) {
    return Result<EndpointDescriptor>::failure(ok.error());
  }

  const std::size_t direct_count = bytes[relay_end];
  if (direct_count > kMaxDirectAddrs) {
    return fail<EndpointDescriptor>(ErrorCode::invalid_range,
                                    MpError::too_many_direct_addrs);
  }
  std::size_t cursor = relay_end + 1U;
  std::vector<DirectAddr> direct_addrs;
  direct_addrs.reserve(direct_count);
  for (std::size_t i = 0U; i < direct_count; ++i) {
    if (cursor >= bytes.size()) {
      return fail<EndpointDescriptor>(ErrorCode::corrupt, MpError::endpoint_truncated);
    }
    const std::uint8_t fam = bytes[cursor++];
    if (fam == 4U) {
      if (bytes.size() - cursor < 6U) {
        return fail<EndpointDescriptor>(ErrorCode::corrupt,
                                        MpError::endpoint_truncated);
      }
      DirectAddrV4 v4{};
      std::memcpy(v4.ip.data(), bytes.data() + cursor, 4U);
      cursor += 4U;
      v4.port = static_cast<std::uint16_t>(
          static_cast<std::uint16_t>(bytes[cursor]) |
          (static_cast<std::uint16_t>(bytes[cursor + 1U]) << 8U));
      cursor += 2U;
      if (v4.port == 0U) {
        return fail<EndpointDescriptor>(ErrorCode::invalid_range,
                                        MpError::invalid_port);
      }
      direct_addrs.emplace_back(v4);
    } else if (fam == 6U) {
      if (bytes.size() - cursor < 18U) {
        return fail<EndpointDescriptor>(ErrorCode::corrupt,
                                        MpError::endpoint_truncated);
      }
      DirectAddrV6 v6{};
      std::memcpy(v6.ip.data(), bytes.data() + cursor, 16U);
      cursor += 16U;
      v6.port = static_cast<std::uint16_t>(
          static_cast<std::uint16_t>(bytes[cursor]) |
          (static_cast<std::uint16_t>(bytes[cursor + 1U]) << 8U));
      cursor += 2U;
      if (v6.port == 0U) {
        return fail<EndpointDescriptor>(ErrorCode::invalid_range,
                                        MpError::invalid_port);
      }
      direct_addrs.emplace_back(v6);
    } else {
      return fail<EndpointDescriptor>(ErrorCode::corrupt, MpError::invalid_addr_family);
    }
  }
  if (cursor != bytes.size()) {
    return fail<EndpointDescriptor>(ErrorCode::corrupt,
                                    MpError::endpoint_trailing_bytes);
  }
  EndpointDescriptor ep{transport_kind.value(), std::move(relay_url),
                        std::move(direct_addrs)};
  if (const auto ok = ep.validate(); !ok.has_value()) {
    return Result<EndpointDescriptor>::failure(ok.error());
  }
  return Result<EndpointDescriptor>::success(std::move(ep));
}

// ---------------------------------------------------------------------------
// 4. MP1 16-byte LE binary frame codec
// ---------------------------------------------------------------------------

Opcode opcode_of(const Mp1Message &message) noexcept {
  if (std::holds_alternative<HelloAckMessage>(message)) {
    return Opcode::hello_ack;
  }
  if (std::holds_alternative<ErrorMessage>(message)) {
    return Opcode::error;
  }
  if (std::holds_alternative<PresenceSetMessage>(message)) {
    return Opcode::presence_set;
  }
  if (std::holds_alternative<PresenceSnapshotMessage>(message)) {
    return Opcode::presence_snapshot;
  }
  if (std::holds_alternative<PresenceDeltaMessage>(message)) {
    return Opcode::presence_delta;
  }
  if (std::holds_alternative<SocialEventMessage>(message)) {
    return Opcode::social_event;
  }
  if (std::holds_alternative<PartyInviteNotifyMessage>(message)) {
    return Opcode::party_invite_notify;
  }
  if (std::holds_alternative<PartySnapshotMessage>(message)) {
    return Opcode::party_snapshot;
  }
  if (std::holds_alternative<PartyMemberJoinedMessage>(message)) {
    return Opcode::party_member_joined;
  }
  if (std::holds_alternative<PartyEndpointUpdateMessage>(message)) {
    return Opcode::party_endpoint_update;
  }
  if (std::holds_alternative<PartyMemberUpdatedMessage>(message)) {
    return Opcode::party_member_updated;
  }
  if (std::holds_alternative<PartyMemberLeftMessage>(message)) {
    return Opcode::party_member_left;
  }
  if (std::holds_alternative<PartyLeaderChangedMessage>(message)) {
    return Opcode::party_leader_changed;
  }
  if (std::holds_alternative<PartyJoinRequestEventMessage>(message)) {
    return Opcode::party_join_request_event;
  }
  return Opcode::party_disbanded;
}

Result<std::vector<std::uint8_t>> encode_frame(std::uint32_t seq,
                                               const Mp1Message &message) {
  std::vector<std::uint8_t> payload;
  payload.reserve(256U);

  if (const auto *hello = std::get_if<HelloAckMessage>(&message)) {
    const auto now_ms = check_safe_u64(hello->server_now_ms);
    if (!now_ms.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(now_ms.error());
    }
    append_bytes(payload, hello->session_id.to_le_bytes());
    append_u64_le(payload, now_ms.value());
    append_u32_le(payload, hello->ping_interval_ms);
  } else if (const auto *err = std::get_if<ErrorMessage>(&message)) {
    append_u32_le(payload, err->ref_seq);
    append_u16_le(payload, err->code);
    append_u32_le(payload, err->retry_after_ms);
  } else if (const auto *pset = std::get_if<PresenceSetMessage>(&message)) {
    payload.push_back(static_cast<std::uint8_t>(pset->visibility));
    payload.push_back(pset->share_party ? 1U : 0U);
  } else if (const auto *psnap = std::get_if<PresenceSnapshotMessage>(&message)) {
    if (psnap->entries.size() > kMaxPresenceEntries) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                             MpError::mp1_invalid_count);
    }
    append_u16_le(payload, static_cast<std::uint16_t>(psnap->entries.size()));
    for (const auto &entry : psnap->entries) {
      if (const auto ok = write_presence_entry(payload, entry); !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
    }
  } else if (const auto *pdelta = std::get_if<PresenceDeltaMessage>(&message)) {
    if (const auto ok = write_presence_entry(payload, pdelta->entry); !ok.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ok.error());
    }
  } else if (const auto *social = std::get_if<SocialEventMessage>(&message)) {
    payload.push_back(static_cast<std::uint8_t>(social->kind));
    append_bytes(payload, social->peer_account_id.to_le_bytes());
  } else if (const auto *invite = std::get_if<PartyInviteNotifyMessage>(&message)) {
    const auto exp = check_safe_u64(invite->expires_at_ms);
    if (!exp.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(exp.error());
    }
    append_bytes(payload, invite->party_invite_id.to_le_bytes());
    append_bytes(payload, invite->party_id.to_le_bytes());
    append_bytes(payload, invite->from_account_id.to_le_bytes());
    append_u64_le(payload, exp.value());
  } else if (const auto *snap = std::get_if<PartySnapshotMessage>(&message)) {
    if (const auto ok = validate_party_snapshot(*snap); !ok.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ok.error());
    }
    append_bytes(payload, snap->party_id.to_le_bytes());
    append_u64_le(payload, snap->party_epoch);
    append_bytes(payload, snap->leader_account_id.to_le_bytes());
    append_bytes(payload, snap->leader_device_id.to_le_bytes());
    payload.push_back(static_cast<std::uint8_t>(snap->visibility));
    payload.push_back(static_cast<std::uint8_t>(snap->join_mode));
    payload.push_back(static_cast<std::uint8_t>(snap->relay_policy));
    payload.push_back(snap->max_members);
    append_u16_le(payload, static_cast<std::uint16_t>(snap->pinned_relay_url.size()));
    append_string_bytes(payload, snap->pinned_relay_url);
    payload.push_back(static_cast<std::uint8_t>(snap->members.size()));
    for (const auto &member : snap->members) {
      if (const auto ok = write_member_record(payload, member); !ok.has_value()) {
        return Result<std::vector<std::uint8_t>>::failure(ok.error());
      }
    }
  } else if (const auto *joined = std::get_if<PartyMemberJoinedMessage>(&message)) {
    const auto epoch = check_positive_safe_u64(joined->party_epoch);
    if (!epoch.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(epoch.error());
    }
    append_u64_le(payload, epoch.value());
    if (const auto ok = write_member_record(payload, joined->member); !ok.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ok.error());
    }
  } else if (const auto *ep_upd = std::get_if<PartyEndpointUpdateMessage>(&message)) {
    const auto ep = ep_upd->endpoint.encode();
    if (!ep.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ep.error());
    }
    append_bytes(payload, ep.value());
  } else if (const auto *updated = std::get_if<PartyMemberUpdatedMessage>(&message)) {
    if (updated->device_cwt.empty() || updated->device_cwt.size() > kMaxCwtBytes) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                             MpError::mp1_invalid_cwt_length);
    }
    const auto epoch = check_positive_safe_u64(updated->party_epoch);
    if (!epoch.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(epoch.error());
    }
    const auto ep = updated->endpoint.encode();
    if (!ep.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ep.error());
    }
    append_u64_le(payload, epoch.value());
    append_bytes(payload, updated->device_id.to_le_bytes());
    payload.push_back(updated->connected ? 1U : 0U);
    append_u16_le(payload, static_cast<std::uint16_t>(updated->device_cwt.size()));
    append_bytes(payload, updated->device_cwt);
    append_u16_le(payload, static_cast<std::uint16_t>(ep.value().size()));
    append_bytes(payload, ep.value());
  } else if (const auto *left = std::get_if<PartyMemberLeftMessage>(&message)) {
    const auto epoch = check_positive_safe_u64(left->party_epoch);
    if (!epoch.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(epoch.error());
    }
    append_u64_le(payload, epoch.value());
    append_bytes(payload, left->device_id.to_le_bytes());
    append_bytes(payload, left->account_id.to_le_bytes());
    payload.push_back(static_cast<std::uint8_t>(left->reason));
  } else if (const auto *leader = std::get_if<PartyLeaderChangedMessage>(&message)) {
    const auto epoch = check_positive_safe_u64(leader->party_epoch);
    if (!epoch.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(epoch.error());
    }
    append_u64_le(payload, epoch.value());
    append_bytes(payload, leader->new_leader_account_id.to_le_bytes());
    append_bytes(payload, leader->new_leader_device_id.to_le_bytes());
    payload.push_back(static_cast<std::uint8_t>(leader->reason));
  } else if (const auto *join_req =
                 std::get_if<PartyJoinRequestEventMessage>(&message)) {
    append_bytes(payload, join_req->request_id.to_le_bytes());
    append_bytes(payload, join_req->account_id.to_le_bytes());
    append_bytes(payload, join_req->device_id.to_le_bytes());
    append_bytes(payload, join_req->root_pubkey);
    append_bytes(payload, join_req->device_pubkey);
  } else {
    const auto &disbanded = std::get<PartyDisbandedMessage>(message);
    const auto epoch = check_positive_safe_u64(disbanded.party_epoch);
    if (!epoch.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(epoch.error());
    }
    append_u64_le(payload, epoch.value());
    payload.push_back(static_cast<std::uint8_t>(disbanded.reason));
  }

  if (payload.size() > kMaxMp1FrameBytes - kMp1HeaderBytes) {
    return fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                           MpError::mp1_frame_too_large);
  }
  const std::size_t total_len = kMp1HeaderBytes + payload.size();
  std::vector<std::uint8_t> frame;
  frame.reserve(total_len);
  frame.push_back(kMp1Version);
  frame.push_back(0U); // flags
  append_u16_le(frame, static_cast<std::uint16_t>(opcode_of(message)));
  append_u32_le(frame, 0U); // reserved
  append_u32_le(frame, seq);
  append_u32_le(frame, static_cast<std::uint32_t>(payload.size()));
  append_bytes(frame, payload);
  return Result<std::vector<std::uint8_t>>::success(std::move(frame));
}

Result<DecodedFrame> decode_frame(std::span<const std::uint8_t> bytes) {
  if (bytes.size() > kMaxMp1FrameBytes) {
    return fail<DecodedFrame>(ErrorCode::capacity, MpError::mp1_frame_too_large);
  }
  if (bytes.size() < kMp1HeaderBytes) {
    return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_truncated);
  }

  BinaryReader reader{bytes};
  const auto version = reader.read_u8();
  if (!version.has_value()) {
    return Result<DecodedFrame>::failure(version.error());
  }
  if (version.value() != kMp1Version) {
    return fail<DecodedFrame>(ErrorCode::unsupported, MpError::mp1_unsupported_version);
  }
  const auto flags = reader.read_u8();
  if (!flags.has_value()) {
    return Result<DecodedFrame>::failure(flags.error());
  }
  if (flags.value() != 0U) {
    return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_non_zero_flags);
  }
  const auto op_raw = reader.read_u16();
  if (!op_raw.has_value()) {
    return Result<DecodedFrame>::failure(op_raw.error());
  }
  const auto opcode = opcode_from_u16(op_raw.value());
  if (!opcode.has_value()) {
    return Result<DecodedFrame>::failure(opcode.error());
  }
  const auto reserved = reader.read_u32();
  if (!reserved.has_value()) {
    return Result<DecodedFrame>::failure(reserved.error());
  }
  if (reserved.value() != 0U) {
    return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_non_zero_reserved);
  }
  const auto seq = reader.read_u32();
  if (!seq.has_value()) {
    return Result<DecodedFrame>::failure(seq.error());
  }
  const auto payload_len = reader.read_u32();
  if (!payload_len.has_value()) {
    return Result<DecodedFrame>::failure(payload_len.error());
  }
  if (static_cast<std::size_t>(payload_len.value()) != bytes.size() - kMp1HeaderBytes) {
    return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_length_mismatch);
  }

  std::optional<Mp1Message> decoded;
  switch (opcode.value()) {
  case Opcode::hello_ack: {
    const auto sid_raw = reader.read_u64_safe();
    if (!sid_raw.has_value()) {
      return Result<DecodedFrame>::failure(sid_raw.error());
    }
    const auto session_id = SessionId::create(sid_raw.value());
    if (!session_id.has_value()) {
      return Result<DecodedFrame>::failure(session_id.error());
    }
    const auto server_now_ms = reader.read_u64_safe();
    if (!server_now_ms.has_value()) {
      return Result<DecodedFrame>::failure(server_now_ms.error());
    }
    const auto ping_interval_ms = reader.read_u32();
    if (!ping_interval_ms.has_value()) {
      return Result<DecodedFrame>::failure(ping_interval_ms.error());
    }
    decoded = HelloAckMessage{session_id.value(), server_now_ms.value(),
                              ping_interval_ms.value()};
    break;
  }
  case Opcode::error: {
    const auto ref_seq = reader.read_u32();
    if (!ref_seq.has_value()) {
      return Result<DecodedFrame>::failure(ref_seq.error());
    }
    const auto code = reader.read_u16();
    if (!code.has_value()) {
      return Result<DecodedFrame>::failure(code.error());
    }
    const auto retry_after_ms = reader.read_u32();
    if (!retry_after_ms.has_value()) {
      return Result<DecodedFrame>::failure(retry_after_ms.error());
    }
    decoded = ErrorMessage{ref_seq.value(), code.value(), retry_after_ms.value()};
    break;
  }
  case Opcode::presence_set: {
    const auto vis_raw = reader.read_u8();
    if (!vis_raw.has_value()) {
      return Result<DecodedFrame>::failure(vis_raw.error());
    }
    const auto visibility = presence_visibility_from_u8(vis_raw.value());
    if (!visibility.has_value()) {
      return Result<DecodedFrame>::failure(visibility.error());
    }
    const auto share_party = reader.read_bool();
    if (!share_party.has_value()) {
      return Result<DecodedFrame>::failure(share_party.error());
    }
    decoded = PresenceSetMessage{visibility.value(), share_party.value()};
    break;
  }
  case Opcode::presence_snapshot: {
    const auto count_raw = reader.read_u16();
    if (!count_raw.has_value()) {
      return Result<DecodedFrame>::failure(count_raw.error());
    }
    const auto count = static_cast<std::size_t>(count_raw.value());
    if (count > kMaxPresenceEntries) {
      return fail<DecodedFrame>(ErrorCode::invalid_range, MpError::mp1_invalid_count);
    }
    std::vector<PresenceEntry> entries;
    entries.reserve(count);
    for (std::size_t i = 0U; i < count; ++i) {
      const auto entry = read_presence_entry(reader);
      if (!entry.has_value()) {
        return Result<DecodedFrame>::failure(entry.error());
      }
      entries.push_back(entry.value());
    }
    decoded = PresenceSnapshotMessage{std::move(entries)};
    break;
  }
  case Opcode::presence_delta: {
    const auto entry = read_presence_entry(reader);
    if (!entry.has_value()) {
      return Result<DecodedFrame>::failure(entry.error());
    }
    decoded = PresenceDeltaMessage{entry.value()};
    break;
  }
  case Opcode::social_event: {
    const auto kind_raw = reader.read_u8();
    if (!kind_raw.has_value()) {
      return Result<DecodedFrame>::failure(kind_raw.error());
    }
    const auto kind = social_event_kind_from_u8(kind_raw.value());
    if (!kind.has_value()) {
      return Result<DecodedFrame>::failure(kind.error());
    }
    const auto peer_raw = reader.read_u64_safe();
    if (!peer_raw.has_value()) {
      return Result<DecodedFrame>::failure(peer_raw.error());
    }
    const auto peer = AccountId::create(peer_raw.value());
    if (!peer.has_value()) {
      return Result<DecodedFrame>::failure(peer.error());
    }
    decoded = SocialEventMessage{kind.value(), peer.value()};
    break;
  }
  case Opcode::party_invite_notify: {
    const auto inv_raw = reader.read_u64_safe();
    if (!inv_raw.has_value()) {
      return Result<DecodedFrame>::failure(inv_raw.error());
    }
    const auto inv_id = PartyInviteId::create(inv_raw.value());
    if (!inv_id.has_value()) {
      return Result<DecodedFrame>::failure(inv_id.error());
    }
    const auto pid_raw = reader.read_u64_safe();
    if (!pid_raw.has_value()) {
      return Result<DecodedFrame>::failure(pid_raw.error());
    }
    const auto party_id = PartyId::create(pid_raw.value());
    if (!party_id.has_value()) {
      return Result<DecodedFrame>::failure(party_id.error());
    }
    const auto from_raw = reader.read_u64_safe();
    if (!from_raw.has_value()) {
      return Result<DecodedFrame>::failure(from_raw.error());
    }
    const auto from_id = AccountId::create(from_raw.value());
    if (!from_id.has_value()) {
      return Result<DecodedFrame>::failure(from_id.error());
    }
    const auto expires_at_ms = reader.read_u64_safe();
    if (!expires_at_ms.has_value()) {
      return Result<DecodedFrame>::failure(expires_at_ms.error());
    }
    decoded = PartyInviteNotifyMessage{inv_id.value(), party_id.value(),
                                       from_id.value(), expires_at_ms.value()};
    break;
  }
  case Opcode::party_snapshot: {
    const auto pid_raw = reader.read_u64_safe();
    if (!pid_raw.has_value()) {
      return Result<DecodedFrame>::failure(pid_raw.error());
    }
    const auto party_id = PartyId::create(pid_raw.value());
    if (!party_id.has_value()) {
      return Result<DecodedFrame>::failure(party_id.error());
    }
    const auto epoch_raw = reader.read_u64_safe();
    if (!epoch_raw.has_value()) {
      return Result<DecodedFrame>::failure(epoch_raw.error());
    }
    const auto party_epoch = check_positive_safe_u64(epoch_raw.value());
    if (!party_epoch.has_value()) {
      return Result<DecodedFrame>::failure(party_epoch.error());
    }
    const auto la_raw = reader.read_u64_safe();
    if (!la_raw.has_value()) {
      return Result<DecodedFrame>::failure(la_raw.error());
    }
    const auto leader_account_id = AccountId::create(la_raw.value());
    if (!leader_account_id.has_value()) {
      return Result<DecodedFrame>::failure(leader_account_id.error());
    }
    const auto ld_raw = reader.read_u64_safe();
    if (!ld_raw.has_value()) {
      return Result<DecodedFrame>::failure(ld_raw.error());
    }
    const auto leader_device_id = DeviceId::create(ld_raw.value());
    if (!leader_device_id.has_value()) {
      return Result<DecodedFrame>::failure(leader_device_id.error());
    }
    const auto vis_raw = reader.read_u8();
    if (!vis_raw.has_value()) {
      return Result<DecodedFrame>::failure(vis_raw.error());
    }
    const auto visibility = party_visibility_from_u8(vis_raw.value());
    if (!visibility.has_value()) {
      return Result<DecodedFrame>::failure(visibility.error());
    }
    const auto jm_raw = reader.read_u8();
    if (!jm_raw.has_value()) {
      return Result<DecodedFrame>::failure(jm_raw.error());
    }
    const auto join_mode = party_join_mode_from_u8(jm_raw.value());
    if (!join_mode.has_value()) {
      return Result<DecodedFrame>::failure(join_mode.error());
    }
    const auto rp_raw = reader.read_u8();
    if (!rp_raw.has_value()) {
      return Result<DecodedFrame>::failure(rp_raw.error());
    }
    const auto relay_policy = relay_policy_from_u8(rp_raw.value());
    if (!relay_policy.has_value()) {
      return Result<DecodedFrame>::failure(relay_policy.error());
    }
    const auto max_members = reader.read_u8();
    if (!max_members.has_value()) {
      return Result<DecodedFrame>::failure(max_members.error());
    }
    if (max_members.value() < 2U ||
        static_cast<std::size_t>(max_members.value()) > kMaxPartyMembers) {
      return fail<DecodedFrame>(ErrorCode::invalid_range, MpError::mp1_invalid_count);
    }
    const auto url_bytes = reader.read_bytes_u16(kMaxRelayUrlBytes);
    if (!url_bytes.has_value()) {
      return Result<DecodedFrame>::failure(url_bytes.error());
    }
    if (!is_valid_utf8(url_bytes.value())) {
      return fail<DecodedFrame>(ErrorCode::corrupt, MpError::invalid_relay_url);
    }
    std::string pinned_relay_url;
    pinned_relay_url.reserve(url_bytes.value().size());
    for (const std::uint8_t b : url_bytes.value()) {
      pinned_relay_url.push_back(static_cast<char>(b));
    }
    const auto mcount_raw = reader.read_u8();
    if (!mcount_raw.has_value()) {
      return Result<DecodedFrame>::failure(mcount_raw.error());
    }
    if (mcount_raw.value() > max_members.value()) {
      return fail<DecodedFrame>(ErrorCode::invalid_range, MpError::mp1_invalid_count);
    }
    std::vector<PartyMemberRecord> members;
    members.reserve(mcount_raw.value());
    for (std::size_t i = 0U; i < mcount_raw.value(); ++i) {
      const auto rec = read_member_record(reader);
      if (!rec.has_value()) {
        return Result<DecodedFrame>::failure(rec.error());
      }
      members.push_back(rec.value());
    }
    PartySnapshotMessage snap{
        party_id.value(),         party_epoch.value(), leader_account_id.value(),
        leader_device_id.value(), visibility.value(),  join_mode.value(),
        relay_policy.value(),     max_members.value(), std::move(pinned_relay_url),
        std::move(members),
    };
    if (const auto ok = validate_party_snapshot(snap); !ok.has_value()) {
      return Result<DecodedFrame>::failure(ok.error());
    }
    decoded = std::move(snap);
    break;
  }
  case Opcode::party_member_joined: {
    const auto epoch_raw = reader.read_u64_safe();
    if (!epoch_raw.has_value()) {
      return Result<DecodedFrame>::failure(epoch_raw.error());
    }
    const auto party_epoch = check_positive_safe_u64(epoch_raw.value());
    if (!party_epoch.has_value()) {
      return Result<DecodedFrame>::failure(party_epoch.error());
    }
    const auto member = read_member_record(reader);
    if (!member.has_value()) {
      return Result<DecodedFrame>::failure(member.error());
    }
    if (const auto seq_ok = check_positive_safe_u64(member.value().joined_seq);
        !seq_ok.has_value()) {
      return Result<DecodedFrame>::failure(seq_ok.error());
    }
    decoded = PartyMemberJoinedMessage{party_epoch.value(), member.value()};
    break;
  }
  case Opcode::party_endpoint_update: {
    const auto rest = reader.take(static_cast<std::size_t>(payload_len.value()));
    if (!rest.has_value()) {
      return Result<DecodedFrame>::failure(rest.error());
    }
    const auto ep = EndpointDescriptor::decode(rest.value());
    if (!ep.has_value()) {
      return Result<DecodedFrame>::failure(ep.error());
    }
    decoded = PartyEndpointUpdateMessage{ep.value()};
    break;
  }
  case Opcode::party_member_updated: {
    const auto epoch_raw = reader.read_u64_safe();
    if (!epoch_raw.has_value()) {
      return Result<DecodedFrame>::failure(epoch_raw.error());
    }
    const auto party_epoch = check_positive_safe_u64(epoch_raw.value());
    if (!party_epoch.has_value()) {
      return Result<DecodedFrame>::failure(party_epoch.error());
    }
    const auto dev_raw = reader.read_u64_safe();
    if (!dev_raw.has_value()) {
      return Result<DecodedFrame>::failure(dev_raw.error());
    }
    const auto device_id = DeviceId::create(dev_raw.value());
    if (!device_id.has_value()) {
      return Result<DecodedFrame>::failure(device_id.error());
    }
    const auto connected = reader.read_bool();
    if (!connected.has_value()) {
      return Result<DecodedFrame>::failure(connected.error());
    }
    const auto cwt_bytes = reader.read_bytes_u16(kMaxCwtBytes);
    if (!cwt_bytes.has_value()) {
      return Result<DecodedFrame>::failure(cwt_bytes.error());
    }
    if (cwt_bytes.value().empty()) {
      return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_invalid_cwt_length);
    }
    const auto ep_bytes = reader.read_bytes_u16(kMaxEndpointDescriptorBytes);
    if (!ep_bytes.has_value()) {
      return Result<DecodedFrame>::failure(ep_bytes.error());
    }
    const auto endpoint = EndpointDescriptor::decode(ep_bytes.value());
    if (!endpoint.has_value()) {
      return Result<DecodedFrame>::failure(endpoint.error());
    }
    decoded = PartyMemberUpdatedMessage{party_epoch.value(), device_id.value(),
                                        connected.value(), cwt_bytes.value(),
                                        endpoint.value()};
    break;
  }
  case Opcode::party_member_left: {
    const auto epoch_raw = reader.read_u64_safe();
    if (!epoch_raw.has_value()) {
      return Result<DecodedFrame>::failure(epoch_raw.error());
    }
    const auto party_epoch = check_positive_safe_u64(epoch_raw.value());
    if (!party_epoch.has_value()) {
      return Result<DecodedFrame>::failure(party_epoch.error());
    }
    const auto dev_raw = reader.read_u64_safe();
    if (!dev_raw.has_value()) {
      return Result<DecodedFrame>::failure(dev_raw.error());
    }
    const auto device_id = DeviceId::create(dev_raw.value());
    if (!device_id.has_value()) {
      return Result<DecodedFrame>::failure(device_id.error());
    }
    const auto acct_raw = reader.read_u64_safe();
    if (!acct_raw.has_value()) {
      return Result<DecodedFrame>::failure(acct_raw.error());
    }
    const auto account_id = AccountId::create(acct_raw.value());
    if (!account_id.has_value()) {
      return Result<DecodedFrame>::failure(account_id.error());
    }
    const auto reason_raw = reader.read_u8();
    if (!reason_raw.has_value()) {
      return Result<DecodedFrame>::failure(reason_raw.error());
    }
    const auto reason = member_leave_reason_from_u8(reason_raw.value());
    if (!reason.has_value()) {
      return Result<DecodedFrame>::failure(reason.error());
    }
    decoded = PartyMemberLeftMessage{party_epoch.value(), device_id.value(),
                                     account_id.value(), reason.value()};
    break;
  }
  case Opcode::party_leader_changed: {
    const auto epoch_raw = reader.read_u64_safe();
    if (!epoch_raw.has_value()) {
      return Result<DecodedFrame>::failure(epoch_raw.error());
    }
    const auto party_epoch = check_positive_safe_u64(epoch_raw.value());
    if (!party_epoch.has_value()) {
      return Result<DecodedFrame>::failure(party_epoch.error());
    }
    const auto acct_raw = reader.read_u64_safe();
    if (!acct_raw.has_value()) {
      return Result<DecodedFrame>::failure(acct_raw.error());
    }
    const auto account_id = AccountId::create(acct_raw.value());
    if (!account_id.has_value()) {
      return Result<DecodedFrame>::failure(account_id.error());
    }
    const auto dev_raw = reader.read_u64_safe();
    if (!dev_raw.has_value()) {
      return Result<DecodedFrame>::failure(dev_raw.error());
    }
    const auto device_id = DeviceId::create(dev_raw.value());
    if (!device_id.has_value()) {
      return Result<DecodedFrame>::failure(device_id.error());
    }
    const auto reason_raw = reader.read_u8();
    if (!reason_raw.has_value()) {
      return Result<DecodedFrame>::failure(reason_raw.error());
    }
    const auto reason = party_leader_change_reason_from_u8(reason_raw.value());
    if (!reason.has_value()) {
      return Result<DecodedFrame>::failure(reason.error());
    }
    decoded = PartyLeaderChangedMessage{party_epoch.value(), account_id.value(),
                                        device_id.value(), reason.value()};
    break;
  }
  case Opcode::party_join_request_event: {
    const auto req_raw = reader.read_u64_safe();
    if (!req_raw.has_value()) {
      return Result<DecodedFrame>::failure(req_raw.error());
    }
    const auto request_id = RequestId::create(req_raw.value());
    if (!request_id.has_value()) {
      return Result<DecodedFrame>::failure(request_id.error());
    }
    const auto acct_raw = reader.read_u64_safe();
    if (!acct_raw.has_value()) {
      return Result<DecodedFrame>::failure(acct_raw.error());
    }
    const auto account_id = AccountId::create(acct_raw.value());
    if (!account_id.has_value()) {
      return Result<DecodedFrame>::failure(account_id.error());
    }
    const auto dev_raw = reader.read_u64_safe();
    if (!dev_raw.has_value()) {
      return Result<DecodedFrame>::failure(dev_raw.error());
    }
    const auto device_id = DeviceId::create(dev_raw.value());
    if (!device_id.has_value()) {
      return Result<DecodedFrame>::failure(device_id.error());
    }
    const auto root_pk = reader.read_pubkey();
    if (!root_pk.has_value()) {
      return Result<DecodedFrame>::failure(root_pk.error());
    }
    const auto dev_pk = reader.read_pubkey();
    if (!dev_pk.has_value()) {
      return Result<DecodedFrame>::failure(dev_pk.error());
    }
    decoded = PartyJoinRequestEventMessage{request_id.value(), account_id.value(),
                                           device_id.value(), root_pk.value(),
                                           dev_pk.value()};
    break;
  }
  case Opcode::party_disbanded: {
    const auto epoch_raw = reader.read_u64_safe();
    if (!epoch_raw.has_value()) {
      return Result<DecodedFrame>::failure(epoch_raw.error());
    }
    const auto party_epoch = check_positive_safe_u64(epoch_raw.value());
    if (!party_epoch.has_value()) {
      return Result<DecodedFrame>::failure(party_epoch.error());
    }
    const auto reason_raw = reader.read_u8();
    if (!reason_raw.has_value()) {
      return Result<DecodedFrame>::failure(reason_raw.error());
    }
    const auto reason = party_disband_reason_from_u8(reason_raw.value());
    if (!reason.has_value()) {
      return Result<DecodedFrame>::failure(reason.error());
    }
    decoded = PartyDisbandedMessage{party_epoch.value(), reason.value()};
    break;
  }
  }

  if (!reader.at_end()) {
    return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_trailing_bytes);
  }
  if (!decoded.has_value()) {
    return fail<DecodedFrame>(ErrorCode::corrupt, MpError::mp1_unknown_opcode);
  }
  return Result<DecodedFrame>::success(DecodedFrame{
      FrameHeader{opcode.value(), seq.value(), payload_len.value()},
      std::move(*decoded),
  });
}

// ---------------------------------------------------------------------------
// 5. Strict RFC 9421 + RFC 9530 HTTP Message Signer & Verifier
// ---------------------------------------------------------------------------

Result<HttpMethod> parse_http_method(std::string_view name) {
  if (name == "GET") {
    return Result<HttpMethod>::success(HttpMethod::get);
  }
  if (name == "POST") {
    return Result<HttpMethod>::success(HttpMethod::post);
  }
  if (name == "PUT") {
    return Result<HttpMethod>::success(HttpMethod::put);
  }
  if (name == "PATCH") {
    return Result<HttpMethod>::success(HttpMethod::patch);
  }
  if (name == "DELETE") {
    return Result<HttpMethod>::success(HttpMethod::del);
  }
  return fail<HttpMethod>(ErrorCode::unsupported, MpError::rfc9421_unsupported_method);
}

Result<KeyId> parse_key_id(std::string_view raw) {
  static constexpr std::string_view kRegPrefix = "reg.";
  if (raw.starts_with(kRegPrefix)) {
    const std::string_view hex_part = raw.substr(kRegPrefix.size());
    if (hex_part.size() != 32U) {
      return fail<KeyId>(ErrorCode::invalid_identity, MpError::rfc9421_invalid_key_id);
    }
    RegistrationKeyId reg{};
    for (std::size_t i = 0U; i < 16U; ++i) {
      const auto hi = hex_nibble_lower(hex_part[i * 2U]);
      const auto lo = hex_nibble_lower(hex_part[(i * 2U) + 1U]);
      if (!hi.has_value() || !lo.has_value()) {
        return fail<KeyId>(ErrorCode::invalid_identity,
                           MpError::rfc9421_invalid_key_id);
      }
      reg.root_pubkey_sha256_prefix[i] =
          static_cast<std::uint8_t>((hi.value() << 4U) | lo.value());
    }
    return Result<KeyId>::success(reg);
  }

  const std::size_t dot = raw.find('.');
  if (dot == std::string_view::npos) {
    return fail<KeyId>(ErrorCode::invalid_identity, MpError::rfc9421_invalid_key_id);
  }
  const std::string_view acct_str = raw.substr(0U, dot);
  const std::string_view rest = raw.substr(dot + 1U);
  const auto account_id = AccountId::parse_decimal(acct_str);
  if (!account_id.has_value()) {
    return fail<KeyId>(ErrorCode::invalid_identity, MpError::rfc9421_invalid_key_id);
  }
  if (rest == "root") {
    return Result<KeyId>::success(RootKeyId{account_id.value()});
  }
  const auto device_id = DeviceId::parse_decimal(rest);
  if (!device_id.has_value()) {
    return fail<KeyId>(ErrorCode::invalid_identity, MpError::rfc9421_invalid_key_id);
  }
  return Result<KeyId>::success(DeviceKeyId{account_id.value(), device_id.value()});
}

std::string format_key_id(const KeyId &key_id) {
  if (const auto *dev = std::get_if<DeviceKeyId>(&key_id)) {
    return dev->account_id.to_decimal() + "." + dev->device_id.to_decimal();
  }
  if (const auto *root = std::get_if<RootKeyId>(&key_id)) {
    return root->account_id.to_decimal() + ".root";
  }
  const auto &reg = std::get<RegistrationKeyId>(key_id);
  return "reg." + hex_lower(reg.root_pubkey_sha256_prefix);
}

Result<RegistrationKeyId> registration_key_id_for_pubkey(const Ed25519PubKey &pubkey) {
  const auto digest = sha256(pubkey);
  if (!digest.has_value()) {
    return Result<RegistrationKeyId>::failure(digest.error());
  }
  RegistrationKeyId reg{};
  std::memcpy(reg.root_pubkey_sha256_prefix.data(), digest.value().data(),
              reg.root_pubkey_sha256_prefix.size());
  return Result<RegistrationKeyId>::success(reg);
}

Result<std::string> compute_content_digest(std::span<const std::uint8_t> body) {
  const auto digest = sha256(body);
  if (!digest.has_value()) {
    return Result<std::string>::failure(digest.error());
  }
  return Result<std::string>::success("sha-256=:" + base64_std_encode(digest.value()) +
                                      ":");
}

Result<void> validate_path_and_query(const HttpTarget &target) {
  if (target.path.empty() || target.path.front() != '/' || target.path.size() > 256U) {
    return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_invalid_path);
  }
  if (target.path.find("//") != std::string_view::npos ||
      target.path.find('\\') != std::string_view::npos ||
      target.path.find('%') != std::string_view::npos) {
    return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_invalid_path);
  }
  for (const char ch : target.path) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x21U || byte > 0x7eU) {
      return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_invalid_path);
    }
  }
  std::size_t start = 1U;
  while (start <= target.path.size()) {
    const std::size_t slash = target.path.find('/', start);
    const std::string_view seg = (slash == std::string_view::npos)
                                     ? target.path.substr(start)
                                     : target.path.substr(start, slash - start);
    if (seg == "." || seg == "..") {
      return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_invalid_path);
    }
    if (slash == std::string_view::npos) {
      break;
    }
    start = slash + 1U;
  }

  if (target.query.empty() || target.query.front() != '?' ||
      target.query.size() > 256U) {
    return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_invalid_path);
  }
  for (const char ch : target.query) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x21U || byte > 0x7eU) {
      return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_invalid_path);
    }
  }
  if (target.query.size() > 1U) {
    const bool allowed =
        target.method == HttpMethod::get &&
        (target.path == "/v1/accounts/resolve" || is_party_requests_path(target.path));
    if (!allowed) {
      return fail_void(ErrorCode::invalid_identity, MpError::rfc9421_query_not_allowed);
    }
  }
  return Result<void>::success();
}

Result<ParsedSignatureInput> parse_signature_input(std::string_view header) {
  const std::string_view trimmed = trim_http_ows(header);
  for (const char ch : trimmed) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x20U || byte > 0x7eU) {
      return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                        MpError::rfc9421_invalid_signature_input);
    }
  }
  static constexpr std::string_view kLabelPrefix = "mp1=";
  if (!trimmed.starts_with(kLabelPrefix)) {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_signature_input);
  }
  const std::string_view rest = trimmed.substr(kLabelPrefix.size());
  if (rest.empty() || rest.front() != '(') {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_signature_input);
  }
  const std::size_t close_paren = rest.find(')');
  if (close_paren == std::string_view::npos) {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_signature_input);
  }
  const std::string_view inner = rest.substr(1U, close_paren - 1U);
  const std::string_view params_part = rest.substr(close_paren + 1U);
  if (params_part.find(',') != std::string_view::npos) {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_signature_input);
  }

  std::vector<std::string> components;
  std::size_t pos = 0U;
  while (pos < inner.size()) {
    while (pos < inner.size() && inner[pos] == ' ') {
      ++pos;
    }
    if (pos >= inner.size()) {
      break;
    }
    const std::size_t end = inner.find(' ', pos);
    const std::string_view tok = (end == std::string_view::npos)
                                     ? inner.substr(pos)
                                     : inner.substr(pos, end - pos);
    if (tok.size() < 2U || tok.front() != '"' || tok.back() != '"') {
      return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                        MpError::rfc9421_invalid_signature_input);
    }
    const std::string_view unquoted = tok.substr(1U, tok.size() - 2U);
    if (unquoted.empty() || unquoted.find('"') != std::string_view::npos ||
        unquoted.find('\\') != std::string_view::npos) {
      return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                        MpError::rfc9421_invalid_signature_input);
    }
    components.emplace_back(unquoted);
    if (end == std::string_view::npos) {
      break;
    }
    pos = end + 1U;
  }
  if (components.empty()) {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_covered_components);
  }

  if (params_part.empty() || params_part.front() != ';') {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_signature_input);
  }

  std::optional<std::int64_t> created;
  std::optional<std::int64_t> expires;
  std::optional<std::string> nonce;
  std::optional<std::string> keyid_raw;
  std::optional<std::string> alg;
  std::optional<std::string> tag;
  std::vector<std::string_view> param_order;
  param_order.reserve(6U);

  std::size_t ppos = 1U;
  while (ppos <= params_part.size()) {
    const std::size_t semi = params_part.find(';', ppos);
    std::string_view param = (semi == std::string_view::npos)
                                 ? params_part.substr(ppos)
                                 : params_part.substr(ppos, semi - ppos);
    while (!param.empty() && param.front() == ' ') {
      param.remove_prefix(1U);
    }
    const std::size_t eq = param.find('=');
    if (eq == std::string_view::npos) {
      return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                        MpError::rfc9421_invalid_signature_input);
    }
    const std::string_view k = param.substr(0U, eq);
    const std::string_view v = param.substr(eq + 1U);
    if (k == "created") {
      if (created.has_value()) {
        return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                          MpError::rfc9421_invalid_signature_input);
      }
      const auto parsed_v = parse_sf_int(v);
      if (!parsed_v.has_value()) {
        return Result<ParsedSignatureInput>::failure(parsed_v.error());
      }
      created = parsed_v.value();
      param_order.push_back("created");
    } else if (k == "expires") {
      if (expires.has_value()) {
        return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                          MpError::rfc9421_invalid_signature_input);
      }
      const auto parsed_v = parse_sf_int(v);
      if (!parsed_v.has_value()) {
        return Result<ParsedSignatureInput>::failure(parsed_v.error());
      }
      expires = parsed_v.value();
      param_order.push_back("expires");
    } else if (k == "nonce") {
      if (nonce.has_value()) {
        return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                          MpError::rfc9421_invalid_signature_input);
      }
      const auto parsed_v = parse_sf_string(v);
      if (!parsed_v.has_value()) {
        return Result<ParsedSignatureInput>::failure(parsed_v.error());
      }
      nonce = parsed_v.value();
      param_order.push_back("nonce");
    } else if (k == "keyid") {
      if (keyid_raw.has_value()) {
        return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                          MpError::rfc9421_invalid_signature_input);
      }
      const auto parsed_v = parse_sf_string(v);
      if (!parsed_v.has_value()) {
        return Result<ParsedSignatureInput>::failure(parsed_v.error());
      }
      keyid_raw = parsed_v.value();
      param_order.push_back("keyid");
    } else if (k == "alg") {
      if (alg.has_value()) {
        return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                          MpError::rfc9421_invalid_signature_input);
      }
      const auto parsed_v = parse_sf_string(v);
      if (!parsed_v.has_value()) {
        return Result<ParsedSignatureInput>::failure(parsed_v.error());
      }
      alg = parsed_v.value();
      param_order.push_back("alg");
    } else if (k == "tag") {
      if (tag.has_value()) {
        return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                          MpError::rfc9421_invalid_signature_input);
      }
      const auto parsed_v = parse_sf_string(v);
      if (!parsed_v.has_value()) {
        return Result<ParsedSignatureInput>::failure(parsed_v.error());
      }
      tag = parsed_v.value();
      param_order.push_back("tag");
    } else {
      return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                        MpError::rfc9421_invalid_signature_input);
    }

    if (semi == std::string_view::npos) {
      break;
    }
    ppos = semi + 1U;
  }

  if (!alg.has_value() || *alg != "ed25519") {
    return fail<ParsedSignatureInput>(ErrorCode::unsupported,
                                      MpError::rfc9421_invalid_algorithm);
  }
  if (!tag.has_value() || *tag != "mp1") {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt, MpError::rfc9421_invalid_tag);
  }
  if (!created.has_value() || !expires.has_value()) {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_signature_input);
  }
  if (!nonce.has_value()) {
    return fail<ParsedSignatureInput>(ErrorCode::corrupt,
                                      MpError::rfc9421_invalid_nonce);
  }
  if (const auto ok = validate_nonce(*nonce); !ok.has_value()) {
    return Result<ParsedSignatureInput>::failure(ok.error());
  }
  if (!keyid_raw.has_value()) {
    return fail<ParsedSignatureInput>(ErrorCode::invalid_identity,
                                      MpError::rfc9421_invalid_key_id);
  }
  const auto keyid = parse_key_id(*keyid_raw);
  if (!keyid.has_value()) {
    return Result<ParsedSignatureInput>::failure(keyid.error());
  }

  std::string canonical_params;
  canonical_params.reserve(rest.size());
  canonical_params.push_back('(');
  for (std::size_t idx = 0U; idx < components.size(); ++idx) {
    if (idx > 0U) {
      canonical_params.push_back(' ');
    }
    canonical_params.push_back('"');
    canonical_params.append(components[idx]);
    canonical_params.push_back('"');
  }
  canonical_params.push_back(')');
  for (const std::string_view k : param_order) {
    canonical_params.push_back(';');
    canonical_params.append(k);
    canonical_params.push_back('=');
    if (k == "created") {
      canonical_params.append(std::to_string(*created));
    } else if (k == "expires") {
      canonical_params.append(std::to_string(*expires));
    } else if (k == "nonce") {
      canonical_params.push_back('"');
      canonical_params.append(*nonce);
      canonical_params.push_back('"');
    } else if (k == "keyid") {
      canonical_params.push_back('"');
      canonical_params.append(*keyid_raw);
      canonical_params.push_back('"');
    } else if (k == "alg") {
      canonical_params.append("\"ed25519\"");
    } else if (k == "tag") {
      canonical_params.append("\"mp1\"");
    }
  }

  return Result<ParsedSignatureInput>::success(ParsedSignatureInput{
      std::move(components),
      std::move(canonical_params),
      *created,
      *expires,
      std::move(*nonce),
      std::move(*keyid_raw),
      keyid.value(),
  });
}

Result<Ed25519Sig> parse_signature_header(std::string_view header) {
  const std::string_view trimmed = trim_http_ows(header);
  static constexpr std::string_view kPrefix = "mp1=:";
  if (!trimmed.starts_with(kPrefix) || trimmed.size() <= kPrefix.size() + 1U ||
      trimmed.back() != ':') {
    return fail<Ed25519Sig>(ErrorCode::corrupt,
                            MpError::rfc9421_invalid_signature_header);
  }
  const std::string_view b64 =
      trimmed.substr(kPrefix.size(), trimmed.size() - kPrefix.size() - 1U);
  if (b64.find(':') != std::string_view::npos ||
      b64.find(',') != std::string_view::npos) {
    return fail<Ed25519Sig>(ErrorCode::corrupt,
                            MpError::rfc9421_invalid_signature_header);
  }
  const auto decoded = base64_std_decode(b64);
  if (!decoded.has_value() || decoded->size() != 64U) {
    return fail<Ed25519Sig>(ErrorCode::corrupt,
                            MpError::rfc9421_invalid_signature_header);
  }
  Ed25519Sig sig{};
  std::memcpy(sig.data(), decoded->data(), sig.size());
  return Result<Ed25519Sig>::success(sig);
}

Result<std::vector<std::uint8_t>>
build_signature_base(const Rfc9421Request &request,
                     const ParsedSignatureInput &parsed) {
  static constexpr std::array<std::string_view, 6> kBodyComponents = {
      "@method", "@authority", "@path", "@query", "content-type", "content-digest",
  };
  static constexpr std::array<std::string_view, 4> kGetComponents = {
      "@method",
      "@authority",
      "@path",
      "@query",
  };

  const std::span<const std::string_view> expected =
      method_requires_body_headers(request.method)
          ? std::span<const std::string_view>{kBodyComponents}
          : std::span<const std::string_view>{kGetComponents};

  if (parsed.components.size() != expected.size()) {
    return fail<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                           MpError::rfc9421_invalid_covered_components);
  }
  for (std::size_t i = 0U; i < expected.size(); ++i) {
    if (parsed.components[i] != expected[i]) {
      return fail<std::vector<std::uint8_t>>(
          ErrorCode::corrupt, MpError::rfc9421_invalid_covered_components);
    }
  }

  std::string base;
  base.reserve(256U);
  base.append("\"@method\": ");
  base.append(http_method_name(request.method));
  base.push_back('\n');

  base.append("\"@authority\": ");
  base.append(request.authority);
  base.push_back('\n');

  base.append("\"@path\": ");
  base.append(request.path);
  base.push_back('\n');

  base.append("\"@query\": ");
  base.append(request.query);
  base.push_back('\n');

  if (method_requires_body_headers(request.method)) {
    if (!request.content_type.has_value()) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                             MpError::rfc9421_missing_content_type);
    }
    if (!request.content_digest.has_value()) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                             MpError::rfc9421_invalid_content_digest);
    }
    base.append("\"content-type\": ");
    base.append(trim_ascii_ws(*request.content_type));
    base.push_back('\n');

    base.append("\"content-digest\": ");
    base.append(trim_ascii_ws(*request.content_digest));
    base.push_back('\n');
  }

  base.append("\"@signature-params\": ");
  base.append(parsed.canonical_params);

  std::vector<std::uint8_t> out;
  out.reserve(base.size());
  append_string_bytes(out, base);
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

Result<SignedRfc9421Headers> sign_rfc9421_request(const Ed25519SigningKey &signing_key,
                                                  const Rfc9421SignRequest &request) {
  if (request.authority.empty() || request.authority.size() > 256U) {
    return fail<SignedRfc9421Headers>(ErrorCode::invalid_identity,
                                      MpError::rfc9421_invalid_authority);
  }
  for (const char ch : request.authority) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (byte < 0x21U || byte > 0x7eU) {
      return fail<SignedRfc9421Headers>(ErrorCode::invalid_identity,
                                        MpError::rfc9421_invalid_authority);
    }
  }
  if (const auto ok =
          validate_path_and_query({request.method, request.path, request.query});
      !ok.has_value()) {
    return Result<SignedRfc9421Headers>::failure(ok.error());
  }
  if (!method_requires_body_headers(request.method) && !request.body.empty()) {
    return fail<SignedRfc9421Headers>(ErrorCode::invalid_range,
                                      MpError::rfc9421_unexpected_body_on_get);
  }
  if (request.created < 0) {
    return fail<SignedRfc9421Headers>(ErrorCode::invalid_range,
                                      MpError::rfc9421_invalid_window);
  }
  const auto window = checked_sub_i64(request.expires, request.created);
  if (!window.has_value() || *window <= 0 || *window > kMaxSignatureWindowSecs) {
    return fail<SignedRfc9421Headers>(ErrorCode::invalid_range,
                                      MpError::rfc9421_invalid_window);
  }
  if (const auto *reg = std::get_if<RegistrationKeyId>(&request.keyid)) {
    const auto expected_reg = registration_key_id_for_pubkey(signing_key.public_key());
    if (!expected_reg.has_value()) {
      return Result<SignedRfc9421Headers>::failure(expected_reg.error());
    }
    if (!constant_time_equal({expected_reg.value().root_pubkey_sha256_prefix,
                              reg->root_pubkey_sha256_prefix})) {
      return fail<SignedRfc9421Headers>(ErrorCode::invalid_identity,
                                        MpError::rfc9421_invalid_key_id);
    }
  }

  std::string nonce;
  if (request.nonce.empty()) {
    const auto generated = generate_nonce_b64url();
    if (!generated.has_value()) {
      return Result<SignedRfc9421Headers>::failure(generated.error());
    }
    nonce = generated.value();
  } else {
    if (const auto ok = validate_nonce(request.nonce); !ok.has_value()) {
      return Result<SignedRfc9421Headers>::failure(ok.error());
    }
    nonce = std::string{request.nonce};
  }

  std::optional<std::string> content_digest;
  std::optional<std::string_view> content_type_trimmed;
  if (method_requires_body_headers(request.method)) {
    if (!request.content_type.has_value()) {
      return fail<SignedRfc9421Headers>(ErrorCode::corrupt,
                                        MpError::rfc9421_missing_content_type);
    }
    const std::string_view ct = trim_ascii_ws(*request.content_type);
    if (ct.empty() || ct.find('\r') != std::string_view::npos ||
        ct.find('\n') != std::string_view::npos ||
        !is_application_json_content_type(ct)) {
      return fail<SignedRfc9421Headers>(ErrorCode::corrupt,
                                        MpError::rfc9421_missing_content_type);
    }
    content_type_trimmed = ct;
    const auto cd = compute_content_digest(request.body);
    if (!cd.has_value()) {
      return Result<SignedRfc9421Headers>::failure(cd.error());
    }
    content_digest = cd.value();
  }

  const std::string keyid_str = format_key_id(request.keyid);
  const std::string_view comps =
      method_requires_body_headers(request.method)
          ? "(\"@method\" \"@authority\" \"@path\" \"@query\" \"content-type\" "
            "\"content-digest\")"
          : "(\"@method\" \"@authority\" \"@path\" \"@query\")";
  std::string sig_input = "mp1=";
  sig_input.append(comps);
  sig_input.append(";created=");
  sig_input.append(std::to_string(request.created));
  sig_input.append(";expires=");
  sig_input.append(std::to_string(request.expires));
  sig_input.append(";nonce=\"");
  sig_input.append(nonce);
  sig_input.append("\";keyid=\"");
  sig_input.append(keyid_str);
  sig_input.append("\";alg=\"ed25519\";tag=\"mp1\"");

  const auto parsed = parse_signature_input(sig_input);
  if (!parsed.has_value()) {
    return Result<SignedRfc9421Headers>::failure(parsed.error());
  }
  const Rfc9421Request base_req{
      request.method,
      request.authority,
      request.path,
      request.query,
      content_type_trimmed,
      content_digest.has_value() ? std::optional<std::string_view>{*content_digest}
                                 : std::nullopt,
      false,
      request.body,
      sig_input,
      {},
  };
  const auto sig_base = build_signature_base(base_req, parsed.value());
  if (!sig_base.has_value()) {
    return Result<SignedRfc9421Headers>::failure(sig_base.error());
  }
  const auto sig = signing_key.sign(sig_base.value());
  if (!sig.has_value()) {
    return Result<SignedRfc9421Headers>::failure(sig.error());
  }
  std::string sig_header = "mp1=:" + base64_std_encode(sig.value()) + ":";
  return Result<SignedRfc9421Headers>::success(SignedRfc9421Headers{
      std::move(sig_input),
      std::move(sig_header),
      std::move(content_digest),
      std::move(nonce),
      sig_base.value(),
  });
}

Result<VerifiedSignature> verify_rfc9421_request(const Rfc9421VerifyInput &input) {
  const Rfc9421Request &req = input.request;
  if (req.authority != input.expected_authority) {
    return fail<VerifiedSignature>(ErrorCode::provider_auth,
                                   MpError::rfc9421_invalid_authority);
  }
  if (req.has_content_encoding) {
    return fail<VerifiedSignature>(ErrorCode::unsupported,
                                   MpError::rfc9421_content_encoding_forbidden);
  }
  if (const auto ok = validate_path_and_query({req.method, req.path, req.query});
      !ok.has_value()) {
    return Result<VerifiedSignature>::failure(ok.error());
  }
  if (!method_requires_body_headers(req.method) && !req.body.empty()) {
    return fail<VerifiedSignature>(ErrorCode::corrupt,
                                   MpError::rfc9421_unexpected_body_on_get);
  }

  const auto parsed = parse_signature_input(req.signature_input);
  if (!parsed.has_value()) {
    return Result<VerifiedSignature>::failure(parsed.error());
  }

  if (const auto *reg = std::get_if<RegistrationKeyId>(&parsed.value().keyid)) {
    const auto digest = sha256(input.pubkey);
    if (!digest.has_value()) {
      return Result<VerifiedSignature>::failure(digest.error());
    }
    const std::span<const std::uint8_t> prefix{digest.value().data(), 16U};
    if (!constant_time_equal({prefix, reg->root_pubkey_sha256_prefix})) {
      return fail<VerifiedSignature>(ErrorCode::provider_auth,
                                     MpError::rfc9421_invalid_key_id);
    }
  }

  const auto window = checked_sub_i64(parsed.value().expires, parsed.value().created);
  if (!window.has_value() || *window <= 0 || *window > kMaxSignatureWindowSecs) {
    return fail<VerifiedSignature>(ErrorCode::provider_auth,
                                   MpError::rfc9421_invalid_window);
  }

  if (method_requires_body_headers(req.method)) {
    if (!req.content_type.has_value()) {
      return fail<VerifiedSignature>(ErrorCode::corrupt,
                                     MpError::rfc9421_missing_content_type);
    }
    const std::string_view ct = trim_ascii_ws(*req.content_type);
    if (ct.empty() || ct.find('\r') != std::string_view::npos ||
        ct.find('\n') != std::string_view::npos ||
        !is_application_json_content_type(ct)) {
      return fail<VerifiedSignature>(ErrorCode::corrupt,
                                     MpError::rfc9421_missing_content_type);
    }
    const auto expected_cd = compute_content_digest(req.body);
    if (!expected_cd.has_value()) {
      return Result<VerifiedSignature>::failure(expected_cd.error());
    }
    if (!req.content_digest.has_value()) {
      return fail<VerifiedSignature>(ErrorCode::corrupt,
                                     MpError::rfc9421_invalid_content_digest);
    }
    const std::string_view got_cd = trim_ascii_ws(*req.content_digest);
    const std::span<const std::uint8_t> expected_bytes{
        reinterpret_cast<const std::uint8_t *>(expected_cd.value().data()),
        expected_cd.value().size()};
    const std::span<const std::uint8_t> got_bytes{
        reinterpret_cast<const std::uint8_t *>(got_cd.data()), got_cd.size()};
    if (!constant_time_equal({expected_bytes, got_bytes})) {
      return fail<VerifiedSignature>(ErrorCode::provider_auth,
                                     MpError::rfc9421_content_digest_mismatch);
    }
  }

  const auto sig_bytes = parse_signature_header(req.signature);
  if (!sig_bytes.has_value()) {
    return Result<VerifiedSignature>::failure(sig_bytes.error());
  }
  const auto sig_base = build_signature_base(req, parsed.value());
  if (!sig_base.has_value()) {
    return Result<VerifiedSignature>::failure(sig_base.error());
  }
  if (const auto sig_ok = verify_ed25519_strict(
          Ed25519VerifyInput{input.pubkey, sig_base.value(), sig_bytes.value()});
      !sig_ok.has_value()) {
    return Result<VerifiedSignature>::failure(sig_ok.error());
  }

  // Enforce clock_skew / expired strictly AFTER Ed25519 verification so unauthenticated
  // probes with forged signatures never receive a clock-skew / existence oracle.
  const std::int64_t max_created = saturating_add_i64(input.now_s, kMaxClockSkewSecs);
  if (parsed.value().created > max_created) {
    return fail<VerifiedSignature>(ErrorCode::clock_regressed,
                                   MpError::rfc9421_clock_skew);
  }
  if (input.now_s > parsed.value().expires) {
    if (parsed.value().created < saturating_sub_i64(input.now_s, kMaxClockSkewSecs)) {
      return fail<VerifiedSignature>(ErrorCode::clock_regressed,
                                     MpError::rfc9421_clock_skew);
    }
    return fail<VerifiedSignature>(ErrorCode::provider_auth, MpError::rfc9421_expired);
  }

  const std::int64_t retain_until_s =
      std::max(parsed.value().expires,
               saturating_add_i64(parsed.value().created, kMaxClockSkewSecs));
  const std::int64_t retain_until_ms = saturating_add_i64(
      saturating_mul_i64(retain_until_s, 1000), kNonceRetentionSlackMs);

  return Result<VerifiedSignature>::success(VerifiedSignature{
      parsed.value().keyid,
      parsed.value().nonce,
      parsed.value().created,
      parsed.value().expires,
      retain_until_ms,
  });
}

// ---------------------------------------------------------------------------
// 6. RFC 8949 Deterministic CBOR + RFC 9052 COSE_Sign1 (-19) + Device CWT
// ---------------------------------------------------------------------------

Result<std::vector<std::uint8_t>>
encode_device_cwt(const Ed25519SigningKey &root_signing_key,
                  const DeviceCwtMintRequest &request) {
  const Ed25519PubKey &root_pubkey = root_signing_key.public_key();
  if (const auto ok = validate_ed25519_pubkey_strict(root_pubkey); !ok.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(ok.error());
  }
  if (const auto ok = validate_ed25519_pubkey_strict(request.device_pubkey);
      !ok.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(ok.error());
  }
  if (const auto ok = validate_cwt_ttl({request.issued_at_s, request.expires_at_s});
      !ok.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(ok.error());
  }

  const auto root_hash = sha256(root_pubkey);
  if (!root_hash.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(root_hash.error());
  }
  const std::string iss = hex_lower(root_hash.value());

  // Deterministic CBOR encoding of CWT claims map:
  // { 1 (iss): tstr, 4 (exp): int, 6 (iat): int,
  //   8 (cnf): { 1 (COSE_Key): { 1 (kty): 1, 3 (alg): -19, -1 (crv): 6, -2 (x):
  //   bstr(32) } } }
  // Keys in both maps are in RFC 8949 section 4.2.1 bytewise deterministic order AND
  // bit-identical to mp-protocol Rust ciborium encoding.
  std::vector<std::uint8_t> payload_bytes;
  payload_bytes.reserve(140U);
  cbor_append_head(payload_bytes, CborMajor::map, 4U); // 4-entry claims map
  cbor_append_int(payload_bytes, kCwtClaimIss);
  cbor_append_tstr(payload_bytes, iss);
  cbor_append_int(payload_bytes, kCwtClaimExp);
  cbor_append_int(payload_bytes, request.expires_at_s);
  cbor_append_int(payload_bytes, kCwtClaimIat);
  cbor_append_int(payload_bytes, request.issued_at_s);
  cbor_append_int(payload_bytes, kCwtClaimCnf);
  cbor_append_head(payload_bytes, CborMajor::map, 1U); // cnf map { 1: COSE_Key }
  cbor_append_int(payload_bytes, kCnfCoseKey);
  cbor_append_head(payload_bytes, CborMajor::map, 4U); // COSE_Key map (4 entries)
  cbor_append_int(payload_bytes, kCoseKeyKty);
  cbor_append_int(payload_bytes, kKtyOkp);
  cbor_append_int(payload_bytes, kCoseKeyAlg);
  cbor_append_int(payload_bytes, kAlgEd25519);
  cbor_append_int(payload_bytes, kCoseKeyCrv);
  cbor_append_int(payload_bytes, kCrvEd25519);
  cbor_append_int(payload_bytes, kCoseKeyX);
  cbor_append_bstr(payload_bytes, request.device_pubkey);

  const std::vector<std::uint8_t> to_be_signed =
      build_cose_sig_structure({kProtectedHeaderEd25519, payload_bytes});
  const auto sig = root_signing_key.sign(to_be_signed);
  if (!sig.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(sig.error());
  }

  std::vector<std::uint8_t> out;
  out.reserve(kMaxCwtBytes);
  cbor_append_head(out, CborMajor::tag, kCoseSign1Tag); // Tag 18 (0xd2)
  cbor_append_head(out, CborMajor::array, 4U);          // 4-element array (0x84)
  cbor_append_bstr(out, kProtectedHeaderEd25519);
  cbor_append_head(out, CborMajor::map, 0U); // empty unprotected map (0xa0)
  cbor_append_bstr(out, payload_bytes);
  cbor_append_bstr(out, sig.value());

  if (out.size() > kMaxCwtBytes) {
    return fail<std::vector<std::uint8_t>>(ErrorCode::capacity, MpError::cwt_too_large);
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

Result<CwtClaims> verify_device_cwt(const DeviceCwtVerifyRequest &request) {
  const auto bytes = request.cwt_bytes;
  if (bytes.empty() || bytes.size() > kMaxCwtBytes) {
    return fail<CwtClaims>(ErrorCode::capacity, MpError::cwt_too_large);
  }
  if (const auto ok = validate_ed25519_pubkey_strict(request.expected_root_pubkey);
      !ok.has_value()) {
    return Result<CwtClaims>::failure(ok.error());
  }

  // Strictly require Tag 18 + definite 4-elem array + exact protected header h'A10132'
  // ({1: -19}) + empty definite unprotected map {}.
  if (bytes.size() <= kCanonicalSign1Prefix.size()) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_envelope_shape);
  }
  if (std::memcmp(bytes.data(), kCanonicalSign1Prefix.data(),
                  kCanonicalSign1Prefix.size()) != 0) {
    // Distinguish protected header / unprotected header errors when Tag 18 + array(4)
    // is present so diagnostics remain sharp.
    if (bytes.size() >= 2U && bytes[0] == 0xd2U && bytes[1] == 0x84U) {
      StrictCborReader diag_reader{bytes.subspan(2U)};
      const auto prot = diag_reader.read_bstr(MpError::cwt_invalid_envelope_shape);
      if (prot.has_value()) {
        if (prot.value().size() != kProtectedHeaderEd25519.size() ||
            std::memcmp(prot.value().data(), kProtectedHeaderEd25519.data(),
                        kProtectedHeaderEd25519.size()) != 0) {
          return fail<CwtClaims>(ErrorCode::corrupt,
                                 MpError::cwt_invalid_protected_header);
        }
        const auto unprot = diag_reader.read_head(MpError::cwt_invalid_envelope_shape);
        if (unprot.has_value() && unprot.value().major == 5U &&
            unprot.value().arg > 0U) {
          return fail<CwtClaims>(ErrorCode::corrupt,
                                 MpError::cwt_non_empty_unprotected_header);
        }
      }
    }
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_envelope_shape);
  }

  const std::uint8_t payload_hdr = bytes[kCanonicalSign1Prefix.size()];
  if (payload_hdr == 0x5fU || (payload_hdr & 0xe0U) != 0x40U) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_envelope_shape);
  }

  StrictCborReader outer{bytes.subspan(kCanonicalSign1Prefix.size())};
  const auto payload_bytes = outer.read_bstr(MpError::cwt_invalid_cbor);
  if (!payload_bytes.has_value()) {
    return Result<CwtClaims>::failure(payload_bytes.error());
  }
  const auto sig_bytes = outer.read_bstr(MpError::cwt_invalid_cbor);
  if (!sig_bytes.has_value()) {
    return Result<CwtClaims>::failure(sig_bytes.error());
  }
  if (!outer.at_end()) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_cbor);
  }
  if (sig_bytes.value().size() != 64U) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_signature_length);
  }
  Ed25519Sig sig{};
  std::memcpy(sig.data(), sig_bytes.value().data(), sig.size());

  // Verify Ed25519 signature strictly over exact received protected & payload bytes.
  const std::vector<std::uint8_t> to_be_signed =
      build_cose_sig_structure({kProtectedHeaderEd25519, payload_bytes.value()});
  if (const auto sig_ok = verify_ed25519_strict(
          Ed25519VerifyInput{request.expected_root_pubkey, to_be_signed, sig});
      !sig_ok.has_value()) {
    return Result<CwtClaims>::failure(sig_ok.error());
  }

  StrictCborReader payload_reader{payload_bytes.value()};
  const auto map_head = payload_reader.read_head(MpError::cwt_invalid_claims);
  if (!map_head.has_value()) {
    return Result<CwtClaims>::failure(map_head.error());
  }
  if (map_head.value().major != 5U || map_head.value().arg > 16U) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }

  std::optional<std::string> iss;
  std::optional<std::int64_t> exp;
  std::optional<std::int64_t> iat;
  std::optional<Ed25519PubKey> device_pubkey;

  for (std::uint64_t i = 0U; i < map_head.value().arg; ++i) {
    const auto key = payload_reader.read_i64(MpError::cwt_invalid_claims);
    if (!key.has_value()) {
      return Result<CwtClaims>::failure(key.error());
    }
    switch (key.value()) {
    case kCwtClaimIss: {
      if (iss.has_value()) {
        return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = payload_reader.read_tstr(MpError::cwt_invalid_claims);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      iss = val.value();
      break;
    }
    case kCwtClaimExp: {
      if (exp.has_value()) {
        return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = payload_reader.read_i64(MpError::cwt_invalid_claims);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      exp = val.value();
      break;
    }
    case kCwtClaimIat: {
      if (iat.has_value()) {
        return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = payload_reader.read_i64(MpError::cwt_invalid_claims);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      iat = val.value();
      break;
    }
    case kCwtClaimCnf: {
      if (device_pubkey.has_value()) {
        return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
      }
      const auto val = parse_cnf_ed25519(payload_reader);
      if (!val.has_value()) {
        return Result<CwtClaims>::failure(val.error());
      }
      device_pubkey = val.value();
      break;
    }
    default:
      return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
    }
  }
  if (!payload_reader.at_end()) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }
  if (!iss.has_value() || !exp.has_value() || !iat.has_value() ||
      !device_pubkey.has_value()) {
    return fail<CwtClaims>(ErrorCode::corrupt, MpError::cwt_invalid_claims);
  }

  const auto root_hash = sha256(request.expected_root_pubkey);
  if (!root_hash.has_value()) {
    return Result<CwtClaims>::failure(root_hash.error());
  }
  const std::string expected_iss = hex_lower(root_hash.value());
  const std::span<const std::uint8_t> iss_bytes{
      reinterpret_cast<const std::uint8_t *>(iss->data()), iss->size()};
  const std::span<const std::uint8_t> expected_iss_bytes{
      reinterpret_cast<const std::uint8_t *>(expected_iss.data()), expected_iss.size()};
  if (!constant_time_equal({iss_bytes, expected_iss_bytes})) {
    return fail<CwtClaims>(ErrorCode::provider_auth, MpError::cwt_issuer_mismatch);
  }
  if (const auto dev_ok = validate_ed25519_pubkey_strict(*device_pubkey);
      !dev_ok.has_value()) {
    return Result<CwtClaims>::failure(dev_ok.error());
  }
  if (request.expected_device_pubkey.has_value() &&
      !constant_time_equal({*device_pubkey, *request.expected_device_pubkey})) {
    return fail<CwtClaims>(ErrorCode::provider_auth, MpError::cwt_device_key_mismatch);
  }

  if (const auto ttl_ok = validate_cwt_ttl({*iat, *exp}); !ttl_ok.has_value()) {
    return Result<CwtClaims>::failure(ttl_ok.error());
  }
  const std::int64_t max_iat = saturating_add_i64(request.now_s, kMaxCwtIatSkewSecs);
  if (*iat > max_iat) {
    return fail<CwtClaims>(ErrorCode::clock_regressed, MpError::cwt_future_issued_at);
  }
  if (request.now_s >= *exp) {
    return fail<CwtClaims>(ErrorCode::provider_auth, MpError::cwt_expired);
  }

  return Result<CwtClaims>::success(
      CwtClaims{std::move(*iss), *iat, *exp, *device_pubkey});
}

Result<CwtClaims> verify_party_member_cwt(const PartyMemberRecord &member,
                                          std::int64_t now_s) {
  return verify_device_cwt(DeviceCwtVerifyRequest{
      member.device_cwt,
      member.root_pubkey,
      member.device_pubkey,
      now_s,
  });
}

} // namespace blackbird::mp
