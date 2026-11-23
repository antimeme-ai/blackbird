#include "blackbird/lan_party_protocol.hpp"

#include "blackbird/json.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <cerrno>
#include <charconv>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#ifdef __APPLE__
#include <dlfcn.h>
#endif

#include <openssl/crypto.h>

extern char **environ;

namespace blackbird::lan {

namespace {

std::atomic<std::uint64_t> g_lan_tmp_seq{0U};

template <typename T> Result<T> fail(ErrorCode code, LanError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_void(ErrorCode code, LanError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

template <std::size_t N> class CleanseArrayGuard {
public:
  explicit CleanseArrayGuard(std::array<std::uint8_t, N> &buf) noexcept : buf_(buf) {}
  CleanseArrayGuard(const CleanseArrayGuard &) = delete;
  CleanseArrayGuard &operator=(const CleanseArrayGuard &) = delete;
  ~CleanseArrayGuard() { OPENSSL_cleanse(buf_.data(), buf_.size()); }

private:
  std::array<std::uint8_t, N> &buf_;
};

template <std::size_t N> class CleanseU32ArrayGuard {
public:
  explicit CleanseU32ArrayGuard(std::array<std::uint32_t, N> &buf) noexcept
      : buf_(buf) {}
  CleanseU32ArrayGuard(const CleanseU32ArrayGuard &) = delete;
  CleanseU32ArrayGuard &operator=(const CleanseU32ArrayGuard &) = delete;
  ~CleanseU32ArrayGuard() {
    OPENSSL_cleanse(buf_.data(), buf_.size() * sizeof(std::uint32_t));
  }

private:
  std::array<std::uint32_t, N> &buf_;
};

class CleanseStringGuard {
public:
  explicit CleanseStringGuard(std::string &buf) noexcept : buf_(buf) {}
  CleanseStringGuard(const CleanseStringGuard &) = delete;
  CleanseStringGuard &operator=(const CleanseStringGuard &) = delete;
  ~CleanseStringGuard() {
    if (!buf_.empty()) {
      OPENSSL_cleanse(buf_.data(), buf_.size());
    }
  }

private:
  std::string &buf_;
};

class CleanseVectorGuard {
public:
  explicit CleanseVectorGuard(std::vector<std::uint8_t> &buf) noexcept : buf_(buf) {}
  CleanseVectorGuard(const CleanseVectorGuard &) = delete;
  CleanseVectorGuard &operator=(const CleanseVectorGuard &) = delete;
  ~CleanseVectorGuard() {
    if (!buf_.empty()) {
      OPENSSL_cleanse(buf_.data(), buf_.size());
    }
  }

private:
  std::vector<std::uint8_t> &buf_;
};

class ScopedFd {
public:
  ScopedFd() noexcept = default;
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
  void reset(int next = -1) noexcept {
    if (fd_ >= 0) {
      (void)::close(fd_);
    }
    fd_ = next;
  }

private:
  int fd_ = -1;
};

// ---------------------------------------------------------------------------
// Owned C++23 BLAKE3 implementation (spec-exact single- & multi-chunk)
// ---------------------------------------------------------------------------

constexpr std::size_t kBlake3BlockLen = 64U;
constexpr std::size_t kBlake3ChunkLen = 1024U;
constexpr std::size_t kBlake3MaxStackDepth = 54U;

constexpr std::uint8_t kBlake3ChunkStart = 1U << 0U;
constexpr std::uint8_t kBlake3ChunkEnd = 1U << 1U;
constexpr std::uint8_t kBlake3Parent = 1U << 2U;
constexpr std::uint8_t kBlake3Root = 1U << 3U;
constexpr std::uint8_t kBlake3KeyedHash = 1U << 4U;
constexpr std::uint8_t kBlake3DeriveKeyContext = 1U << 5U;
constexpr std::uint8_t kBlake3DeriveKeyMaterial = 1U << 6U;

using CvWords = std::array<std::uint32_t, 8>;
using BlockWords = std::array<std::uint32_t, 16>;

inline constexpr CvWords kBlake3Iv = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U,
};

inline constexpr std::array<std::array<std::uint8_t, 16>, 7> kBlake3MsgSchedule = {{
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
}};

constexpr std::uint32_t load_u32_le(std::span<const std::uint8_t, 4> bytes) noexcept {
  return static_cast<std::uint32_t>(bytes[0]) |
         (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) |
         (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

CvWords bytes_to_cv_words(std::span<const std::uint8_t, 32> bytes) noexcept {
  CvWords words{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    words[i] = load_u32_le(bytes.subspan(i * 4U, 4U).first<4>());
  }
  return words;
}

BlockWords bytes_to_block_words(std::span<const std::uint8_t, 64> bytes) noexcept {
  BlockWords words{};
  for (std::size_t i = 0U; i < 16U; ++i) {
    words[i] = load_u32_le(bytes.subspan(i * 4U, 4U).first<4>());
  }
  return words;
}

Blake3Digest cv_words_to_bytes(const CvWords &words) noexcept {
  Blake3Digest out{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    const std::uint32_t w = words[i];
    out[(i * 4U) + 0U] = static_cast<std::uint8_t>(w & 0xffU);
    out[(i * 4U) + 1U] = static_cast<std::uint8_t>((w >> 8U) & 0xffU);
    out[(i * 4U) + 2U] = static_cast<std::uint8_t>((w >> 16U) & 0xffU);
    out[(i * 4U) + 3U] = static_cast<std::uint8_t>((w >> 24U) & 0xffU);
  }
  return out;
}

struct QuarterRoundIndices {
  std::size_t a;
  std::size_t b;
  std::size_t c;
  std::size_t d;
};

struct QuarterRoundInputs {
  std::uint32_t mx;
  std::uint32_t my;
};

constexpr void blake3_g(BlockWords &state, QuarterRoundIndices idx,
                        QuarterRoundInputs in) noexcept {
  state[idx.a] = state[idx.a] + state[idx.b] + in.mx;
  state[idx.d] = std::rotr(state[idx.d] ^ state[idx.a], 16);
  state[idx.c] = state[idx.c] + state[idx.d];
  state[idx.b] = std::rotr(state[idx.b] ^ state[idx.c], 12);
  state[idx.a] = state[idx.a] + state[idx.b] + in.my;
  state[idx.d] = std::rotr(state[idx.d] ^ state[idx.a], 8);
  state[idx.c] = state[idx.c] + state[idx.d];
  state[idx.b] = std::rotr(state[idx.b] ^ state[idx.c], 7);
}

struct CompressParams {
  std::uint64_t counter = 0U;
  std::uint32_t block_len = 0U;
  std::uint8_t flags = 0U;
};

BlockWords blake3_compress(const CvWords &cv, const BlockWords &m,
                           CompressParams params) noexcept {
  BlockWords state = {
      cv[0],
      cv[1],
      cv[2],
      cv[3],
      cv[4],
      cv[5],
      cv[6],
      cv[7],
      kBlake3Iv[0],
      kBlake3Iv[1],
      kBlake3Iv[2],
      kBlake3Iv[3],
      static_cast<std::uint32_t>(params.counter & 0xffffffffU),
      static_cast<std::uint32_t>(params.counter >> 32U),
      params.block_len,
      static_cast<std::uint32_t>(params.flags),
  };

  for (std::size_t round = 0U; round < 7U; ++round) {
    const auto &s = kBlake3MsgSchedule[round];
    // Column step
    blake3_g(state, {0U, 4U, 8U, 12U}, {m[s[0]], m[s[1]]});
    blake3_g(state, {1U, 5U, 9U, 13U}, {m[s[2]], m[s[3]]});
    blake3_g(state, {2U, 6U, 10U, 14U}, {m[s[4]], m[s[5]]});
    blake3_g(state, {3U, 7U, 11U, 15U}, {m[s[6]], m[s[7]]});
    // Diagonal step
    blake3_g(state, {0U, 5U, 10U, 15U}, {m[s[8]], m[s[9]]});
    blake3_g(state, {1U, 6U, 11U, 12U}, {m[s[10]], m[s[11]]});
    blake3_g(state, {2U, 7U, 8U, 13U}, {m[s[12]], m[s[13]]});
    blake3_g(state, {3U, 4U, 9U, 14U}, {m[s[14]], m[s[15]]});
  }

  for (std::size_t i = 0U; i < 8U; ++i) {
    state[i] ^= state[i + 8U];
    state[i + 8U] ^= cv[i];
  }
  return state;
}

CvWords first_8_words(const BlockWords &words) noexcept {
  CvWords out{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    out[i] = words[i];
  }
  return out;
}

struct Blake3Output {
  CvWords input_cv{};
  BlockWords block_words{};
  std::uint64_t counter = 0U;
  std::uint32_t block_len = 0U;
  std::uint8_t flags = 0U;

  CvWords chaining_value() const noexcept {
    BlockWords compressed =
        blake3_compress(input_cv, block_words, {counter, block_len, flags});
    CvWords out = first_8_words(compressed);
    OPENSSL_cleanse(compressed.data(), compressed.size() * sizeof(std::uint32_t));
    return out;
  }

  Blake3Digest root_digest() const noexcept {
    BlockWords compressed = blake3_compress(
        input_cv, block_words,
        {0U, block_len, static_cast<std::uint8_t>(flags | kBlake3Root)});
    CvWords words = first_8_words(compressed);
    Blake3Digest out = cv_words_to_bytes(words);
    OPENSSL_cleanse(compressed.data(), compressed.size() * sizeof(std::uint32_t));
    OPENSSL_cleanse(words.data(), words.size() * sizeof(std::uint32_t));
    return out;
  }

  void cleanse() noexcept {
    OPENSSL_cleanse(input_cv.data(), input_cv.size() * sizeof(std::uint32_t));
    OPENSSL_cleanse(block_words.data(), block_words.size() * sizeof(std::uint32_t));
    counter = 0U;
    block_len = 0U;
    flags = 0U;
  }
};

struct ParentChildren {
  CvWords left{};
  CvWords right{};
};

struct ParentContext {
  CvWords key_words{};
  std::uint8_t flags = 0U;
};

Blake3Output make_parent_output(const ParentChildren &children,
                                const ParentContext &ctx) noexcept {
  BlockWords block_words{};
  for (std::size_t i = 0U; i < 8U; ++i) {
    block_words[i] = children.left[i];
    block_words[i + 8U] = children.right[i];
  }
  return Blake3Output{
      ctx.key_words,
      block_words,
      0U,
      static_cast<std::uint32_t>(kBlake3BlockLen),
      static_cast<std::uint8_t>(kBlake3Parent | ctx.flags),
  };
}

CvWords compute_parent_cv(const ParentChildren &children,
                          const ParentContext &ctx) noexcept {
  Blake3Output out = make_parent_output(children, ctx);
  CvWords cv = out.chaining_value();
  out.cleanse();
  return cv;
}

class Blake3ChunkState {
public:
  struct Init {
    CvWords key_words{};
    std::uint64_t chunk_counter = 0U;
    std::uint8_t flags = 0U;
  };

  explicit Blake3ChunkState(const Init &init) noexcept
      : cv_(init.key_words), chunk_counter_(init.chunk_counter), flags_(init.flags) {}

  ~Blake3ChunkState() { cleanse(); }

  std::size_t len() const noexcept {
    return (static_cast<std::size_t>(blocks_compressed_) * kBlake3BlockLen) +
           static_cast<std::size_t>(block_len_);
  }

  std::uint64_t chunk_counter() const noexcept { return chunk_counter_; }

  void reset(const Init &init) noexcept {
    cleanse();
    cv_ = init.key_words;
    chunk_counter_ = init.chunk_counter;
    flags_ = init.flags;
  }

  void update(std::span<const std::uint8_t> input) noexcept {
    while (!input.empty()) {
      if (block_len_ == kBlake3BlockLen) {
        BlockWords bw = bytes_to_block_words(block_);
        const auto start_flag =
            blocks_compressed_ == 0U ? kBlake3ChunkStart : std::uint8_t{0U};
        BlockWords compressed = blake3_compress(
            cv_, bw,
            {chunk_counter_, static_cast<std::uint32_t>(kBlake3BlockLen),
             static_cast<std::uint8_t>(flags_ | start_flag)});
        cv_ = first_8_words(compressed);
        OPENSSL_cleanse(bw.data(), bw.size() * sizeof(std::uint32_t));
        OPENSSL_cleanse(compressed.data(), compressed.size() * sizeof(std::uint32_t));
        ++blocks_compressed_;
        block_.fill(0U);
        block_len_ = 0U;
      }
      const std::size_t want = kBlake3BlockLen - static_cast<std::size_t>(block_len_);
      const std::size_t take = std::min(want, input.size());
      std::memcpy(block_.data() + block_len_, input.data(), take);
      block_len_ = static_cast<std::uint8_t>(block_len_ + take);
      input = input.subspan(take);
    }
  }

  Blake3Output output() const noexcept {
    std::array<std::uint8_t, kBlake3BlockLen> padded = block_;
    if (block_len_ < kBlake3BlockLen) {
      std::memset(padded.data() + block_len_, 0, kBlake3BlockLen - block_len_);
    }
    BlockWords bw = bytes_to_block_words(padded);
    OPENSSL_cleanse(padded.data(), padded.size());
    const auto start_flag =
        blocks_compressed_ == 0U ? kBlake3ChunkStart : std::uint8_t{0U};
    return Blake3Output{
        cv_,
        bw,
        chunk_counter_,
        static_cast<std::uint32_t>(block_len_),
        static_cast<std::uint8_t>(flags_ | start_flag | kBlake3ChunkEnd),
    };
  }

  void cleanse() noexcept {
    OPENSSL_cleanse(cv_.data(), cv_.size() * sizeof(std::uint32_t));
    OPENSSL_cleanse(block_.data(), block_.size());
    chunk_counter_ = 0U;
    block_len_ = 0U;
    blocks_compressed_ = 0U;
    flags_ = 0U;
  }

private:
  CvWords cv_{};
  std::uint64_t chunk_counter_ = 0U;
  std::array<std::uint8_t, kBlake3BlockLen> block_{};
  std::uint8_t block_len_ = 0U;
  std::uint8_t blocks_compressed_ = 0U;
  std::uint8_t flags_ = 0U;
};

class Blake3Hasher {
public:
  Blake3Hasher(const CvWords &key_words, std::uint8_t flags) noexcept
      : chunk_state_({key_words, 0U, flags}), key_words_(key_words), flags_(flags) {}

  Blake3Hasher(const Blake3Hasher &) = delete;
  Blake3Hasher &operator=(const Blake3Hasher &) = delete;

  ~Blake3Hasher() {
    chunk_state_.cleanse();
    OPENSSL_cleanse(key_words_.data(), key_words_.size() * sizeof(std::uint32_t));
    for (auto &cv : cv_stack_) {
      OPENSSL_cleanse(cv.data(), cv.size() * sizeof(std::uint32_t));
    }
    cv_stack_len_ = 0U;
    flags_ = 0U;
  }

  void update(std::span<const std::uint8_t> input) noexcept {
    while (!input.empty()) {
      if (chunk_state_.len() == kBlake3ChunkLen) {
        Blake3Output chunk_out = chunk_state_.output();
        CvWords chunk_cv = chunk_out.chaining_value();
        chunk_out.cleanse();
        const std::uint64_t total_chunks = chunk_state_.chunk_counter() + 1U;
        add_chunk_cv(chunk_cv, total_chunks);
        OPENSSL_cleanse(chunk_cv.data(), chunk_cv.size() * sizeof(std::uint32_t));
        chunk_state_.reset({key_words_, total_chunks, flags_});
      }
      const std::size_t want = kBlake3ChunkLen - chunk_state_.len();
      const std::size_t take = std::min(want, input.size());
      chunk_state_.update(input.subspan(0U, take));
      input = input.subspan(take);
    }
  }

  Blake3Digest finalize() const noexcept {
    Blake3Output out = chunk_state_.output();
    std::size_t parent_remaining = cv_stack_len_;
    while (parent_remaining > 0U) {
      --parent_remaining;
      CvWords right_cv = out.chaining_value();
      out.cleanse();
      out = make_parent_output({cv_stack_[parent_remaining], right_cv},
                               {key_words_, flags_});
      OPENSSL_cleanse(right_cv.data(), right_cv.size() * sizeof(std::uint32_t));
    }
    Blake3Digest digest = out.root_digest();
    out.cleanse();
    return digest;
  }

private:
  void add_chunk_cv(CvWords new_cv, std::uint64_t total_chunks) noexcept {
    while ((total_chunks & 1U) == 0U && cv_stack_len_ > 0U) {
      --cv_stack_len_;
      CvWords left_cv = cv_stack_[cv_stack_len_];
      OPENSSL_cleanse(cv_stack_[cv_stack_len_].data(),
                      cv_stack_[cv_stack_len_].size() * sizeof(std::uint32_t));
      new_cv = compute_parent_cv({left_cv, new_cv}, {key_words_, flags_});
      OPENSSL_cleanse(left_cv.data(), left_cv.size() * sizeof(std::uint32_t));
      total_chunks >>= 1U;
    }
    if (cv_stack_len_ < kBlake3MaxStackDepth) {
      cv_stack_[cv_stack_len_] = new_cv;
      ++cv_stack_len_;
    }
    OPENSSL_cleanse(new_cv.data(), new_cv.size() * sizeof(std::uint32_t));
  }

  Blake3ChunkState chunk_state_;
  CvWords key_words_{};
  std::array<CvWords, kBlake3MaxStackDepth> cv_stack_{};
  std::size_t cv_stack_len_ = 0U;
  std::uint8_t flags_ = 0U;
};

// ---------------------------------------------------------------------------
// Strict UTF-8, ASCII, hex, and control-character checks
// ---------------------------------------------------------------------------

bool is_valid_utf8_bytes(std::span<const std::uint8_t> bytes) noexcept {
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
        return false;
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

bool is_valid_utf8_text(std::string_view text) noexcept {
  const auto *ptr = reinterpret_cast<const std::uint8_t *>(text.data());
  return is_valid_utf8_bytes(std::span<const std::uint8_t>{ptr, text.size()});
}

// Rejects ASCII controls (<0x20, 0x7f), Unicode C1 controls (U+0080..U+009F),
// BiDi isolates/overrides, and BOM.
bool contains_disallowed_pin_codepoint(std::string_view utf8) noexcept {
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(utf8.data());
  std::size_t i = 0U;
  while (i < utf8.size()) {
    const std::uint8_t b0 = bytes[i];
    std::uint32_t cp = 0U;
    if (b0 <= 0x7fU) {
      cp = b0;
      ++i;
    } else if (b0 >= 0xc2U && b0 <= 0xdfU) {
      cp = ((static_cast<std::uint32_t>(b0 & 0x1fU)) << 6U) |
           static_cast<std::uint32_t>(bytes[i + 1U] & 0x3fU);
      i += 2U;
    } else if (b0 >= 0xe0U && b0 <= 0xefU) {
      cp = ((static_cast<std::uint32_t>(b0 & 0x0fU)) << 12U) |
           ((static_cast<std::uint32_t>(bytes[i + 1U] & 0x3fU)) << 6U) |
           static_cast<std::uint32_t>(bytes[i + 2U] & 0x3fU);
      i += 3U;
    } else {
      cp = ((static_cast<std::uint32_t>(b0 & 0x07U)) << 18U) |
           ((static_cast<std::uint32_t>(bytes[i + 1U] & 0x3fU)) << 12U) |
           ((static_cast<std::uint32_t>(bytes[i + 2U] & 0x3fU)) << 6U) |
           static_cast<std::uint32_t>(bytes[i + 3U] & 0x3fU);
      i += 4U;
    }
    if (cp < 0x20U || cp == 0x7fU || (cp >= 0x80U && cp <= 0x9fU)) {
      return true;
    }
    if (cp == 0x200eU || cp == 0x200fU || (cp >= 0x202aU && cp <= 0x202eU) ||
        (cp >= 0x2066U && cp <= 0x2069U) || cp == 0xfeffU) {
      return true;
    }
  }
  return false;
}

constexpr std::optional<std::uint8_t> hex_nibble_lower(char ch) noexcept {
  if (ch >= '0' && ch <= '9') {
    return static_cast<std::uint8_t>(ch - '0');
  }
  if (ch >= 'a' && ch <= 'f') {
    return static_cast<std::uint8_t>(10 + (ch - 'a'));
  }
  return std::nullopt;
}

template <std::size_t N>
std::optional<std::array<std::uint8_t, N>> parse_exact_hex_lower(std::string_view hex) {
  if (hex.size() != N * 2U) {
    return std::nullopt;
  }
  std::array<std::uint8_t, N> out{};
  for (std::size_t i = 0U; i < N; ++i) {
    const auto hi = hex_nibble_lower(hex[i * 2U]);
    const auto lo = hex_nibble_lower(hex[(i * 2U) + 1U]);
    if (!hi.has_value() || !lo.has_value()) {
      OPENSSL_cleanse(out.data(), out.size());
      return std::nullopt;
    }
    out[i] = static_cast<std::uint8_t>((*hi << 4U) | *lo);
  }
  return out;
}

constexpr bool is_ascii_printable(char ch) noexcept {
  const auto byte = static_cast<std::uint8_t>(ch);
  return byte >= 0x20U && byte <= 0x7eU;
}

constexpr char to_ascii_lower(char ch) noexcept {
  return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch + ('a' - 'A')) : ch;
}

std::string ascii_lower(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(to_ascii_lower(ch));
  }
  return out;
}

constexpr std::string_view trim_ows(std::string_view text) noexcept {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1U);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1U);
  }
  return text;
}

std::optional<std::string> lookup_env(const EnvLookupFn &env_lookup,
                                      std::string_view name) {
  if (env_lookup) {
    return env_lookup(name);
  }
  const std::string key{name};
  const char *val = std::getenv(key.c_str());
  if (val == nullptr) {
    return std::nullopt;
  }
  return std::string{val};
}

bool env_kill_switch_active(const EnvLookupFn &env_lookup, std::string_view var_name) {
  const auto val = lookup_env(env_lookup, var_name);
  if (!val.has_value()) {
    return false;
  }
  const std::string lower = ascii_lower(trim_ows(*val));
  if (lower.empty() || lower == "0" || lower == "false" || lower == "no") {
    return false;
  }
  // Honor 1/true/yes and fail closed on any other non-empty value.
  return true;
}

// ---------------------------------------------------------------------------
// Secure POSIX file helpers (O_NOFOLLOW, lstat/fstat match, atomic 0600)
// ---------------------------------------------------------------------------

Result<void> fsync_fd(int fd) {
  for (;;) {
    if (::fsync(fd) == 0) {
      return Result<void>::success();
    }
    if (errno == EINTR) {
      continue;
    }
    return fail_void(ErrorCode::io, LanError::identity_io_failed);
  }
}

struct PolicyFileCheck {
  std::uint32_t expected_uid = 0U;
  bool forbid_group_world_write = false;
};

struct PolicyFileReadResult {
  bool exists = false;
  std::string contents;
};

Result<PolicyFileReadResult>
read_verified_policy_file(const std::filesystem::path &path, PolicyFileCheck check) {
  if (path.empty()) {
    return fail<PolicyFileReadResult>(ErrorCode::invalid_identity,
                                      LanError::policy_io_failed);
  }
  const std::string path_str = path.string();
  struct stat lst{};
  if (::lstat(path_str.c_str(), &lst) != 0) {
    if (errno == ENOENT) {
      return Result<PolicyFileReadResult>::success(PolicyFileReadResult{false, {}});
    }
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_io_failed);
  }
  if (S_ISLNK(lst.st_mode)) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_symlink_rejected);
  }
  if (!S_ISREG(lst.st_mode)) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_insecure_file);
  }
  if (static_cast<std::uint32_t>(lst.st_uid) != check.expected_uid) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_insecure_file);
  }
  if (check.forbid_group_world_write && ((lst.st_mode & mode_t{0022}) != 0)) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_insecure_file);
  }

  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ELOOP) {
      return fail<PolicyFileReadResult>(ErrorCode::io,
                                        LanError::policy_symlink_rejected);
    }
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_io_failed);
  }
  ScopedFd owned{fd};

  struct stat fst{};
  if (::fstat(owned.get(), &fst) != 0) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_io_failed);
  }
  if (!S_ISREG(fst.st_mode) || fst.st_dev != lst.st_dev || fst.st_ino != lst.st_ino ||
      static_cast<std::uint32_t>(fst.st_uid) != check.expected_uid) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_insecure_file);
  }
  if (check.forbid_group_world_write && ((fst.st_mode & mode_t{0022}) != 0)) {
    return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_insecure_file);
  }

  std::string content;
  std::array<char, 4096> chunk{};
  for (;;) {
    const ssize_t n = ::read(owned.get(), chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fail<PolicyFileReadResult>(ErrorCode::io, LanError::policy_io_failed);
    }
    if (n == 0) {
      break;
    }
    const auto got = static_cast<std::size_t>(n);
    if (content.size() + got > kMaxLanPolicyFileBytes) {
      return fail<PolicyFileReadResult>(ErrorCode::capacity,
                                        LanError::policy_parse_error);
    }
    content.append(chunk.data(), got);
  }
  return Result<PolicyFileReadResult>::success(
      PolicyFileReadResult{true, std::move(content)});
}

Result<ScopedFd> open_lan_identity_dir(const std::filesystem::path &dir) {
  if (dir.empty()) {
    return fail<ScopedFd>(ErrorCode::invalid_identity, LanError::identity_io_failed);
  }
  std::string path_str = dir.string();
  while (path_str.size() > 1U && path_str.back() == '/') {
    path_str.pop_back();
  }

  struct stat lst{};
  if (::lstat(path_str.c_str(), &lst) == 0) {
    if (S_ISLNK(lst.st_mode)) {
      return fail<ScopedFd>(ErrorCode::io, LanError::identity_symlink_rejected);
    }
  } else if (errno != ENOENT) {
    return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
  }

  bool created = false;
  if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
    created = true;
  } else if (errno == ENOENT) {
    const auto parent = std::filesystem::path{path_str}.parent_path();
    if (!parent.empty()) {
      std::error_code ec;
      (void)std::filesystem::create_directories(parent, ec);
      if (ec) {
        return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
      }
    }
    if (::mkdir(path_str.c_str(), mode_t{0700}) == 0) {
      created = true;
    } else if (errno != EEXIST) {
      return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
    }
  } else if (errno != EEXIST) {
    return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
  }

  int fd = -1;
  do {
    fd = ::open(path_str.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ELOOP || errno == ENOTDIR) {
      return fail<ScopedFd>(ErrorCode::io, LanError::identity_symlink_rejected);
    }
    return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
  }
  ScopedFd owned{fd};

  if (created && ::fchmod(owned.get(), mode_t{0700}) != 0) {
    return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
  }
  struct stat st{};
  if (::fstat(owned.get(), &st) != 0) {
    return fail<ScopedFd>(ErrorCode::io, LanError::identity_io_failed);
  }
  if (!S_ISDIR(st.st_mode) || st.st_uid != ::geteuid() ||
      ((st.st_mode & mode_t{0077}) != 0)) {
    return fail<ScopedFd>(ErrorCode::io, LanError::identity_insecure_permissions);
  }
  return Result<ScopedFd>::success(std::move(owned));
}

struct ReadSecretFileResult {
  bool exists = false;
  std::vector<std::uint8_t> bytes;
};

Result<ReadSecretFileResult> read_secret_file_0600(int dir_fd, const char *name,
                                                   std::size_t max_bytes) {
  int fd = -1;
  do {
    fd = ::openat(dir_fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    if (errno == ENOENT) {
      return Result<ReadSecretFileResult>::success(ReadSecretFileResult{false, {}});
    }
    if (errno == ELOOP) {
      return fail<ReadSecretFileResult>(ErrorCode::io,
                                        LanError::identity_symlink_rejected);
    }
    return fail<ReadSecretFileResult>(ErrorCode::io, LanError::identity_io_failed);
  }
  ScopedFd owned{fd};

  struct stat st{};
  if (::fstat(owned.get(), &st) != 0) {
    return fail<ReadSecretFileResult>(ErrorCode::io, LanError::identity_io_failed);
  }
  if (!S_ISREG(st.st_mode) || st.st_uid != ::geteuid() ||
      ((st.st_mode & mode_t{0077}) != 0)) {
    return fail<ReadSecretFileResult>(ErrorCode::io,
                                      LanError::identity_insecure_permissions);
  }

  std::vector<std::uint8_t> buf;
  std::array<std::uint8_t, 4096> chunk{};
  CleanseArrayGuard chunk_guard{chunk};
  for (;;) {
    const ssize_t n = ::read(owned.get(), chunk.data(), chunk.size());
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
      }
      return fail<ReadSecretFileResult>(ErrorCode::io, LanError::identity_io_failed);
    }
    if (n == 0) {
      break;
    }
    const auto got = static_cast<std::size_t>(n);
    if (buf.size() + got > max_bytes) {
      if (!buf.empty()) {
        OPENSSL_cleanse(buf.data(), buf.size());
      }
      return fail<ReadSecretFileResult>(ErrorCode::corrupt, LanError::identity_corrupt);
    }
    buf.insert(buf.end(), chunk.begin(),
               chunk.begin() + static_cast<std::ptrdiff_t>(got));
  }
  return Result<ReadSecretFileResult>::success(
      ReadSecretFileResult{true, std::move(buf)});
}

Result<void> write_secret_file_atomic_0600(int dir_fd, const char *name,
                                           std::span<const std::uint8_t> data) {
  const std::uint64_t seq = g_lan_tmp_seq.fetch_add(1U, std::memory_order_relaxed);
  const std::string tmp_name = std::string{"."} + name + ".tmp." + std::to_string(seq) +
                               "." +
                               std::to_string(static_cast<std::uint64_t>(::getpid()));

  int fd = -1;
  do {
    fd = ::openat(dir_fd, tmp_name.c_str(),
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t{0600});
  } while (fd < 0 && errno == EINTR);
  if (fd < 0) {
    return fail_void(ErrorCode::io, LanError::identity_io_failed);
  }
  ScopedFd owned{fd};

  auto cleanup_tmp = [&]() noexcept {
    owned.reset();
    (void)::unlinkat(dir_fd, tmp_name.c_str(), 0);
  };

  if (::fchmod(owned.get(), mode_t{0600}) != 0) {
    cleanup_tmp();
    return fail_void(ErrorCode::io, LanError::identity_io_failed);
  }

  std::size_t offset = 0U;
  while (offset < data.size()) {
    const ssize_t written =
        ::write(owned.get(), data.data() + offset, data.size() - offset);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      cleanup_tmp();
      return fail_void(ErrorCode::io, LanError::identity_io_failed);
    }
    if (written == 0) {
      cleanup_tmp();
      return fail_void(ErrorCode::io, LanError::identity_io_failed);
    }
    offset += static_cast<std::size_t>(written);
  }

  if (const auto synced = fsync_fd(owned.get()); !synced.has_value()) {
    cleanup_tmp();
    return synced;
  }
  owned.reset();

  if (::renameat(dir_fd, tmp_name.c_str(), dir_fd, name) != 0) {
    (void)::unlinkat(dir_fd, tmp_name.c_str(), 0);
    return fail_void(ErrorCode::io, LanError::identity_io_failed);
  }
  return fsync_fd(dir_fd);
}

// ---------------------------------------------------------------------------
// Local OS Presence helpers (sudo via posix_spawn + macOS LAContext via dlopen)
// ---------------------------------------------------------------------------

Result<void> run_sudo_flag(const char *flag) {
  std::string prog = "/usr/bin/sudo";
  std::string arg = flag;
  std::array<char *, 3> argv = {prog.data(), arg.data(), nullptr};

  pid_t pid = -1;
  const int spawn_rc =
      ::posix_spawn(&pid, prog.c_str(), nullptr, nullptr, argv.data(), environ);
  if (spawn_rc != 0) {
    if (spawn_rc == ENOENT) {
      return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
    }
    return fail_void(ErrorCode::io, LanError::local_auth_failed);
  }

  int status = 0;
  for (;;) {
    const pid_t w = ::waitpid(pid, &status, 0);
    if (w < 0) {
      if (errno == EINTR) {
        continue;
      }
      return fail_void(ErrorCode::io, LanError::local_auth_failed);
    }
    break;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return fail_void(ErrorCode::provider_auth, LanError::local_auth_denied);
  }
  return Result<void>::success();
}

Result<void> verify_via_sudo() {
  // Always invalidate cached sudo timestamp first so a walk-up attacker cannot
  // reuse an existing sudo grace window.
  if (const auto k = run_sudo_flag("-k"); !k.has_value()) {
    return k;
  }
  return run_sudo_flag("-v");
}

#ifdef __APPLE__
bool is_headless_ssh_session(const EnvLookupFn &env_lookup) {
  for (const std::string_view key : {"SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"}) {
    const auto val = lookup_env(env_lookup, key);
    if (val.has_value() && !val->empty()) {
      return true;
    }
  }
  return false;
}

template <typename FnPtr> FnPtr dlsym_fn(void *handle, const char *symbol) noexcept {
  void *sym = ::dlsym(handle, symbol);
  FnPtr out = nullptr;
  static_assert(sizeof(out) == sizeof(sym));
  std::memcpy(&out, &sym, sizeof(out));
  return out;
}

struct ObjcBlockDescriptor {
  unsigned long reserved;
  unsigned long size;
};

struct LaReplyBlock {
  void *isa;
  int flags;
  int reserved;
  void (*invoke)(LaReplyBlock *, signed char, void *);
  const ObjcBlockDescriptor *descriptor;
  std::mutex *mu;
  std::condition_variable *cv;
  bool *done;
  bool *succeeded;
};

void la_reply_invoke(LaReplyBlock *block, signed char success, void * /*err*/) {
  if (block == nullptr || block->mu == nullptr || block->cv == nullptr ||
      block->done == nullptr || block->succeeded == nullptr) {
    return;
  }
  std::lock_guard<std::mutex> lock(*block->mu);
  *block->succeeded = (success != 0);
  *block->done = true;
  // Notify while still holding *block->mu so the waiting thread cannot return
  // and destroy stack-allocated cv before notify_one() completes.
  block->cv->notify_one();
}

Result<void> verify_via_macos_local_auth(std::string_view reason) {
  static void *const kLaFramework = ::dlopen(
      "/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication",
      RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE);
  static void *const kFoundationFramework =
      ::dlopen("/System/Library/Frameworks/Foundation.framework/Foundation",
               RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE);
  static void *const kObjcLib =
      ::dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY | RTLD_LOCAL | RTLD_NODELETE);

  if (kLaFramework == nullptr || kFoundationFramework == nullptr ||
      kObjcLib == nullptr) {
    return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
  }

  using ObjcGetClassFn = void *(*)(const char *);
  using SelRegisterNameFn = void *(*)(const char *);
  using MsgSendIdFn = void *(*)(void *, void *);
  using MsgSendVoidFn = void (*)(void *, void *);
  using MsgSendIdCStrFn = void *(*)(void *, void *, const char *);
  using MsgSendCanEvalFn = signed char (*)(void *, void *, long, void **);
  using MsgSendEvalFn = void (*)(void *, void *, long, void *, void *);

  const auto get_class = dlsym_fn<ObjcGetClassFn>(kObjcLib, "objc_getClass");
  const auto reg_sel = dlsym_fn<SelRegisterNameFn>(kObjcLib, "sel_registerName");
  const auto msg_id = dlsym_fn<MsgSendIdFn>(kObjcLib, "objc_msgSend");
  const auto msg_void = dlsym_fn<MsgSendVoidFn>(kObjcLib, "objc_msgSend");
  const auto msg_id_cstr = dlsym_fn<MsgSendIdCStrFn>(kObjcLib, "objc_msgSend");
  const auto msg_can_eval = dlsym_fn<MsgSendCanEvalFn>(kObjcLib, "objc_msgSend");
  const auto msg_eval = dlsym_fn<MsgSendEvalFn>(kObjcLib, "objc_msgSend");
  void *stack_block_isa = ::dlsym(RTLD_DEFAULT, "_NSConcreteStackBlock");

  if (get_class == nullptr || reg_sel == nullptr || msg_id == nullptr ||
      msg_void == nullptr || msg_id_cstr == nullptr || msg_can_eval == nullptr ||
      msg_eval == nullptr || stack_block_isa == nullptr) {
    return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
  }

  void *la_ctx_cls = get_class("LAContext");
  void *ns_string_cls = get_class("NSString");
  if (la_ctx_cls == nullptr || ns_string_cls == nullptr) {
    return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
  }

  void *sel_alloc = reg_sel("alloc");
  void *sel_init = reg_sel("init");
  void *sel_release = reg_sel("release");
  void *sel_init_utf8 = reg_sel("initWithUTF8String:");
  void *sel_can_eval = reg_sel("canEvaluatePolicy:error:");
  void *sel_eval = reg_sel("evaluatePolicy:localizedReason:reply:");

  void *ctx_alloc = msg_id(la_ctx_cls, sel_alloc);
  if (ctx_alloc == nullptr) {
    return fail_void(ErrorCode::allocation, LanError::local_auth_failed);
  }
  void *ctx = msg_id(ctx_alloc, sel_init);
  if (ctx == nullptr) {
    return fail_void(ErrorCode::allocation, LanError::local_auth_failed);
  }

  struct ObjcReleaseGuard {
    void *obj;
    MsgSendVoidFn send_void;
    void *release_sel;
    ~ObjcReleaseGuard() {
      if (obj != nullptr) {
        send_void(obj, release_sel);
      }
    }
  };
  ObjcReleaseGuard ctx_guard{ctx, msg_void, sel_release};

  // LAPolicyDeviceOwnerAuthentication == 2 (biometrics or OS login password).
  constexpr long kLaPolicyDeviceOwnerAuthentication = 2L;
  void *ns_err = nullptr;
  if (msg_can_eval(ctx, sel_can_eval, kLaPolicyDeviceOwnerAuthentication, &ns_err) ==
      0) {
    return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
  }

  const std::string reason_str{reason};
  void *str_alloc = msg_id(ns_string_cls, sel_alloc);
  if (str_alloc == nullptr) {
    return fail_void(ErrorCode::allocation, LanError::local_auth_failed);
  }
  void *ns_reason = msg_id_cstr(str_alloc, sel_init_utf8, reason_str.c_str());
  if (ns_reason == nullptr) {
    return fail_void(ErrorCode::allocation, LanError::local_auth_failed);
  }
  ObjcReleaseGuard reason_guard{ns_reason, msg_void, sel_release};

  static constexpr ObjcBlockDescriptor kBlockDescriptor = {0UL, sizeof(LaReplyBlock)};
  std::mutex mu;
  std::condition_variable cv;
  bool done = false;
  bool succeeded = false;
  LaReplyBlock reply_block{
      stack_block_isa, 0,          0, &la_reply_invoke, &kBlockDescriptor, &mu, &cv,
      &done,           &succeeded,
  };

  msg_eval(ctx, sel_eval, kLaPolicyDeviceOwnerAuthentication, ns_reason, &reply_block);

  std::unique_lock<std::mutex> lock(mu);
  cv.wait(lock, [&]() noexcept { return done; });
  if (!succeeded) {
    return fail_void(ErrorCode::provider_auth, LanError::local_auth_denied);
  }
  return Result<void>::success();
}
#endif

// ---------------------------------------------------------------------------
// Strict JSON helpers for identity & handshake frames
// ---------------------------------------------------------------------------

Result<const Value::Object *> expect_json_object(const Value &v, LanError err) {
  const auto *obj = std::get_if<Value::Object>(&v.value());
  if (obj == nullptr) {
    return fail<const Value::Object *>(ErrorCode::corrupt, err);
  }
  return Result<const Value::Object *>::success(obj);
}

Result<void> check_allowed_unique_keys(const Value::Object &obj,
                                       std::span<const std::string_view> allowed,
                                       LanError err) {
  std::set<std::string_view> seen;
  for (const auto &[key, _] : obj) {
    const bool is_allowed =
        std::any_of(allowed.begin(), allowed.end(),
                    [&](std::string_view candidate) { return candidate == key; });
    if (!is_allowed) {
      return fail_void(ErrorCode::corrupt, err);
    }
    if (!seen.insert(key).second) {
      return fail_void(ErrorCode::corrupt, err);
    }
  }
  return Result<void>::success();
}

const Value *find_field(const Value::Object &obj, std::string_view key) noexcept {
  for (const auto &[k, v] : obj) {
    if (k == key) {
      return &v;
    }
  }
  return nullptr;
}

Result<std::uint64_t> field_as_u64(const Value &v, LanError err) {
  const auto *num = std::get_if<Number>(&v.value());
  if (num == nullptr) {
    return fail<std::uint64_t>(ErrorCode::corrupt, err);
  }
  if (const auto *u = std::get_if<std::uint64_t>(&num->storage())) {
    return Result<std::uint64_t>::success(*u);
  }
  if (const auto *i = std::get_if<std::int64_t>(&num->storage())) {
    if (*i < 0) {
      return fail<std::uint64_t>(ErrorCode::corrupt, err);
    }
    return Result<std::uint64_t>::success(static_cast<std::uint64_t>(*i));
  }
  return fail<std::uint64_t>(ErrorCode::corrupt, err);
}

Result<std::uint64_t> get_required_safe_u64(const Value::Object &obj,
                                            std::string_view key, LanError err) {
  const Value *v = find_field(obj, key);
  if (v == nullptr) {
    return fail<std::uint64_t>(ErrorCode::corrupt, err);
  }
  const auto val = field_as_u64(*v, err);
  if (!val.has_value() || val.value() > mp::kMaxSafeId) {
    return fail<std::uint64_t>(ErrorCode::corrupt, err);
  }
  return val;
}

Result<bool> get_required_bool(const Value::Object &obj, std::string_view key,
                               LanError err) {
  const Value *v = find_field(obj, key);
  if (v == nullptr) {
    return fail<bool>(ErrorCode::corrupt, err);
  }
  const auto *b = std::get_if<bool>(&v->value());
  if (b == nullptr) {
    return fail<bool>(ErrorCode::corrupt, err);
  }
  return Result<bool>::success(*b);
}

Result<std::string> get_required_string(const Value::Object &obj, std::string_view key,
                                        LanError err) {
  const Value *v = find_field(obj, key);
  if (v == nullptr) {
    return fail<std::string>(ErrorCode::corrupt, err);
  }
  const auto *s = std::get_if<std::string>(&v->value());
  if (s == nullptr) {
    return fail<std::string>(ErrorCode::corrupt, err);
  }
  return Result<std::string>::success(*s);
}

bool is_valid_reason_text(std::string_view text) noexcept {
  if (text.size() > kLanMaxRejectReasonBytes) {
    return false;
  }
  for (const char ch : text) {
    if (!is_ascii_printable(ch)) {
      return false;
    }
  }
  return true;
}

Result<void> validate_member_info(const LanMemberInfo &member) {
  if (member.account_id > mp::kMaxSafeId) {
    return fail_void(ErrorCode::invalid_range, LanError::frame_invalid_field);
  }
  if (!is_valid_lan_name(member.display_name)) {
    return fail_void(ErrorCode::invalid_identity, LanError::frame_invalid_field);
  }
  if (!mp::validate_ed25519_pubkey_strict(member.pubkey).has_value()) {
    return fail_void(ErrorCode::invalid_identity, LanError::invalid_pubkey);
  }
  return Result<void>::success();
}

Result<void> validate_member_list(const std::vector<LanMemberInfo> &members,
                                  bool allow_empty) {
  if (!allow_empty && members.empty()) {
    return fail_void(ErrorCode::corrupt, LanError::frame_invalid_field);
  }
  if (members.size() > kLanMaxMembers) {
    return fail_void(ErrorCode::capacity, LanError::frame_too_many_members);
  }
  std::set<mp::Ed25519PubKey> seen_pubkeys;
  for (const auto &member : members) {
    if (const auto ok = validate_member_info(member); !ok.has_value()) {
      return ok;
    }
    if (!seen_pubkeys.insert(member.pubkey).second) {
      return fail_void(ErrorCode::conflict, LanError::frame_invalid_field);
    }
  }
  return Result<void>::success();
}

Value member_to_json(const LanMemberInfo &member) {
  Value::Object obj;
  obj.emplace_back("account_id", Value{Number{member.account_id}});
  obj.emplace_back("display_name", Value{member.display_name});
  obj.emplace_back("pubkey", Value{mp::hex_lower(member.pubkey)});
  obj.emplace_back("is_host", Value{member.is_host});
  return Value::object(std::move(obj));
}

Result<LanMemberInfo> member_from_json(const Value &v) {
  const auto obj_res = expect_json_object(v, LanError::frame_invalid_field);
  if (!obj_res.has_value()) {
    return Result<LanMemberInfo>::failure(obj_res.error());
  }
  const auto &obj = *obj_res.value();
  static constexpr std::array<std::string_view, 4> kAllowed = {
      "account_id", "display_name", "pubkey", "is_host"};
  if (const auto ok =
          check_allowed_unique_keys(obj, kAllowed, LanError::frame_invalid_field);
      !ok.has_value()) {
    return Result<LanMemberInfo>::failure(ok.error());
  }

  const auto acct =
      get_required_safe_u64(obj, "account_id", LanError::frame_invalid_field);
  const auto name =
      get_required_string(obj, "display_name", LanError::frame_invalid_field);
  const auto pk_hex = get_required_string(obj, "pubkey", LanError::frame_invalid_field);
  const auto is_host = get_required_bool(obj, "is_host", LanError::frame_invalid_field);
  if (!acct.has_value() || !name.has_value() || !pk_hex.has_value() ||
      !is_host.has_value()) {
    return fail<LanMemberInfo>(ErrorCode::corrupt, LanError::frame_invalid_field);
  }
  const auto pk = parse_exact_hex_lower<32U>(pk_hex.value());
  if (!pk.has_value()) {
    return fail<LanMemberInfo>(ErrorCode::corrupt, LanError::frame_invalid_field);
  }
  LanMemberInfo out{acct.value(), name.value(), *pk, is_host.value()};
  if (const auto ok = validate_member_info(out); !ok.has_value()) {
    return Result<LanMemberInfo>::failure(ok.error());
  }
  return Result<LanMemberInfo>::success(std::move(out));
}

Result<std::vector<LanMemberInfo>> members_array_from_json(const Value::Object &obj,
                                                           bool allow_empty) {
  const Value *field = find_field(obj, "members");
  if (field == nullptr) {
    return fail<std::vector<LanMemberInfo>>(ErrorCode::corrupt,
                                            LanError::frame_invalid_field);
  }
  const auto *arr = std::get_if<Value::Array>(&field->value());
  if (arr == nullptr) {
    return fail<std::vector<LanMemberInfo>>(ErrorCode::corrupt,
                                            LanError::frame_invalid_field);
  }
  if (arr->size() > kLanMaxMembers) {
    return fail<std::vector<LanMemberInfo>>(ErrorCode::capacity,
                                            LanError::frame_too_many_members);
  }
  std::vector<LanMemberInfo> out;
  out.reserve(arr->size());
  for (const auto &elem : *arr) {
    auto m = member_from_json(elem);
    if (!m.has_value()) {
      return Result<std::vector<LanMemberInfo>>::failure(m.error());
    }
    out.push_back(std::move(m).value());
  }
  if (const auto ok = validate_member_list(out, allow_empty); !ok.has_value()) {
    return Result<std::vector<LanMemberInfo>>::failure(ok.error());
  }
  return Result<std::vector<LanMemberInfo>>::success(std::move(out));
}

} // namespace

// ---------------------------------------------------------------------------
// Error & kind names
// ---------------------------------------------------------------------------

std::string_view lan_error_name(LanError detail) noexcept {
  switch (detail) {
  case LanError::none:
    return "none";
  case LanError::invalid_pin:
    return "invalid_pin";
  case LanError::invalid_lan_party_id:
    return "invalid_lan_party_id";
  case LanError::invalid_pubkey:
    return "invalid_pubkey";
  case LanError::pin_proof_mismatch:
    return "pin_proof_mismatch";
  case LanError::crypto_internal:
    return "crypto_internal";
  case LanError::lan_disabled:
    return "lan_disabled";
  case LanError::policy_parse_error:
    return "policy_parse_error";
  case LanError::policy_insecure_file:
    return "policy_insecure_file";
  case LanError::policy_symlink_rejected:
    return "policy_symlink_rejected";
  case LanError::policy_io_failed:
    return "policy_io_failed";
  case LanError::invalid_display_name:
    return "invalid_display_name";
  case LanError::identity_insecure_permissions:
    return "identity_insecure_permissions";
  case LanError::identity_symlink_rejected:
    return "identity_symlink_rejected";
  case LanError::identity_corrupt:
    return "identity_corrupt";
  case LanError::identity_io_failed:
    return "identity_io_failed";
  case LanError::local_auth_denied:
    return "local_auth_denied";
  case LanError::local_auth_unavailable:
    return "local_auth_unavailable";
  case LanError::local_auth_failed:
    return "local_auth_failed";
  case LanError::frame_too_large:
    return "frame_too_large";
  case LanError::frame_truncated:
    return "frame_truncated";
  case LanError::frame_unsupported_version:
    return "frame_unsupported_version";
  case LanError::frame_unknown_kind:
    return "frame_unknown_kind";
  case LanError::frame_non_zero_reserved:
    return "frame_non_zero_reserved";
  case LanError::frame_lane_mismatch:
    return "frame_lane_mismatch";
  case LanError::frame_invalid_utf8:
    return "frame_invalid_utf8";
  case LanError::frame_invalid_json:
    return "frame_invalid_json";
  case LanError::frame_invalid_field:
    return "frame_invalid_field";
  case LanError::frame_too_many_members:
    return "frame_too_many_members";
  case LanError::pin_peer_locked:
    return "pin_peer_locked";
  case LanError::pin_lobby_locked:
    return "pin_lobby_locked";
  }
  return "unknown";
}

std::string_view lan_handshake_kind_name(LanHandshakeKind kind) noexcept {
  switch (kind) {
  case LanHandshakeKind::lan_hello:
    return "lan_hello";
  case LanHandshakeKind::lan_join:
    return "lan_join";
  case LanHandshakeKind::lan_welcome:
    return "lan_welcome";
  case LanHandshakeKind::lan_roster:
    return "lan_roster";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// 1. BLAKE3 & PIN Proof API
// ---------------------------------------------------------------------------

Blake3Digest blake3_hash(std::span<const std::uint8_t> input) noexcept {
  Blake3Hasher hasher{kBlake3Iv, 0U};
  hasher.update(input);
  return hasher.finalize();
}

Blake3Digest blake3_keyed_hash(const Blake3Key &key,
                               std::span<const std::uint8_t> input) noexcept {
  CvWords key_words = bytes_to_cv_words(key);
  CleanseU32ArrayGuard key_words_guard{key_words};
  Blake3Hasher hasher{key_words, kBlake3KeyedHash};
  hasher.update(input);
  return hasher.finalize();
}

Blake3Digest blake3_derive_key(std::string_view context,
                               std::span<const std::uint8_t> key_material) noexcept {
  Blake3Hasher ctx_hasher{kBlake3Iv, kBlake3DeriveKeyContext};
  const auto *ctx_ptr = reinterpret_cast<const std::uint8_t *>(context.data());
  ctx_hasher.update(std::span<const std::uint8_t>{ctx_ptr, context.size()});
  Blake3Digest ctx_key = ctx_hasher.finalize();
  CleanseArrayGuard ctx_key_guard{ctx_key};

  CvWords ctx_key_words = bytes_to_cv_words(ctx_key);
  CleanseU32ArrayGuard ctx_key_words_guard{ctx_key_words};
  Blake3Hasher material_hasher{ctx_key_words, kBlake3DeriveKeyMaterial};
  material_hasher.update(key_material);
  return material_hasher.finalize();
}

CleansedPin::CleansedPin(const CleansedPin &other) noexcept
    : bytes_(other.bytes_), len_(other.len_) {}

CleansedPin &CleansedPin::operator=(const CleansedPin &other) noexcept {
  if (this != &other) {
    cleanse();
    bytes_ = other.bytes_;
    len_ = other.len_;
  }
  return *this;
}

CleansedPin::CleansedPin(CleansedPin &&other) noexcept
    : bytes_(other.bytes_), len_(other.len_) {
  other.cleanse();
}

CleansedPin &CleansedPin::operator=(CleansedPin &&other) noexcept {
  if (this != &other) {
    cleanse();
    bytes_ = other.bytes_;
    len_ = other.len_;
    other.cleanse();
  }
  return *this;
}

CleansedPin::~CleansedPin() { cleanse(); }

void CleansedPin::cleanse() noexcept {
  OPENSSL_cleanse(bytes_.data(), bytes_.size());
  len_ = 0U;
}

Result<CleansedPin> CleansedPin::create(std::string_view raw) {
  if (const auto valid = validate_lan_pin(raw); !valid.has_value()) {
    return Result<CleansedPin>::failure(valid.error());
  }
  CleansedPin out{};
  std::memcpy(out.bytes_.data(), raw.data(), raw.size());
  out.len_ = raw.size();
  return Result<CleansedPin>::success(std::move(out));
}

Result<void> validate_lan_pin(std::string_view pin) {
  if (pin.empty() || pin.size() > kLanPinMaxBytes) {
    return fail_void(ErrorCode::invalid_range, LanError::invalid_pin);
  }
  if (!is_valid_utf8_text(pin)) {
    return fail_void(ErrorCode::corrupt, LanError::invalid_pin);
  }
  if (contains_disallowed_pin_codepoint(pin)) {
    return fail_void(ErrorCode::invalid_identity, LanError::invalid_pin);
  }
  return Result<void>::success();
}

Result<LanPartyId> parse_lan_party_id_hex(std::string_view hex) {
  const auto parsed = parse_exact_hex_lower<kLanPartyIdBytes>(hex);
  if (!parsed.has_value()) {
    return fail<LanPartyId>(ErrorCode::invalid_identity,
                            LanError::invalid_lan_party_id);
  }
  return Result<LanPartyId>::success(*parsed);
}

std::string format_lan_party_id_hex(const LanPartyId &id) { return mp::hex_lower(id); }

Result<LanPinProof> compute_lan_pin_proof(const LanPinProofInput &input) {
  if (const auto pin_ok = validate_lan_pin(input.pin); !pin_ok.has_value()) {
    return Result<LanPinProof>::failure(pin_ok.error());
  }
  const auto party_id = parse_lan_party_id_hex(input.lan_party_id_hex);
  if (!party_id.has_value()) {
    return Result<LanPinProof>::failure(party_id.error());
  }

  const auto *pin_ptr = reinterpret_cast<const std::uint8_t *>(input.pin.data());
  Blake3Key key = blake3_derive_key(
      kLanPinDeriveContext, std::span<const std::uint8_t>{pin_ptr, input.pin.size()});
  CleanseArrayGuard key_guard{key};

  static_assert(kLanJoinProofDomain.size() == 12U);
  std::array<std::uint8_t, 12U + 8U + 32U + 32U + 32U> msg{};
  static_assert(msg.size() == 116U);
  CleanseArrayGuard msg_guard{msg};

  std::size_t off = 0U;
  std::memcpy(msg.data() + off, kLanJoinProofDomain.data(), kLanJoinProofDomain.size());
  off += kLanJoinProofDomain.size();
  std::memcpy(msg.data() + off, party_id.value().data(), party_id.value().size());
  off += party_id.value().size();
  std::memcpy(msg.data() + off, input.host_pubkey.data(), input.host_pubkey.size());
  off += input.host_pubkey.size();
  std::memcpy(msg.data() + off, input.joiner_pubkey.data(), input.joiner_pubkey.size());
  off += input.joiner_pubkey.size();
  std::memcpy(msg.data() + off, input.host_nonce.data(), input.host_nonce.size());

  const LanPinProof proof = blake3_keyed_hash(key, msg);
  return Result<LanPinProof>::success(proof);
}

Result<bool> verify_lan_pin_proof(const LanPinProofInput &input,
                                  const LanPinProof &provided_proof) {
  auto expected_res = compute_lan_pin_proof(input);
  if (!expected_res.has_value()) {
    return Result<bool>::failure(expected_res.error());
  }
  LanPinProof expected = expected_res.value();
  OPENSSL_cleanse(expected_res.value().data(), expected_res.value().size());
  CleanseArrayGuard expected_guard{expected};

  const bool match =
      CRYPTO_memcmp(expected.data(), provided_proof.data(), expected.size()) == 0;
  return Result<bool>::success(match);
}

// ---------------------------------------------------------------------------
// 2. Policy Engine (Mandates #1, #2, #3, #6)
// ---------------------------------------------------------------------------

namespace {

struct ParsedLanPolicyFile {
  bool disabled = false;
  bool require_pin = false;
  bool require_local_auth = false;
  std::optional<std::uint32_t> idle_timeout_sec = std::nullopt;
  std::optional<std::uint32_t> scan_timeout_sec = std::nullopt;
};

struct TimeoutMergeInput {
  std::optional<std::uint32_t> sys_val;
  std::optional<std::uint32_t> user_val;
  std::uint32_t default_val;
  std::uint32_t hard_cap;
};

constexpr std::uint32_t resolve_policy_timeout(TimeoutMergeInput in) noexcept {
  if (in.sys_val.has_value() && in.user_val.has_value()) {
    return std::min({*in.sys_val, *in.user_val, in.hard_cap});
  }
  if (in.sys_val.has_value()) {
    return std::min(*in.sys_val, in.hard_cap);
  }
  if (in.user_val.has_value()) {
    return std::min(*in.user_val, in.hard_cap);
  }
  return in.default_val;
}

Result<ParsedLanPolicyFile> parse_lan_policy_file_toml(std::string_view text) {
  if (text.size() > kMaxLanPolicyFileBytes || !is_valid_utf8_text(text)) {
    return fail<ParsedLanPolicyFile>(ErrorCode::corrupt, LanError::policy_parse_error);
  }
  for (const char ch : text) {
    if (ch == '\0') {
      return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                       LanError::policy_parse_error);
    }
  }

  ParsedLanPolicyFile cfg{};
  bool in_lan_section = false;
  bool seen_lan_section = false;
  std::set<std::string_view> seen_keys;

  std::size_t pos = 0U;
  while (pos < text.size()) {
    std::size_t nl = text.find('\n', pos);
    if (nl == std::string_view::npos) {
      nl = text.size();
    }
    std::string_view line = text.substr(pos, nl - pos);
    pos = (nl < text.size()) ? (nl + 1U) : text.size();

    if (!line.empty() && line.back() == '\r') {
      line.remove_suffix(1U);
    }
    // Strip inline comments (none of [lan]'s keys accept string values).
    if (const std::size_t hash = line.find('#'); hash != std::string_view::npos) {
      line = line.substr(0U, hash);
    }
    line = trim_ows(line);
    if (line.empty()) {
      continue;
    }

    if (line.front() == '[') {
      if (line.back() != ']') {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      const std::string_view section = trim_ows(line.substr(1U, line.size() - 2U));
      if (section != "lan" || seen_lan_section) {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      in_lan_section = true;
      seen_lan_section = true;
      continue;
    }

    if (!in_lan_section) {
      return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                       LanError::policy_parse_error);
    }

    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) {
      return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                       LanError::policy_parse_error);
    }
    const std::string_view key = trim_ows(line.substr(0U, eq));
    const std::string_view val = trim_ows(line.substr(eq + 1U));
    if (key.empty() || val.empty()) {
      return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                       LanError::policy_parse_error);
    }
    if (!seen_keys.insert(key).second) {
      return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                       LanError::policy_parse_error);
    }

    auto parse_bool = [](std::string_view raw) -> std::optional<bool> {
      if (raw == "true") {
        return true;
      }
      if (raw == "false") {
        return false;
      }
      return std::nullopt;
    };

    auto parse_pos_u32 = [](std::string_view raw) -> std::optional<std::uint32_t> {
      if (raw.empty()) {
        return std::nullopt;
      }
      for (const char ch : raw) {
        if (ch < '0' || ch > '9') {
          return std::nullopt;
        }
      }
      std::uint32_t out = 0U;
      const auto [ptr, ec] =
          std::from_chars(raw.data(), raw.data() + raw.size(), out, 10);
      if (ec != std::errc{} || ptr != raw.data() + raw.size() || out == 0U) {
        return std::nullopt;
      }
      return out;
    };

    if (key == "disabled") {
      const auto b = parse_bool(val);
      if (!b.has_value()) {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      cfg.disabled = *b;
    } else if (key == "require_pin") {
      const auto b = parse_bool(val);
      if (!b.has_value()) {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      cfg.require_pin = *b;
    } else if (key == "require_local_auth") {
      const auto b = parse_bool(val);
      if (!b.has_value()) {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      cfg.require_local_auth = *b;
    } else if (key == "idle_timeout_sec") {
      const auto n = parse_pos_u32(val);
      if (!n.has_value()) {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      cfg.idle_timeout_sec = *n;
    } else if (key == "scan_timeout_sec") {
      const auto n = parse_pos_u32(val);
      if (!n.has_value()) {
        return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                         LanError::policy_parse_error);
      }
      cfg.scan_timeout_sec = *n;
    } else {
      return fail<ParsedLanPolicyFile>(ErrorCode::corrupt,
                                       LanError::policy_parse_error);
    }
  }

  return Result<ParsedLanPolicyFile>::success(cfg);
}

} // namespace

Result<LanPolicyConfig> parse_lan_policy_toml(std::string_view text) {
  const auto parsed = parse_lan_policy_file_toml(text);
  if (!parsed.has_value()) {
    return Result<LanPolicyConfig>::failure(parsed.error());
  }
  LanPolicyConfig cfg{};
  cfg.disabled = parsed.value().disabled;
  cfg.require_pin = parsed.value().require_pin;
  cfg.require_local_auth = parsed.value().require_local_auth;
  cfg.idle_timeout_sec =
      parsed.value().idle_timeout_sec.value_or(kDefaultLanIdleTimeoutSec);
  cfg.scan_timeout_sec =
      parsed.value().scan_timeout_sec.value_or(kDefaultLanScanTimeoutSec);
  return Result<LanPolicyConfig>::success(cfg);
}

Result<LanPolicyConfig> load_effective_lan_policy(const LanPolicyPaths &paths,
                                                  const EnvLookupFn &env_lookup) {
  ParsedLanPolicyFile sys_cfg{};
  if (!paths.system_policy_path.empty()) {
    const auto sys_file = read_verified_policy_file(
        paths.system_policy_path,
        PolicyFileCheck{paths.expected_system_uid, /*forbid_group_world_write=*/true});
    if (!sys_file.has_value()) {
      return Result<LanPolicyConfig>::failure(sys_file.error());
    }
    if (sys_file.value().exists) {
      const auto parsed = parse_lan_policy_file_toml(sys_file.value().contents);
      if (!parsed.has_value()) {
        return Result<LanPolicyConfig>::failure(parsed.error());
      }
      sys_cfg = parsed.value();
    }
  }

  std::optional<std::filesystem::path> resolved_user_path = paths.user_policy_path;
  if (!resolved_user_path.has_value()) {
    if (const auto xdg = lookup_env(env_lookup, "XDG_CONFIG_HOME");
        xdg.has_value() && !xdg->empty()) {
      resolved_user_path = std::filesystem::path{*xdg} / "blackbird" / "lan.toml";
    } else if (const auto home = lookup_env(env_lookup, "HOME");
               home.has_value() && !home->empty()) {
      resolved_user_path =
          std::filesystem::path{*home} / ".config" / "blackbird" / "lan.toml";
    }
  }

  ParsedLanPolicyFile user_cfg{};
  if (resolved_user_path.has_value() && !resolved_user_path->empty()) {
    const std::uint32_t expected_uid =
        paths.expected_user_uid.value_or(static_cast<std::uint32_t>(::geteuid()));
    const auto user_file = read_verified_policy_file(
        *resolved_user_path,
        PolicyFileCheck{expected_uid, /*forbid_group_world_write=*/false});
    if (!user_file.has_value()) {
      return Result<LanPolicyConfig>::failure(user_file.error());
    }
    if (user_file.value().exists) {
      const auto parsed = parse_lan_policy_file_toml(user_file.value().contents);
      if (!parsed.has_value()) {
        return Result<LanPolicyConfig>::failure(parsed.error());
      }
      user_cfg = parsed.value();
    }
  }

  const bool env_disabled = env_kill_switch_active(env_lookup, "MP_DISABLE_LAN") ||
                            env_kill_switch_active(env_lookup, "BLACKBIRD_DISABLE_LAN");

  LanPolicyConfig effective{};
  effective.disabled = sys_cfg.disabled || user_cfg.disabled || env_disabled;
  effective.require_pin = sys_cfg.require_pin || user_cfg.require_pin;
  effective.require_local_auth =
      sys_cfg.require_local_auth || user_cfg.require_local_auth;
  effective.idle_timeout_sec =
      resolve_policy_timeout({sys_cfg.idle_timeout_sec, user_cfg.idle_timeout_sec,
                              kDefaultLanIdleTimeoutSec, kMaxLanIdleTimeoutSec});
  effective.scan_timeout_sec =
      resolve_policy_timeout({sys_cfg.scan_timeout_sec, user_cfg.scan_timeout_sec,
                              kDefaultLanScanTimeoutSec, kMaxLanScanTimeoutSec});
  return Result<LanPolicyConfig>::success(effective);
}

// ---------------------------------------------------------------------------
// 3. Local-Only LAN Identity & Canonical Safety Number
// ---------------------------------------------------------------------------

bool is_valid_lan_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > kLanMaxNameBytes) {
    return false;
  }
  if (name.front() == ' ' || name.back() == ' ') {
    return false;
  }
  for (const char ch : name) {
    if (!is_ascii_printable(ch)) {
      return false;
    }
  }
  return true;
}

std::string sanitize_lan_display_name(std::string_view raw) {
  std::string out;
  out.reserve(std::min(raw.size(), kLanMaxNameBytes));
  for (const char ch : raw) {
    if (is_ascii_printable(ch)) {
      out.push_back(ch);
    }
  }
  while (!out.empty() && out.front() == ' ') {
    out.erase(out.begin());
  }
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  if (out.size() > kLanMaxNameBytes) {
    out.resize(kLanMaxNameBytes);
    while (!out.empty() && out.back() == ' ') {
      out.pop_back();
    }
  }
  if (out.empty()) {
    return "lan-player";
  }
  return out;
}

Result<std::string> compute_lan_safety_number(std::uint64_t account_id,
                                              const mp::Ed25519PubKey &pubkey) {
  if (account_id > mp::kMaxSafeId) {
    return fail<std::string>(ErrorCode::invalid_range, LanError::invalid_pubkey);
  }
  if (account_id > 0U) {
    const auto acct = mp::AccountId::create(account_id);
    if (!acct.has_value()) {
      return Result<std::string>::failure(acct.error());
    }
    return mp::compute_safety_number(acct.value(), pubkey);
  }

  // Exact same algorithm as mp::compute_safety_number in src/mp_protocol.cpp
  // with account_id = 0u64 in little-endian.
  if (const auto valid = mp::validate_ed25519_pubkey_strict(pubkey);
      !valid.has_value()) {
    return Result<std::string>::failure(valid.error());
  }

  static constexpr std::string_view kDomain = "mp-safety-v1:";
  static_assert(kDomain.size() == 13U);

  std::array<std::uint8_t, kDomain.size() + 8U + 32U> preimage{};
  static_assert(preimage.size() == 53U);
  std::memcpy(preimage.data(), kDomain.data(), kDomain.size());
  // Bytes [13..21) remain zero (u64(0) LE).
  std::memcpy(preimage.data() + kDomain.size() + 8U, pubkey.data(), pubkey.size());

  const auto digest = mp::sha256(preimage);
  if (!digest.has_value()) {
    return Result<std::string>::failure(digest.error());
  }

  static constexpr std::string_view kCrockfordBase32 =
      "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  static_assert(kCrockfordBase32.size() == 32U);

  std::string out;
  out.reserve(mp::kSafetyNumberFormattedLength);
  for (std::size_t chunk = 0U; chunk < 4U; ++chunk) {
    const std::size_t base = chunk * 5U;
    std::uint64_t bits = 0U;
    for (std::size_t byte_idx = 0U; byte_idx < 5U; ++byte_idx) {
      bits = (bits << 8U) | static_cast<std::uint64_t>(digest.value()[base + byte_idx]);
    }
    for (std::size_t sym = 0U; sym < 8U; ++sym) {
      if (!out.empty() && (((chunk * 8U) + sym) % 4U) == 0U) {
        out.push_back('-');
      }
      const std::size_t shift = (7U - sym) * 5U;
      const auto index = static_cast<std::size_t>((bits >> shift) & 0x1fU);
      out.push_back(kCrockfordBase32[index]);
    }
  }
  return Result<std::string>::success(std::move(out));
}

Result<mp::Ed25519SigningKey> LanIdentity::signing_key() const {
  return mp::Ed25519SigningKey::from_seed(signing_seed.bytes());
}

Result<LanIdentity> load_or_create_lan_identity(const LanIdentityRequest &request) {
  // 1. Prefer existing online MpIdentityStore when present and registered.
  if (request.online_state_dir.has_value() && !request.online_state_dir->empty()) {
    const auto online = mp::MpIdentityStore::open_existing(*request.online_state_dir);
    if (online.has_value()) {
      const auto &st = online.value().state();
      if (st.account_id.has_value()) {
        const mp::CleansedSeed chosen_seed =
            st.root_seed.has_value() ? *st.root_seed : st.device_seed;
        const auto signing_key = mp::Ed25519SigningKey::from_seed(chosen_seed.bytes());
        if (!signing_key.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        const auto pk = signing_key.value().public_key();
        const auto sn = compute_lan_safety_number(st.account_id->value(), pk);
        if (!sn.has_value()) {
          return Result<LanIdentity>::failure(sn.error());
        }
        const std::string display =
            !st.handle.empty()
                ? sanitize_lan_display_name(st.handle)
                : sanitize_lan_display_name(request.preferred_display_name);
        return Result<LanIdentity>::success(LanIdentity{
            st.account_id->value(),
            true,
            display,
            pk,
            chosen_seed,
            sn.value(),
        });
      }
    } else {
      const auto err = mp::mp_client_error_of(online.error());
      if (err == mp::MpClientError::keystore_symlink_rejected) {
        return fail<LanIdentity>(ErrorCode::io, LanError::identity_symlink_rejected);
      }
      if (err == mp::MpClientError::keystore_insecure_permissions) {
        return fail<LanIdentity>(ErrorCode::io,
                                 LanError::identity_insecure_permissions);
      }
      // Missing or uninitialized online store falls through to local-only LAN identity.
    }
  }

  // 2. Local-only LAN identity in lan_state_dir / "identity.json" (0600, O_NOFOLLOW).
  auto dir_fd_res = open_lan_identity_dir(request.lan_state_dir);
  if (!dir_fd_res.has_value()) {
    return Result<LanIdentity>::failure(dir_fd_res.error());
  }
  ScopedFd dir_fd = std::move(dir_fd_res).value();

  static constexpr const char *kLanIdentityFile = "identity.json";
  static constexpr std::size_t kMaxLanIdentityFileBytes = 16U * 1024U;

  auto file_res =
      read_secret_file_0600(dir_fd.get(), kLanIdentityFile, kMaxLanIdentityFileBytes);
  if (!file_res.has_value()) {
    return Result<LanIdentity>::failure(file_res.error());
  }
  CleanseVectorGuard file_bytes_guard{file_res.value().bytes};

  if (file_res.value().exists) {
    const std::string_view text{
        reinterpret_cast<const char *>(file_res.value().bytes.data()),
        file_res.value().bytes.size()};
    if (!is_valid_utf8_text(text)) {
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }

    // Parse flat identity.json directly so seed_hex is decoded straight from the
    // cleansed file buffer into a cleansed stack seed and NEVER enters Value or
    // leaves an un-cleansed heap std::string copy behind.
    auto skip_json_ws = [](std::string_view s, std::size_t &idx) noexcept {
      while (idx < s.size() &&
             (s[idx] == ' ' || s[idx] == '\t' || s[idx] == '\r' || s[idx] == '\n')) {
        ++idx;
      }
    };
    auto scan_json_string = [](std::string_view s,
                               std::size_t &idx) -> std::optional<std::string_view> {
      if (idx >= s.size() || s[idx] != '"') {
        return std::nullopt;
      }
      const std::size_t start = idx++;
      while (idx < s.size()) {
        const char ch = s[idx++];
        if (ch == '"') {
          return s.substr(start, idx - start);
        }
        if (ch == '\\') {
          if (idx >= s.size()) {
            return std::nullopt;
          }
          ++idx;
        } else if (static_cast<std::uint8_t>(ch) < 0x20U) {
          return std::nullopt;
        }
      }
      return std::nullopt;
    };
    auto scan_json_uint = [](std::string_view s,
                             std::size_t &idx) -> std::optional<std::string_view> {
      const std::size_t start = idx;
      while (idx < s.size() && s[idx] >= '0' && s[idx] <= '9') {
        ++idx;
      }
      if (idx == start) {
        return std::nullopt;
      }
      return s.substr(start, idx - start);
    };

    std::size_t pos = 0U;
    skip_json_ws(text, pos);
    if (pos >= text.size() || text[pos] != '{') {
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }
    ++pos;
    skip_json_ws(text, pos);

    std::set<std::string> seen_keys;
    std::optional<std::uint64_t> version;
    std::optional<std::uint64_t> account_id;
    std::optional<std::string> display_name;
    std::optional<mp::CleansedSeed> loaded_seed;
    std::optional<mp::Ed25519PubKey> declared_pk;

    if (pos < text.size() && text[pos] == '}') {
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }
    for (;;) {
      skip_json_ws(text, pos);
      const auto key_token = scan_json_string(text, pos);
      if (!key_token.has_value()) {
        return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
      }
      const auto key_val = parse_json(*key_token, ValueLimits{256U, 8U, 2U});
      if (!key_val.has_value()) {
        return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
      }
      const auto *key_str = std::get_if<std::string>(&key_val.value().value());
      if (key_str == nullptr || !seen_keys.insert(*key_str).second) {
        return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
      }

      skip_json_ws(text, pos);
      if (pos >= text.size() || text[pos] != ':') {
        return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
      }
      ++pos;
      skip_json_ws(text, pos);

      if (*key_str == "version" || *key_str == "account_id") {
        const auto num_tok = scan_json_uint(text, pos);
        if (!num_tok.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        const auto parsed_num = parse_json(*num_tok, ValueLimits{64U, 8U, 2U});
        if (!parsed_num.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        const auto u = field_as_u64(parsed_num.value(), LanError::identity_corrupt);
        if (!u.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        if (*key_str == "version") {
          version = u.value();
        } else {
          account_id = u.value();
        }
      } else if (*key_str == "display_name") {
        const auto str_tok = scan_json_string(text, pos);
        if (!str_tok.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        const auto parsed_str = parse_json(*str_tok, ValueLimits{512U, 8U, 2U});
        if (!parsed_str.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        const auto *s = std::get_if<std::string>(&parsed_str.value().value());
        if (s == nullptr || !is_valid_lan_name(*s)) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        display_name = *s;
      } else if (*key_str == "seed_hex") {
        const auto str_tok = scan_json_string(text, pos);
        if (!str_tok.has_value() || str_tok->size() != 66U) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        auto seed_bytes = parse_exact_hex_lower<32U>(str_tok->substr(1U, 64U));
        if (!seed_bytes.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        CleanseArrayGuard seed_bytes_guard{*seed_bytes};
        loaded_seed = mp::CleansedSeed{*seed_bytes};
      } else if (*key_str == "public_key_hex") {
        const auto str_tok = scan_json_string(text, pos);
        if (!str_tok.has_value() || str_tok->size() != 66U) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        const auto pk_bytes = parse_exact_hex_lower<32U>(str_tok->substr(1U, 64U));
        if (!pk_bytes.has_value()) {
          return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
        }
        declared_pk = *pk_bytes;
      } else {
        return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
      }

      skip_json_ws(text, pos);
      if (pos >= text.size()) {
        return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
      }
      if (text[pos] == ',') {
        ++pos;
        continue;
      }
      if (text[pos] == '}') {
        ++pos;
        break;
      }
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }
    skip_json_ws(text, pos);
    if (pos != text.size() || !version.has_value() || *version != 1U ||
        !account_id.has_value() || *account_id != 0U || !display_name.has_value() ||
        !loaded_seed.has_value()) {
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }

    const auto signing_key = mp::Ed25519SigningKey::from_seed(loaded_seed->bytes());
    if (!signing_key.has_value()) {
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }
    const auto pk = signing_key.value().public_key();
    if (declared_pk.has_value() && *declared_pk != pk) {
      return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_corrupt);
    }

    const auto sn = compute_lan_safety_number(0U, pk);
    if (!sn.has_value()) {
      return Result<LanIdentity>::failure(sn.error());
    }
    return Result<LanIdentity>::success(LanIdentity{
        0U,
        false,
        std::move(*display_name),
        pk,
        std::move(*loaded_seed),
        sn.value(),
    });
  }

  // Create fresh local-only Ed25519 LAN identity.
  auto seed_res = mp::CleansedSeed::generate();
  if (!seed_res.has_value()) {
    return Result<LanIdentity>::failure(seed_res.error());
  }
  mp::CleansedSeed seed = std::move(seed_res).value();
  const auto signing_key = mp::Ed25519SigningKey::from_seed(seed.bytes());
  if (!signing_key.has_value()) {
    return Result<LanIdentity>::failure(signing_key.error());
  }
  const auto pk = signing_key.value().public_key();
  const auto sn = compute_lan_safety_number(0U, pk);
  if (!sn.has_value()) {
    return Result<LanIdentity>::failure(sn.error());
  }
  const std::string display = sanitize_lan_display_name(request.preferred_display_name);

  std::string seed_hex = mp::hex_lower(seed.bytes());
  CleanseStringGuard seed_hex_guard{seed_hex};
  const std::string pk_hex = mp::hex_lower(pk);

  // Serialize JSON manually into a cleansed string so seed_hex does not linger in
  // shared Value storage.
  Value::Object display_wrap;
  display_wrap.emplace_back("d", Value{display});
  const auto escaped_wrap = dump_json(Value::object(std::move(display_wrap)));
  if (!escaped_wrap.has_value() || escaped_wrap.value().size() < 7U) {
    return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_io_failed);
  }
  // escaped_wrap is {"d":"<escaped>"}
  const std::size_t colon = escaped_wrap.value().find(':');
  if (colon == std::string::npos || escaped_wrap.value().back() != '}') {
    return fail<LanIdentity>(ErrorCode::corrupt, LanError::identity_io_failed);
  }
  const std::string_view quoted_display = std::string_view{escaped_wrap.value()}.substr(
      colon + 1U, escaped_wrap.value().size() - colon - 2U);

  std::string json;
  CleanseStringGuard json_guard{json};
  json.reserve(256U);
  json.append("{\"version\":1,\"account_id\":0,\"display_name\":");
  json.append(quoted_display);
  json.append(",\"seed_hex\":\"");
  json.append(seed_hex);
  json.append("\",\"public_key_hex\":\"");
  json.append(pk_hex);
  json.append("\"}\n");

  const auto *raw_ptr = reinterpret_cast<const std::uint8_t *>(json.data());
  if (const auto written = write_secret_file_atomic_0600(
          dir_fd.get(), kLanIdentityFile,
          std::span<const std::uint8_t>{raw_ptr, json.size()});
      !written.has_value()) {
    return Result<LanIdentity>::failure(written.error());
  }

  return Result<LanIdentity>::success(LanIdentity{
      0U,
      false,
      display,
      pk,
      std::move(seed),
      sn.value(),
  });
}

// ---------------------------------------------------------------------------
// 4. Mandate #6 Local OS Presence Guard
// ---------------------------------------------------------------------------

Result<void> verify_local_os_presence(const LocalAuthOptions &options) {
  if (options.reason.empty() || options.reason.size() > 256U ||
      !is_valid_utf8_text(options.reason) ||
      contains_disallowed_pin_codepoint(options.reason)) {
    return fail_void(ErrorCode::invalid_identity, LanError::local_auth_failed);
  }

  if (options.prompt_override) {
    return options.prompt_override(options.reason);
  }

#ifdef __APPLE__
  if (!is_headless_ssh_session(options.env_lookup)) {
    const auto la = verify_via_macos_local_auth(options.reason);
    if (la.has_value()) {
      return la;
    }
    if (lan_error_of(la.error()) != LanError::local_auth_unavailable ||
        !options.allow_sudo_fallback) {
      return la;
    }
  }
  if (!options.allow_sudo_fallback) {
    return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
  }
  return verify_via_sudo();
#else
  if (!options.allow_sudo_fallback) {
    return fail_void(ErrorCode::unsupported, LanError::local_auth_unavailable);
  }
  return verify_via_sudo();
#endif
}

// ---------------------------------------------------------------------------
// 5. In-TLS Handshake Framing & PIN Rate Limiter
// ---------------------------------------------------------------------------

LanHandshakeKind lan_handshake_kind(const LanHandshakeMessage &message) noexcept {
  if (std::holds_alternative<LanHelloMessage>(message)) {
    return LanHandshakeKind::lan_hello;
  }
  if (std::holds_alternative<LanJoinMessage>(message)) {
    return LanHandshakeKind::lan_join;
  }
  if (std::holds_alternative<LanWelcomeMessage>(message)) {
    return LanHandshakeKind::lan_welcome;
  }
  return LanHandshakeKind::lan_roster;
}

bool is_lan_handshake_frame(std::span<const std::uint8_t> bytes) noexcept {
  if (bytes.size() < kLanHandshakeHeaderBytes) {
    return false;
  }
  const std::uint8_t k = bytes[1];
  return bytes[0] == kLanHandshakeVersion && k >= 0x10U && k <= 0x13U;
}

Result<std::vector<std::uint8_t>>
encode_lan_handshake_frame(const LanHandshakeMessage &message) {
  Value::Object obj;
  LanHandshakeKind kind = LanHandshakeKind::lan_hello;

  if (const auto *hello = std::get_if<LanHelloMessage>(&message)) {
    kind = LanHandshakeKind::lan_hello;
    if (!parse_lan_party_id_hex(hello->lan_party_id).has_value() ||
        !is_valid_lan_name(hello->lobby_name) || !is_valid_lan_name(hello->host_name) ||
        hello->host_account_id > mp::kMaxSafeId || hello->max_members == 0U ||
        hello->max_members > kLanMaxMembers) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_identity,
                                             LanError::frame_invalid_field);
    }
    if (!mp::validate_ed25519_pubkey_strict(hello->host_pubkey).has_value()) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_identity,
                                             LanError::invalid_pubkey);
    }
    obj.emplace_back("lan_party_id", Value{hello->lan_party_id});
    obj.emplace_back("lobby_name", Value{hello->lobby_name});
    obj.emplace_back("host_name", Value{hello->host_name});
    obj.emplace_back("host_account_id", Value{Number{hello->host_account_id}});
    obj.emplace_back("host_pubkey", Value{mp::hex_lower(hello->host_pubkey)});
    obj.emplace_back("require_pin", Value{hello->require_pin});
    obj.emplace_back("host_nonce", Value{mp::hex_lower(hello->host_nonce)});
    obj.emplace_back("max_members",
                     Value{Number{static_cast<std::uint64_t>(hello->max_members)}});
  } else if (const auto *join = std::get_if<LanJoinMessage>(&message)) {
    kind = LanHandshakeKind::lan_join;
    if (!parse_lan_party_id_hex(join->lan_party_id).has_value() ||
        !is_valid_lan_name(join->display_name) || join->account_id > mp::kMaxSafeId) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_identity,
                                             LanError::frame_invalid_field);
    }
    obj.emplace_back("lan_party_id", Value{join->lan_party_id});
    obj.emplace_back("display_name", Value{join->display_name});
    obj.emplace_back("account_id", Value{Number{join->account_id}});
    if (join->pin_proof.has_value()) {
      obj.emplace_back("pin_proof", Value{mp::hex_lower(*join->pin_proof)});
    }
  } else if (const auto *welcome = std::get_if<LanWelcomeMessage>(&message)) {
    kind = LanHandshakeKind::lan_welcome;
    if (!parse_lan_party_id_hex(welcome->lan_party_id).has_value() ||
        !is_valid_reason_text(welcome->reason) ||
        welcome->roster_epoch > mp::kMaxSafeId) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_identity,
                                             LanError::frame_invalid_field);
    }
    if (!welcome->accepted && !welcome->members.empty()) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_identity,
                                             LanError::frame_invalid_field);
    }
    if (const auto ok = validate_member_list(welcome->members, !welcome->accepted);
        !ok.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ok.error());
    }
    Value::Array members_arr;
    members_arr.reserve(welcome->members.size());
    for (const auto &m : welcome->members) {
      members_arr.push_back(member_to_json(m));
    }
    obj.emplace_back("lan_party_id", Value{welcome->lan_party_id});
    obj.emplace_back("accepted", Value{welcome->accepted});
    obj.emplace_back("reason", Value{welcome->reason});
    obj.emplace_back("roster_epoch", Value{Number{welcome->roster_epoch}});
    obj.emplace_back("members", Value{std::move(members_arr)});
  } else {
    const auto &roster = std::get<LanRosterMessage>(message);
    kind = LanHandshakeKind::lan_roster;
    if (!parse_lan_party_id_hex(roster.lan_party_id).has_value() ||
        roster.roster_epoch > mp::kMaxSafeId) {
      return fail<std::vector<std::uint8_t>>(ErrorCode::invalid_identity,
                                             LanError::frame_invalid_field);
    }
    if (const auto ok = validate_member_list(roster.members, /*allow_empty=*/false);
        !ok.has_value()) {
      return Result<std::vector<std::uint8_t>>::failure(ok.error());
    }
    Value::Array members_arr;
    members_arr.reserve(roster.members.size());
    for (const auto &m : roster.members) {
      members_arr.push_back(member_to_json(m));
    }
    obj.emplace_back("lan_party_id", Value{roster.lan_party_id});
    obj.emplace_back("roster_epoch", Value{Number{roster.roster_epoch}});
    obj.emplace_back("locked", Value{roster.locked});
    obj.emplace_back("members", Value{std::move(members_arr)});
  }

  const auto json_res = dump_json(Value::object(std::move(obj)),
                                  ValueLimits{kLanHandshakeMaxFrameBytes, 1024U, 16U});
  if (!json_res.has_value()) {
    return fail<std::vector<std::uint8_t>>(ErrorCode::corrupt,
                                           LanError::frame_invalid_json);
  }
  const std::string &payload = json_res.value();
  if (kLanHandshakeHeaderBytes + payload.size() > kLanHandshakeMaxFrameBytes) {
    return fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                           LanError::frame_too_large);
  }

  std::vector<std::uint8_t> frame;
  frame.reserve(kLanHandshakeHeaderBytes + payload.size());
  frame.push_back(kLanHandshakeVersion);
  frame.push_back(static_cast<std::uint8_t>(kind));
  frame.push_back(0x00U);
  frame.push_back(0x00U);
  for (const char ch : payload) {
    frame.push_back(static_cast<std::uint8_t>(ch));
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(frame));
}

Result<LanHandshakeMessage>
decode_lan_handshake_frame(P2pLane expected_lane, std::span<const std::uint8_t> bytes) {
  if (expected_lane != P2pLane::control) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_lane_mismatch);
  }
  if (bytes.size() < kLanHandshakeHeaderBytes) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_truncated);
  }
  if (bytes.size() > kLanHandshakeMaxFrameBytes) {
    return fail<LanHandshakeMessage>(ErrorCode::capacity, LanError::frame_too_large);
  }
  if (bytes[0] != kLanHandshakeVersion) {
    return fail<LanHandshakeMessage>(ErrorCode::unsupported,
                                     LanError::frame_unsupported_version);
  }
  const std::uint8_t raw_kind = bytes[1];
  if (raw_kind < 0x10U || raw_kind > 0x13U) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_unknown_kind);
  }
  if (bytes[2] != 0x00U || bytes[3] != 0x00U) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                     LanError::frame_non_zero_reserved);
  }

  const auto payload_bytes = bytes.subspan(kLanHandshakeHeaderBytes);
  if (payload_bytes.empty()) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_truncated);
  }
  if (!is_valid_utf8_bytes(payload_bytes)) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_invalid_utf8);
  }
  const std::string_view payload_text{
      reinterpret_cast<const char *>(payload_bytes.data()), payload_bytes.size()};
  const auto parsed =
      parse_json(payload_text, ValueLimits{kLanHandshakeMaxFrameBytes, 1024U, 16U});
  if (!parsed.has_value()) {
    return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_invalid_json);
  }
  const auto obj_res = expect_json_object(parsed.value(), LanError::frame_invalid_json);
  if (!obj_res.has_value()) {
    return Result<LanHandshakeMessage>::failure(obj_res.error());
  }
  const auto &obj = *obj_res.value();

  switch (static_cast<LanHandshakeKind>(raw_kind)) {
  case LanHandshakeKind::lan_hello: {
    static constexpr std::array<std::string_view, 8> kAllowed = {
        "lan_party_id", "lobby_name",  "host_name",  "host_account_id",
        "host_pubkey",  "require_pin", "host_nonce", "max_members"};
    if (const auto ok =
            check_allowed_unique_keys(obj, kAllowed, LanError::frame_invalid_field);
        !ok.has_value()) {
      return Result<LanHandshakeMessage>::failure(ok.error());
    }
    const auto party_id =
        get_required_string(obj, "lan_party_id", LanError::frame_invalid_field);
    const auto lobby_name =
        get_required_string(obj, "lobby_name", LanError::frame_invalid_field);
    const auto host_name =
        get_required_string(obj, "host_name", LanError::frame_invalid_field);
    const auto host_acct =
        get_required_safe_u64(obj, "host_account_id", LanError::frame_invalid_field);
    const auto host_pk_hex =
        get_required_string(obj, "host_pubkey", LanError::frame_invalid_field);
    const auto req_pin =
        get_required_bool(obj, "require_pin", LanError::frame_invalid_field);
    const auto nonce_hex =
        get_required_string(obj, "host_nonce", LanError::frame_invalid_field);
    const auto max_mem =
        get_required_safe_u64(obj, "max_members", LanError::frame_invalid_field);
    if (!party_id.has_value() || !lobby_name.has_value() || !host_name.has_value() ||
        !host_acct.has_value() || !host_pk_hex.has_value() || !req_pin.has_value() ||
        !nonce_hex.has_value() || !max_mem.has_value()) {
      return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                       LanError::frame_invalid_field);
    }
    const auto host_pk = parse_exact_hex_lower<32U>(host_pk_hex.value());
    const auto nonce = parse_exact_hex_lower<32U>(nonce_hex.value());
    if (!parse_lan_party_id_hex(party_id.value()).has_value() ||
        !is_valid_lan_name(lobby_name.value()) ||
        !is_valid_lan_name(host_name.value()) || !host_pk.has_value() ||
        !nonce.has_value() || max_mem.value() == 0U ||
        max_mem.value() > kLanMaxMembers) {
      return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                       LanError::frame_invalid_field);
    }
    if (!mp::validate_ed25519_pubkey_strict(*host_pk).has_value()) {
      return fail<LanHandshakeMessage>(ErrorCode::invalid_identity,
                                       LanError::invalid_pubkey);
    }
    return Result<LanHandshakeMessage>::success(LanHelloMessage{
        party_id.value(),
        lobby_name.value(),
        host_name.value(),
        host_acct.value(),
        *host_pk,
        req_pin.value(),
        *nonce,
        static_cast<std::uint8_t>(max_mem.value()),
    });
  }

  case LanHandshakeKind::lan_join: {
    static constexpr std::array<std::string_view, 4> kAllowed = {
        "lan_party_id", "display_name", "account_id", "pin_proof"};
    if (const auto ok =
            check_allowed_unique_keys(obj, kAllowed, LanError::frame_invalid_field);
        !ok.has_value()) {
      return Result<LanHandshakeMessage>::failure(ok.error());
    }
    const auto party_id =
        get_required_string(obj, "lan_party_id", LanError::frame_invalid_field);
    const auto display_name =
        get_required_string(obj, "display_name", LanError::frame_invalid_field);
    const auto account_id =
        get_required_safe_u64(obj, "account_id", LanError::frame_invalid_field);
    if (!party_id.has_value() || !display_name.has_value() || !account_id.has_value() ||
        !parse_lan_party_id_hex(party_id.value()).has_value() ||
        !is_valid_lan_name(display_name.value())) {
      return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                       LanError::frame_invalid_field);
    }
    std::optional<LanPinProof> pin_proof;
    if (const Value *proof_field = find_field(obj, "pin_proof");
        proof_field != nullptr &&
        !std::holds_alternative<std::nullptr_t>(proof_field->value())) {
      const auto *proof_hex = std::get_if<std::string>(&proof_field->value());
      if (proof_hex == nullptr) {
        return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                         LanError::frame_invalid_field);
      }
      const auto parsed_proof = parse_exact_hex_lower<kLanPinProofBytes>(*proof_hex);
      if (!parsed_proof.has_value()) {
        return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                         LanError::frame_invalid_field);
      }
      pin_proof = *parsed_proof;
    }
    return Result<LanHandshakeMessage>::success(LanJoinMessage{
        party_id.value(),
        display_name.value(),
        account_id.value(),
        pin_proof,
    });
  }

  case LanHandshakeKind::lan_welcome: {
    static constexpr std::array<std::string_view, 5> kAllowed = {
        "lan_party_id", "accepted", "reason", "roster_epoch", "members"};
    if (const auto ok =
            check_allowed_unique_keys(obj, kAllowed, LanError::frame_invalid_field);
        !ok.has_value()) {
      return Result<LanHandshakeMessage>::failure(ok.error());
    }
    const auto party_id =
        get_required_string(obj, "lan_party_id", LanError::frame_invalid_field);
    const auto accepted =
        get_required_bool(obj, "accepted", LanError::frame_invalid_field);
    const auto reason =
        get_required_string(obj, "reason", LanError::frame_invalid_field);
    const auto roster_epoch =
        get_required_safe_u64(obj, "roster_epoch", LanError::frame_invalid_field);
    if (!party_id.has_value() || !accepted.has_value() || !reason.has_value() ||
        !roster_epoch.has_value() ||
        !parse_lan_party_id_hex(party_id.value()).has_value() ||
        !is_valid_reason_text(reason.value())) {
      return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                       LanError::frame_invalid_field);
    }
    auto members = members_array_from_json(obj, !accepted.value());
    if (!members.has_value()) {
      return Result<LanHandshakeMessage>::failure(members.error());
    }
    if (!accepted.value() && !members.value().empty()) {
      return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                       LanError::frame_invalid_field);
    }
    return Result<LanHandshakeMessage>::success(LanWelcomeMessage{
        party_id.value(),
        accepted.value(),
        reason.value(),
        roster_epoch.value(),
        std::move(members).value(),
    });
  }

  case LanHandshakeKind::lan_roster: {
    static constexpr std::array<std::string_view, 4> kAllowed = {
        "lan_party_id", "roster_epoch", "locked", "members"};
    if (const auto ok =
            check_allowed_unique_keys(obj, kAllowed, LanError::frame_invalid_field);
        !ok.has_value()) {
      return Result<LanHandshakeMessage>::failure(ok.error());
    }
    const auto party_id =
        get_required_string(obj, "lan_party_id", LanError::frame_invalid_field);
    const auto roster_epoch =
        get_required_safe_u64(obj, "roster_epoch", LanError::frame_invalid_field);
    const auto locked = get_required_bool(obj, "locked", LanError::frame_invalid_field);
    if (!party_id.has_value() || !roster_epoch.has_value() || !locked.has_value() ||
        !parse_lan_party_id_hex(party_id.value()).has_value()) {
      return fail<LanHandshakeMessage>(ErrorCode::corrupt,
                                       LanError::frame_invalid_field);
    }
    auto members = members_array_from_json(obj, /*allow_empty=*/false);
    if (!members.has_value()) {
      return Result<LanHandshakeMessage>::failure(members.error());
    }
    return Result<LanHandshakeMessage>::success(LanRosterMessage{
        party_id.value(),
        roster_epoch.value(),
        locked.value(),
        std::move(members).value(),
    });
  }
  }
  return fail<LanHandshakeMessage>(ErrorCode::corrupt, LanError::frame_unknown_kind);
}

LanPinRateLimiter::LanPinRateLimiter(LanPinRateLimitConfig config) noexcept
    : config_(config) {
  if (config_.max_peer_failures == 0U) {
    config_.max_peer_failures = 1U;
  }
  if (config_.max_lobby_failures == 0U) {
    config_.max_lobby_failures = 1U;
  }
}

LanPinLockoutStatus LanPinRateLimiter::check(const LanPinPeerKey &peer) const noexcept {
  if (is_lobby_locked()) {
    return LanPinLockoutStatus::lobby_locked;
  }
  if (is_peer_locked(peer)) {
    return LanPinLockoutStatus::peer_locked;
  }
  return LanPinLockoutStatus::allowed;
}

LanPinLockoutStatus LanPinRateLimiter::record_failure(const LanPinPeerKey &peer) {
  if (is_lobby_locked()) {
    return LanPinLockoutStatus::lobby_locked;
  }
  if (total_failures_ < std::numeric_limits<std::uint32_t>::max()) {
    ++total_failures_;
  }
  std::uint32_t &peer_count = peer_failures_[peer];
  if (peer_count < std::numeric_limits<std::uint32_t>::max()) {
    ++peer_count;
  }
  if (is_lobby_locked()) {
    return LanPinLockoutStatus::lobby_locked;
  }
  if (peer_count >= config_.max_peer_failures) {
    return LanPinLockoutStatus::peer_locked;
  }
  return LanPinLockoutStatus::allowed;
}

void LanPinRateLimiter::record_success(const LanPinPeerKey &peer) noexcept {
  if (is_lobby_locked() || is_peer_locked(peer)) {
    return;
  }
  peer_failures_.erase(peer);
}

std::uint32_t
LanPinRateLimiter::peer_failures(const LanPinPeerKey &peer) const noexcept {
  const auto it = peer_failures_.find(peer);
  return it == peer_failures_.end() ? 0U : it->second;
}

bool LanPinRateLimiter::is_peer_locked(const LanPinPeerKey &peer) const noexcept {
  return peer_failures(peer) >= config_.max_peer_failures;
}

void LanPinRateLimiter::reset() noexcept {
  total_failures_ = 0U;
  peer_failures_.clear();
}

} // namespace blackbird::lan
