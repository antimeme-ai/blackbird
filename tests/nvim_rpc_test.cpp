#include "blackbird/nvim_rpc.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <source_location>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird;

void require(bool condition, std::string_view claim,
             std::source_location loc = std::source_location::current()) {
  if (!condition) {
    std::ostringstream out;
    out << loc.file_name() << ':' << loc.line() << ": failed requirement: " << claim;
    throw std::runtime_error(out.str());
  }
}

struct TempDir {
  std::filesystem::path root;

  TempDir() {
    std::string tmpl =
        (std::filesystem::temp_directory_path() / "bb-nvim-rpc-test-XXXXXX").string();
    char *created = ::mkdtemp(tmpl.data());
    require(created != nullptr, "mkdtemp for nvim_rpc test fixture");
    root = std::filesystem::canonical(created);
  }

  ~TempDir() {
    if (std::uncaught_exceptions() != 0) {
      std::cerr << "retained failed nvim_rpc fixture: " << root << '\n';
      return;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }
};

std::size_t count_open_fds() {
  std::size_t count = 0;
  for (int fd = 0; fd < 512; ++fd) {
    if (::fcntl(fd, F_GETFD) >= 0) {
      ++count;
    }
  }
  return count;
}

std::vector<std::uint8_t> roundtrip_encode(const MsgPackValue &value) {
  auto encoded = encode_msgpack(value);
  require(encoded.has_value(), "encode_msgpack succeeds");
  return std::move(encoded.value());
}

MsgPackValue roundtrip_decode(std::span<const std::uint8_t> bytes) {
  auto decoded = decode_msgpack(bytes);
  require(decoded.has_value(), "decode_msgpack succeeds");
  return std::move(decoded.value());
}

// ============================================================================
// 1. Exhaustive MsgPack Codec Tests (Always Runs on Every Host)
// ============================================================================

void test_msgpack_scalars_and_boundaries() {
  // nil
  {
    auto bytes = roundtrip_encode(MsgPackValue::nil());
    require(bytes.size() == 1U && bytes[0] == 0xc0U, "nil encodes to 0xc0");
    require(roundtrip_decode(bytes).is_nil(), "nil decodes back");
  }

  // bool
  {
    auto b_false = roundtrip_encode(MsgPackValue::boolean(false));
    auto b_true = roundtrip_encode(MsgPackValue::boolean(true));
    require(b_false.size() == 1U && b_false[0] == 0xc2U, "false encodes to 0xc2");
    require(b_true.size() == 1U && b_true[0] == 0xc3U, "true encodes to 0xc3");
    require(roundtrip_decode(b_false).as_bool() == false, "false decodes");
    require(roundtrip_decode(b_true).as_bool() == true, "true decodes");
  }

  // Unsigned integer wire-format boundaries
  struct UintCase {
    std::uint64_t value;
    std::uint8_t expected_tag;
    std::size_t expected_len;
  };
  const std::vector<UintCase> uint_cases = {
      {0U, 0x00U, 1U},
      {1U, 0x01U, 1U},
      {127U, 0x7fU, 1U},
      {128U, 0xccU, 2U},
      {255U, 0xccU, 2U},
      {256U, 0xcdU, 3U},
      {65535U, 0xcdU, 3U},
      {65536U, 0xceU, 5U},
      {0xffffffffULL, 0xceU, 5U},
      {0x100000000ULL, 0xcfU, 9U},
      {std::numeric_limits<std::uint64_t>::max(), 0xcfU, 9U},
  };
  for (const auto &tc : uint_cases) {
    auto bytes = roundtrip_encode(MsgPackValue::uint64(tc.value));
    require(bytes.size() == tc.expected_len, "uint encoded length matches spec");
    require(bytes[0] == tc.expected_tag, "uint encoded tag matches spec");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_uint64() == tc.value, "uint round-trips exact value");
  }

  // Signed integer wire-format boundaries
  struct IntCase {
    std::int64_t value;
    std::uint8_t expected_tag;
    std::size_t expected_len;
  };
  const std::vector<IntCase> int_cases = {
      {-1, 0xffU, 1U},
      {-32, 0xe0U, 1U},
      {-33, 0xd0U, 2U},
      {-128, 0xd0U, 2U},
      {-129, 0xd1U, 3U},
      {-32768, 0xd1U, 3U},
      {-32769, 0xd2U, 5U},
      {-2147483648LL, 0xd2U, 5U},
      {-2147483649LL, 0xd3U, 9U},
      {std::numeric_limits<std::int64_t>::min(), 0xd3U, 9U},
  };
  for (const auto &tc : int_cases) {
    auto bytes = roundtrip_encode(MsgPackValue::int64(tc.value));
    require(bytes.size() == tc.expected_len, "int encoded length matches spec");
    require(bytes[0] == tc.expected_tag, "int encoded tag matches spec");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_int64() == tc.value, "int round-trips exact value");
  }

  // Positive signed int64 encodes compactly and reads back via as_int64()
  {
    auto bytes = roundtrip_encode(MsgPackValue::int64(42));
    require(bytes.size() == 1U && bytes[0] == 42U, "positive int64 uses fixint");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_int64() == 42, "positive fixint readable as int64");
    require(decoded.as_uint64() == 42U, "positive fixint readable as uint64");
  }

  // float64 round-trip (normal, negative zero, inf, nan)
  {
    const std::vector<double> vals = {0.0,
                                      -0.0,
                                      3.141592653589793,
                                      -1e300,
                                      std::numeric_limits<double>::infinity(),
                                      -std::numeric_limits<double>::infinity()};
    for (const double v : vals) {
      auto bytes = roundtrip_encode(MsgPackValue::number(v));
      require(bytes.size() == 9U && bytes[0] == 0xcbU, "float64 encodes to 0xcb + 8B");
      auto decoded = roundtrip_decode(bytes);
      require(decoded.as_double().has_value() && *decoded.as_double() == v,
              "float64 round-trips");
    }
    auto nan_bytes = roundtrip_encode(
        MsgPackValue::number(std::numeric_limits<double>::quiet_NaN()));
    auto nan_decoded = roundtrip_decode(nan_bytes);
    require(nan_decoded.as_double().has_value() && std::isnan(*nan_decoded.as_double()),
            "float64 NaN round-trips");
  }

  // float32 direct wire decode (0xca + 4B big-endian IEEE-754)
  {
    const float sample = -12.5F;
    const auto bits = std::bit_cast<std::uint32_t>(sample);
    const std::vector<std::uint8_t> wire = {
        0xcaU,
        static_cast<std::uint8_t>((bits >> 24U) & 0xffU),
        static_cast<std::uint8_t>((bits >> 16U) & 0xffU),
        static_cast<std::uint8_t>((bits >> 8U) & 0xffU),
        static_cast<std::uint8_t>(bits & 0xffU),
    };
    auto decoded = roundtrip_decode(wire);
    require(decoded.as_double().has_value() && *decoded.as_double() == -12.5,
            "float32 decodes accurately");
  }
}

void test_msgpack_strings_bins_exts() {
  // fixstr (0, 31), str8 (32, 255), str16 (256, 70000 -> str32)
  struct StrCase {
    std::size_t len;
    std::uint8_t expected_tag;
    std::size_t header_len;
  };
  const std::vector<StrCase> str_cases = {
      {0U, 0xa0U, 1U},   {31U, 0xbfU, 1U},    {32U, 0xd9U, 2U},    {255U, 0xd9U, 2U},
      {256U, 0xdaU, 3U}, {65535U, 0xdaU, 3U}, {65536U, 0xdbU, 5U},
  };
  for (const auto &tc : str_cases) {
    std::string text(tc.len, 'k');
    auto bytes = roundtrip_encode(MsgPackValue::string(text));
    require(bytes.size() == tc.header_len + tc.len, "str total wire size");
    require(bytes[0] == tc.expected_tag, "str wire format tag");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_string() != nullptr && *decoded.as_string() == text,
            "str round-trips");
  }

  // bin8, bin16, bin32
  struct BinCase {
    std::size_t len;
    std::uint8_t expected_tag;
    std::size_t header_len;
  };
  const std::vector<BinCase> bin_cases = {
      {0U, 0xc4U, 2U},
      {255U, 0xc4U, 2U},
      {256U, 0xc5U, 3U},
      {65536U, 0xc6U, 5U},
  };
  for (const auto &tc : bin_cases) {
    MsgPackValue::Bin payload(tc.len, 0x5aU);
    auto bytes = roundtrip_encode(MsgPackValue::bin(payload));
    require(bytes.size() == tc.header_len + tc.len, "bin total wire size");
    require(bytes[0] == tc.expected_tag, "bin wire format tag");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_bin() != nullptr && *decoded.as_bin() == payload,
            "bin round-trips");
  }

  // fixext1/2/4/8/16 and ext8/16/32
  struct ExtCase {
    std::int8_t type;
    std::size_t len;
    std::uint8_t expected_tag;
  };
  const std::vector<ExtCase> ext_cases = {
      {0, 1U, 0xd4U},  {1, 2U, 0xd5U},     {2, 4U, 0xd6U},
      {-1, 8U, 0xd7U}, {-128, 16U, 0xd8U}, {7, 0U, 0xc7U},
      {7, 3U, 0xc7U},  {42, 300U, 0xc8U},  {99, 65536U, 0xc9U},
  };
  for (const auto &tc : ext_cases) {
    MsgPackValue::Bin payload(tc.len, 0xa5U);
    auto bytes = roundtrip_encode(MsgPackValue::ext(tc.type, payload));
    require(bytes[0] == tc.expected_tag, "ext wire format tag");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_ext() != nullptr, "ext decodes as ext");
    require(decoded.as_ext()->type == tc.type, "ext type preserved");
    require(decoded.as_ext()->data == payload, "ext payload preserved");
  }
}

void test_msgpack_containers_and_streaming() {
  // fixarray, array16, fixmap, map16
  {
    std::vector<MsgPackValue> items;
    for (std::uint64_t i = 0; i < 20U; ++i) {
      items.push_back(MsgPackValue::uint64(i));
    }
    auto bytes = roundtrip_encode(MsgPackValue::array(items));
    require(bytes[0] == 0xdcU, "20-element array uses array16");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_array() != nullptr && decoded.as_array()->size() == 20U,
            "array16 round-trips");
  }

  // map16 with mixed key types (string + integer keys)
  {
    std::vector<MsgPackMapEntry> entries;
    for (std::uint64_t i = 0; i < 18U; ++i) {
      entries.push_back(
          MsgPackMapEntry{MsgPackValue::string("k" + std::to_string(i)),
                          MsgPackValue::int64(-static_cast<std::int64_t>(i))});
    }
    auto bytes = roundtrip_encode(MsgPackValue::map(entries));
    require(bytes[0] == 0xdeU, "18-entry map uses map16");
    auto decoded = roundtrip_decode(bytes);
    require(decoded.as_map() != nullptr && decoded.as_map()->size() == 18U,
            "map16 round-trips");
    const auto *k5 = decoded.as_map()->find("k5");
    require(k5 != nullptr && k5->as_int64() == -5, "map find works");
  }

  // array32 and map32 direct wire decode
  {
    const std::vector<std::uint8_t> arr32 = {0xddU, 0x00U, 0x00U, 0x00U,
                                             0x02U, 0x01U, 0x02U};
    auto dec_arr = roundtrip_decode(arr32);
    require(dec_arr.as_array() != nullptr && dec_arr.as_array()->size() == 2U,
            "array32 decodes");

    const std::vector<std::uint8_t> map32 = {0xdfU, 0x00U, 0x00U, 0x00U,
                                             0x01U, 0xa1U, 'a',   0x2aU};
    auto dec_map = roundtrip_decode(map32);
    require(dec_map.as_map() != nullptr && dec_map.as_map()->size() == 1U,
            "map32 decodes");
    require(dec_map.as_map()->find("a")->as_uint64() == 42U, "map32 entry decodes");
  }

  // Streaming decode_msgpack_next over concatenated frames + trailing rejection
  {
    auto f1 = roundtrip_encode(MsgPackValue::string("hello"));
    auto f2 = roundtrip_encode(MsgPackValue::uint64(999U));
    std::vector<std::uint8_t> stream = f1;
    stream.insert(stream.end(), f2.begin(), f2.end());

    // Single-value decode_msgpack must reject trailing bytes.
    auto bad = decode_msgpack(stream);
    require(!bad.has_value() &&
                nvim_rpc_error_of(bad.error()) == NvimRpcError::msgpack_trailing_bytes,
            "decode_msgpack rejects trailing bytes");

    // Streaming decode_msgpack_next consumes frame by frame.
    auto step1 = decode_msgpack_next(stream);
    require(step1.has_value() && step1.value().consumed == f1.size(),
            "first frame decoded");
    require(*step1.value().value.as_string() == "hello", "first frame value");

    auto tail = std::span<const std::uint8_t>{stream}.subspan(step1.value().consumed);
    auto step2 = decode_msgpack_next(tail);
    require(step2.has_value() && step2.value().consumed == f2.size(),
            "second frame decoded");
    require(step2.value().value.as_uint64() == 999U, "second frame value");
  }
}

void test_msgpack_fuzz_hardening_and_bounds() {
  // 1. Reserved 0xc1 byte rejected as corrupt
  {
    const std::vector<std::uint8_t> bad = {0xc1U};
    auto res = decode_msgpack(bad);
    require(!res.has_value() &&
                nvim_rpc_error_of(res.error()) == NvimRpcError::msgpack_invalid_format,
            "0xc1 rejected");
  }

  // 2. Empty input rejected as incomplete
  {
    const std::vector<std::uint8_t> empty;
    auto res = decode_msgpack(empty);
    require(!res.has_value() &&
                nvim_rpc_error_of(res.error()) == NvimRpcError::msgpack_incomplete,
            "empty buffer rejected as incomplete");
  }

  // 3. Every prefix of a complex nested MsgPack message fails cleanly as incomplete
  {
    std::vector<MsgPackMapEntry> map_entries;
    map_entries.push_back(MsgPackMapEntry{
        MsgPackValue::string("bin"), MsgPackValue::bin({0x01U, 0x02U, 0x03U, 0x04U})});
    map_entries.push_back(
        MsgPackMapEntry{MsgPackValue::string("ext"),
                        MsgPackValue::ext(2, {0xaaU, 0xbbU, 0xccU, 0xddU})});
    map_entries.push_back(
        MsgPackMapEntry{MsgPackValue::string("num"), MsgPackValue::number(1.25)});
    std::vector<MsgPackValue> frame = {
        MsgPackValue::uint64(1U),
        MsgPackValue::uint64(77U),
        MsgPackValue::nil(),
        MsgPackValue::map(std::move(map_entries)),
    };
    auto wire = roundtrip_encode(MsgPackValue::array(std::move(frame)));
    for (std::size_t trunc = 0; trunc < wire.size(); ++trunc) {
      auto res = decode_msgpack(std::span<const std::uint8_t>{wire.data(), trunc});
      require(!res.has_value() &&
                  nvim_rpc_error_of(res.error()) == NvimRpcError::msgpack_incomplete,
              "truncated prefix fails cleanly as incomplete");
    }
  }

  // 4. Max-depth = 32 accepted; depth = 33 rejected cleanly without stack overflow
  {
    std::vector<std::uint8_t> depth32(32U, 0x91U); // 32 nested 1-element fixarrays
    depth32.push_back(0xc0U);                      // leaf nil
    auto ok32 = decode_msgpack(depth32);
    require(ok32.has_value(), "depth 32 accepted");

    std::vector<std::uint8_t> depth33(33U, 0x91U); // 33 nested 1-element fixarrays
    depth33.push_back(0xc0U);
    auto bad33 = decode_msgpack(depth33);
    require(!bad33.has_value() && nvim_rpc_error_of(bad33.error()) ==
                                      NvimRpcError::msgpack_depth_exceeded,
            "depth 33 rejected with msgpack_depth_exceeded");

    // 10,000 nested arrays also rejected instantly without stack blowup
    std::vector<std::uint8_t> depth10k(10000U, 0x91U);
    depth10k.push_back(0xc0U);
    auto bad10k = decode_msgpack(depth10k);
    require(!bad10k.has_value() && nvim_rpc_error_of(bad10k.error()) ==
                                       NvimRpcError::msgpack_depth_exceeded,
            "depth 10000 rejected cleanly");
  }

  // 5. 4 GiB length-bombs rejected immediately with capacity error (zero OOM!)
  {
    const std::vector<std::vector<std::uint8_t>> byte_bombs = {
        {0xdbU, 0xffU, 0xffU, 0xffU, 0xffU},        // str32 4GiB
        {0xc6U, 0xffU, 0xffU, 0xffU, 0xffU},        // bin32 4GiB
        {0xc9U, 0xffU, 0xffU, 0xffU, 0xffU, 0x01U}, // ext32 4GiB
    };
    for (const auto &bomb : byte_bombs) {
      auto res = decode_msgpack(bomb);
      require(!res.has_value() && nvim_rpc_error_of(res.error()) ==
                                      NvimRpcError::msgpack_bytes_exceeded,
              "4GiB str/bin/ext length bomb rejected immediately");
    }

    const std::vector<std::vector<std::uint8_t>> elem_bombs = {
        {0xddU, 0xffU, 0xffU, 0xffU, 0xffU}, // array32 4G elements
        {0xdfU, 0xffU, 0xffU, 0xffU, 0xffU}, // map32 4G pairs
    };
    for (const auto &bomb : elem_bombs) {
      auto res = decode_msgpack(bomb);
      require(!res.has_value() && nvim_rpc_error_of(res.error()) ==
                                      NvimRpcError::msgpack_elements_exceeded,
              "4G array/map element bomb rejected immediately");
    }
  }

  // 6. Custom max_elements limit enforced cleanly
  {
    MsgPackLimits tight;
    tight.max_elements = 5U;
    // 6-element fixarray (1 container + 6 items = 7 > 5)
    const std::vector<std::uint8_t> arr = {0x96U, 1U, 2U, 3U, 4U, 5U, 6U};
    auto res = decode_msgpack(arr, tight);
    require(!res.has_value() && nvim_rpc_error_of(res.error()) ==
                                    NvimRpcError::msgpack_elements_exceeded,
            "max_elements bound enforced");
  }

  // 7. Zero max_bytes limit fails cleanly without integer underflow (including ext)
  {
    MsgPackLimits zero_bytes;
    zero_bytes.max_bytes = 0U;
    const std::vector<std::uint8_t> ext1 = {0xd4U, 0x01U, 0x2aU};
    auto res = decode_msgpack(ext1, zero_bytes);
    require(!res.has_value() &&
                nvim_rpc_error_of(res.error()) == NvimRpcError::msgpack_bytes_exceeded,
            "max_bytes=0 rejects ext cleanly without underflow");
  }

  // 8. Encoder enforces depth, bytes, and elements limits
  {
    MsgPackValue deep = MsgPackValue::nil();
    for (int i = 0; i < 33; ++i) {
      std::vector<MsgPackValue> wrap;
      wrap.push_back(std::move(deep));
      deep = MsgPackValue::array(std::move(wrap));
    }
    auto enc_deep = encode_msgpack(deep);
    require(!enc_deep.has_value() && nvim_rpc_error_of(enc_deep.error()) ==
                                         NvimRpcError::msgpack_depth_exceeded,
            "encode_msgpack rejects depth > 32");

    MsgPackLimits small_bytes;
    small_bytes.max_bytes = 8U;
    auto enc_big =
        encode_msgpack(MsgPackValue::string("0123456789abcdef"), small_bytes);
    require(!enc_big.has_value() && nvim_rpc_error_of(enc_big.error()) ==
                                        NvimRpcError::msgpack_bytes_exceeded,
            "encode_msgpack enforces max_bytes");
  }
}

// ============================================================================
// 2. Audit-Safety Script Validator Tests (Always Runs)
// ============================================================================

void test_script_validation_policy() {
  // Safe Ex scripts accepted
  require(validate_scratch_script("%s/foo/bar/g", false).allowed,
          "Ex substitute allowed");
  require(validate_scratch_script("1,3s/alpha/BETA/g\n%sort u", false).allowed,
          "multi-line Ex substitute + sort allowed");
  require(validate_scratch_script("g/TODO/d", false).allowed,
          "Ex global delete allowed");

  // Dangerous Ex escapes rejected
  const std::vector<std::string_view> bad_ex = {
      ":!echo pwned",           "!id",
      "%!cat /etc/passwd",      ":w /tmp/escape.txt",
      "write /tmp/escape.txt",  "wq",
      "e /etc/hosts",           "r /etc/hosts",
      "lua os.execute('id')",   "source /tmp/evil.vim",
      "call system('id')",      "terminal",
      "%s/a/b/g | !id",         "%s/a/b/g | w /tmp/x",
      "%s/a/\\=system('id')/g", "g/foo/!id",
      "g/foo/w /tmp/x",         "v/foo/lua os.execute('id')",
      "norm! :w /tmp/x",
  };
  for (const auto script : bad_ex) {
    require(!validate_scratch_script(script, false).allowed,
            "dangerous Ex script rejected: " + std::string{script});
  }

  // Safe Lua scratch script accepted
  require(validate_scratch_script(
              "local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)\n"
              "lines[1] = 'updated'\n"
              "vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)\n",
              true)
              .allowed,
          "safe Lua buffer edit allowed");

  // Dangerous Lua escapes rejected
  const std::vector<std::string_view> bad_lua = {
      "io.open('/tmp/x', 'w')",
      "os.execute('id')",
      "os.remove('/tmp/x')",
      "vim.system({'id'})",
      "vim.cmd('w /tmp/x')",
      "vim.fn.writefile({'x'}, '/tmp/x')",
      "vim.api.nvim_command('!id')",
      "vim.api.nvim_exec2('w /tmp/x', {})",
      "vim.uv.fs_open('/tmp/x', 'w', 420)",
      "require('os')",
      "dofile('/tmp/x.lua')",
      "loadstring('return 1')",
      "debug.getinfo(1)",
      "_G['os']",
      "system('id')",
      "\x1bLJ\x02",
  };
  for (const auto script : bad_lua) {
    require(!validate_scratch_script(script, true).allowed,
            "dangerous Lua script rejected");
  }
}

// ============================================================================
// 3. Missing-Binary Graceful Probe Test (Always Runs)
// ============================================================================

void test_missing_nvim_probe_graceful() {
  NvimProbeOptions opts;
  opts.executable = "/nonexistent/blackbird-no-such-nvim-binary";
  opts.timeout = std::chrono::milliseconds{2000};
  const auto caps = probe_nvim_capabilities(opts);
  require(!caps.available, "probe returns available=false for missing binary");
  require(!caps.diagnostic.empty(), "probe populates diagnostic when unavailable");
}

// ============================================================================
// 4. Live Headless Neovim E2E Tests (Gated on probe_nvim_capabilities().available)
// ============================================================================

void test_live_neovim_e2e() {
  const auto fds_before = count_open_fds();

  const auto caps = probe_nvim_capabilities();
  if (!caps.available) {
    std::cout << "[nvim_rpc_test] nvim not installed; skipping live Neovim E2E ("
              << caps.diagnostic << ")\n";
    return;
  }

  std::cout << "[nvim_rpc_test] live Neovim detected: " << caps.version_string << " ("
            << caps.executable_path << "), parsers=" << caps.treesitter_parsers.size()
            << "\n";

  require(!caps.version_string.empty(), "version_string populated");
  require(caps.has_treesitter, "vim.treesitter available in headless Neovim");
  require(caps.has_vim_diff, "vim.diff available in headless Neovim");
  require(std::find(caps.treesitter_parsers.begin(), caps.treesitter_parsers.end(),
                    "lua") != caps.treesitter_parsers.end(),
          "bundled lua Tree-sitter parser available");
  require(std::find(caps.treesitter_parsers.begin(), caps.treesitter_parsers.end(),
                    "c") != caps.treesitter_parsers.end(),
          "bundled c Tree-sitter parser available");

  // Spawn persistent headless Neovim client inside an isolated temp dir to prove zero
  // disk writes occur anywhere in cwd.
  TempDir workdir;
  NvimClientOptions client_opts;
  client_opts.working_directory = workdir.root;
  auto spawned = NvimRpcClient::spawn(client_opts);
  require(spawned.has_value(), "NvimRpcClient::spawn succeeds");
  auto client = std::move(spawned.value());
  require(client.is_open(), "client is open");
  const auto child_pid = client.child_pid();
  require(child_pid > 0, "valid child pid");

  // A. nvim_eval & nvim_exec_lua round-trips
  {
    auto eval_res = client.nvim_eval("21 * 2");
    require(eval_res.has_value(), "nvim_eval succeeds");
    require(eval_res.value().as_int64() == 42, "nvim_eval 21 * 2 == 42");

    std::vector<MsgPackValue> lua_args = {
        MsgPackValue::string("blackbird"),
        MsgPackValue::int64(7),
    };
    auto lua_res = client.nvim_exec_lua(
        "local name, n = ...; return { greeting = 'hi ' .. name, doubled = n * 2 }",
        std::move(lua_args));
    require(lua_res.has_value(), "nvim_exec_lua succeeds");
    const auto *m = lua_res.value().as_map();
    require(m != nullptr, "lua table returned as MsgPackMap");
    require(m->find("greeting") != nullptr &&
                *m->find("greeting")->as_string() == "hi blackbird",
            "lua greeting round-trips");
    require(m->find("doubled") != nullptr && m->find("doubled")->as_int64() == 14,
            "lua integer calculation round-trips");
  }

  // B. Real Tree-sitter AST query on Lua source
  {
    const std::string lua_source = "local function compute(a, b)\n"
                                   "  return a + b\n"
                                   "end\n"
                                   "\n"
                                   "function greet(who)\n"
                                   "  return 'hello ' .. who\n"
                                   "end\n";
    NvimAstQueryRequest req;
    req.language = "lua";
    req.source_text = lua_source;
    req.treesitter_query = "(function_declaration name: (identifier) @fn_name)";
    auto caps_res = client.ast_query(req);
    require(caps_res.has_value(),
            "Lua ast_query succeeds: " + client.last_error_message());
    const auto &captures = caps_res.value();
    require(captures.size() == 2U, "Lua ast_query found both functions");

    require(captures[0].capture_name == "fn_name", "first capture name");
    require(captures[0].node_type == "identifier", "first capture node_type");
    require(captures[0].text == "compute", "first capture text == compute");
    require(captures[0].start_row == 0U && captures[0].start_col == 15U &&
                captures[0].end_row == 0U && captures[0].end_col == 22U,
            "first capture exact line/col range");

    require(captures[1].capture_name == "fn_name", "second capture name");
    require(captures[1].node_type == "identifier", "second capture node_type");
    require(captures[1].text == "greet", "second capture text == greet");
    require(captures[1].start_row == 4U && captures[1].start_col == 9U &&
                captures[1].end_row == 4U && captures[1].end_col == 14U,
            "second capture exact line/col range");
  }

  // C. Real Tree-sitter AST query on C source
  {
    const std::string c_source = "int add(int x, int y) {\n"
                                 "  return x + y;\n"
                                 "}\n"
                                 "static void reset_state(void) {}\n";
    NvimAstQueryRequest req;
    req.language = "c";
    req.source_text = c_source;
    req.treesitter_query =
        "(function_definition declarator: (function_declarator declarator: "
        "(identifier) @fn))";
    auto caps_res = client.ast_query(req);
    require(caps_res.has_value(),
            "C ast_query succeeds: " + client.last_error_message());
    const auto &captures = caps_res.value();
    require(captures.size() == 2U, "C ast_query found both functions");

    require(captures[0].capture_name == "fn", "C first capture name");
    require(captures[0].node_type == "identifier", "C first node_type");
    require(captures[0].text == "add", "C first capture text == add");
    require(captures[0].start_row == 0U && captures[0].start_col == 4U &&
                captures[0].end_row == 0U && captures[0].end_col == 7U,
            "C first capture exact range");

    require(captures[1].text == "reset_state", "C second capture text == reset_state");
    require(captures[1].start_row == 3U && captures[1].start_col == 12U &&
                captures[1].end_row == 3U && captures[1].end_col == 23U,
            "C second capture exact range");
  }

  // D. scratch_edit (Ex mode) applies structural edit in-memory & produces unified diff
  {
    const std::string original = "alpha\nbeta\ngamma\n";
    NvimScratchEditRequest req;
    req.source_text = original;
    req.script = "%s/beta/BETA/g";
    req.is_lua = false;
    auto prop = client.scratch_edit(req);
    require(prop.has_value(),
            "Ex scratch_edit succeeds: " + client.last_error_message());
    require(prop.value().original_lines_count == 3U, "original_lines_count == 3");
    require(prop.value().changed, "proposal reports changed=true");
    require(prop.value().proposed_text == "alpha\nBETA\ngamma\n",
            "proposed_text matches exact replacement");
    require(prop.value().unified_diff.find("-beta\n+BETA\n") != std::string::npos,
            "unified_diff contains expected hunk");
  }

  // E. scratch_edit (Lua mode) applies structural Tree-sitter-guided edit in-memory
  {
    const std::string original = "local function old_name(v)\n"
                                 "  return v * 2\n"
                                 "end\n";
    const std::string lua_edit = R"lua(
local lines = vim.api.nvim_buf_get_lines(buf, 0, -1, false)
local src = table.concat(lines, "\n") .. "\n"
local parser = vim.treesitter.get_string_parser(src, "lua")
local root = parser:parse()[1]:root()
local q = vim.treesitter.query.parse("lua", "(function_declaration name: (identifier) @fn)")
for _, node in q:iter_captures(root, src, 0, -1) do
  local sr, sc, er, ec = node:range()
  vim.api.nvim_buf_set_text(buf, sr, sc, er, ec, { "renamed_fn" })
end
)lua";
    NvimScratchEditRequest req;
    req.source_text = original;
    req.script = lua_edit;
    req.is_lua = true;
    auto prop = client.scratch_edit(req);
    require(prop.has_value(),
            "Lua scratch_edit succeeds: " + client.last_error_message());
    require(prop.value().original_lines_count == 3U,
            "Lua edit original_lines_count == 3");
    require(prop.value().changed, "Lua edit reports changed=true");
    require(prop.value().proposed_text ==
                "local function renamed_fn(v)\n  return v * 2\nend\n",
            "Lua AST edit produced exact proposed_text");
    require(prop.value().unified_diff.find("-local function old_name(v)") !=
                    std::string::npos &&
                prop.value().unified_diff.find("+local function renamed_fn(v)") !=
                    std::string::npos,
            "Lua AST edit unified_diff accurate");
  }

  // F. scratch_edit refuses dangerous escapes (both static C++ gate & runtime sandbox!)
  {
    const auto sentinel = workdir.root / "must_never_exist.txt";
    NvimScratchEditRequest bad_w_req;
    bad_w_req.source_text = "hello\n";
    bad_w_req.script = "w " + sentinel.string();
    bad_w_req.is_lua = false;
    auto bad_w = client.scratch_edit(bad_w_req);
    require(!bad_w.has_value() && nvim_rpc_error_of(bad_w.error()) ==
                                      NvimRpcError::unsafe_script_rejected,
            "scratch_edit rejects :w escape");
    require(!std::filesystem::exists(sentinel), "no file written on rejected :w");

    NvimScratchEditRequest bad_lua_req;
    bad_lua_req.source_text = "hello\n";
    bad_lua_req.script = "io.open('" + sentinel.string() + "', 'w')";
    bad_lua_req.is_lua = true;
    auto bad_lua = client.scratch_edit(bad_lua_req);
    require(!bad_lua.has_value() && nvim_rpc_error_of(bad_lua.error()) ==
                                        NvimRpcError::unsafe_script_rejected,
            "scratch_edit rejects io.open escape");
    require(!std::filesystem::exists(sentinel), "no file written on rejected io.open");

    // Runtime LuaJIT setfenv sandbox defense-in-depth even if static check is bypassed
    // by a subtle Lua expression referencing unavailable globals (e.g. collectgarbage).
    NvimScratchEditRequest runtime_req;
    runtime_req.source_text = "hello\n";
    runtime_req.script = "collectgarbage('collect')";
    runtime_req.is_lua = true;
    auto runtime_blocked = client.scratch_edit(runtime_req);
    require(!runtime_blocked.has_value(),
            "runtime LuaJIT setfenv sandbox blocks unlisted globals");
  }

  // F2. Notification drain & >128 KiB large-payload round-trip (zero pipe deadlock)
  {
    auto notif_res = client.nvim_exec_lua(
        "vim.rpcnotify(0, 'bb_test_event', 'hello', 123); return 'notified'");
    require(notif_res.has_value() && *notif_res.value().as_string() == "notified",
            "nvim_exec_lua emitting rpcnotify succeeds");
    const auto notes = client.drain_notifications();
    bool found_note = false;
    for (const auto &n : notes) {
      if (n.method == "bb_test_event" && n.params.size() == 2U &&
          n.params[0].as_string() != nullptr && *n.params[0].as_string() == "hello" &&
          n.params[1].as_int64() == 123) {
        found_note = true;
      }
    }
    require(found_note, "drain_notifications captured real MsgPack-RPC notification");

    // Build a >128 KiB source buffer (larger than OS 64 KiB pipe buffer) and transform.
    std::string large_src;
    large_src.reserve(160000U);
    for (int i = 0; i < 4000; ++i) {
      large_src += "line_" + std::to_string(i) + "_payload_0123456789abcdef\n";
    }
    large_src += "TARGET_SENTINEL\n";
    NvimScratchEditRequest big_req;
    big_req.source_text = large_src;
    big_req.script = "%s/TARGET_SENTINEL/REPLACED_SENTINEL/";
    big_req.is_lua = false;
    auto big_prop = client.scratch_edit(big_req);
    require(big_prop.has_value(),
            "large >128KiB scratch_edit succeeds without pipe deadlock");
    require(big_prop.value().changed, "large edit changed=true");
    require(big_prop.value().original_lines_count == 4001U,
            "large edit original_lines_count == 4001");
    require(big_prop.value().proposed_text.find("REPLACED_SENTINEL\n") !=
                std::string::npos,
            "large edit replacement present");

    // Invalid Tree-sitter query returns clean treesitter_error without killing session.
    NvimAstQueryRequest bad_q;
    bad_q.language = "lua";
    bad_q.source_text = "local x = 1\n";
    bad_q.treesitter_query = "(nonexistent_node_type_xyz @bad)";
    auto bad_q_res = client.ast_query(bad_q);
    require(!bad_q_res.has_value() &&
                nvim_rpc_error_of(bad_q_res.error()) == NvimRpcError::treesitter_error,
            "invalid Tree-sitter query returns treesitter_error");
    auto alive = client.nvim_eval("1 + 1");
    require(alive.has_value() && alive.value().as_int64() == 2,
            "client stays healthy after invalid Tree-sitter query");
  }

  // G. Verify ZERO files were created or touched in the working directory
  {
    std::size_t entries = 0;
    for (const auto &entry : std::filesystem::directory_iterator(workdir.root)) {
      (void)entry;
      ++entries;
    }
    require(entries == 0U, "zero files created in working directory");
  }

  // H. Clean shutdown: 0 zombies, 0 leaked FDs
  client.close();
  require(!client.is_open(), "client reports closed");
  require(client.child_pid() == -1, "client reports child_pid == -1 after close");

  // Confirm child process is completely reaped (waitpid returns -1 / ECHILD).
  int status = 0;
  const pid_t reap_check = ::waitpid(static_cast<pid_t>(child_pid), &status, WNOHANG);
  require(reap_check == -1 && errno == ECHILD, "child process reaped with 0 zombies");

  const auto fds_after = count_open_fds();
  require(fds_after == fds_before, "zero leaked file descriptors after Neovim E2E");
}

} // namespace

int main() {
  try {
    test_msgpack_scalars_and_boundaries();
    test_msgpack_strings_bins_exts();
    test_msgpack_containers_and_streaming();
    test_msgpack_fuzz_hardening_and_bounds();
    test_script_validation_policy();
    test_missing_nvim_probe_graceful();
    test_live_neovim_e2e();
    std::cout << "[nvim_rpc_test] ALL TESTS PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "[nvim_rpc_test] FAILURE: " << ex.what() << '\n';
    return 1;
  }
}
