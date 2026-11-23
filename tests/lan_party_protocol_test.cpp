#include "blackbird/lan_party_protocol.hpp"

#include "blackbird/mp_client.hpp"
#include "blackbird/mp_protocol.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace blackbird;
using namespace blackbird::lan;

namespace {

const char *g_stage = "startup";

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(std::string{g_stage} + ": " + message);
  }
}

template <typename T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: " + error_name(result.error().code) + " (" +
                             std::string{lan_error_name(lan_error_of(result.error()))} +
                             ")");
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: " + error_name(result.error().code) + " (" +
                             std::string{lan_error_name(lan_error_of(result.error()))} +
                             ")");
  }
}

template <typename T>
void expect_lan_err(const Result<T> &result, LanError expected, const char *context) {
  if (result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: expected error " +
                             std::string{lan_error_name(expected)} + ", got success");
  }
  const LanError actual = lan_error_of(result.error());
  if (actual != expected) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: expected error " +
                             std::string{lan_error_name(expected)} + ", got " +
                             std::string{lan_error_name(actual)});
  }
}

struct TempDir {
  std::filesystem::path path;

  explicit TempDir(std::string_view tag) {
    const auto base = std::filesystem::temp_directory_path();
    path = base / ("blackbird_lan_test_" + std::string{tag} + "_" +
                   std::to_string(static_cast<std::uint64_t>(::getpid())));
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    std::filesystem::create_directories(path);
  }

  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;

  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

void write_text_file(const std::filesystem::path &path, std::string_view text,
                     mode_t mode = mode_t{0644}) {
  if (!path.parent_path().empty()) {
    std::filesystem::create_directories(path.parent_path());
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  require(out.good(), "open temp file for write");
  out.write(text.data(), static_cast<std::streamsize>(text.size()));
  out.close();
  require(out.good(), "flush temp file");
  require(::chmod(path.c_str(), mode) == 0, "chmod temp file");
}

std::vector<std::uint8_t> paint_input(std::size_t len) {
  std::vector<std::uint8_t> out(len);
  for (std::size_t i = 0U; i < len; ++i) {
    out[i] = static_cast<std::uint8_t>(i % 251U);
  }
  return out;
}

std::vector<std::uint8_t> bytes_of(std::string_view text) {
  std::vector<std::uint8_t> out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<std::uint8_t>(ch));
  }
  return out;
}

mp::Ed25519PubKey seq_bytes_32(std::uint8_t start) {
  mp::Ed25519PubKey out{};
  for (std::size_t i = 0U; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(start + i);
  }
  return out;
}

mp::Ed25519PubKey valid_test_pubkey(std::uint8_t seed_fill) {
  mp::Ed25519Seed seed{};
  seed.fill(seed_fill);
  const auto key = mp::Ed25519SigningKey::from_seed(seed);
  require(key.has_value(), "derive valid ed25519 test key");
  return key.value().public_key();
}

EnvLookupFn make_env(std::map<std::string, std::string> vars) {
  return [map = std::move(vars)](std::string_view key) -> std::optional<std::string> {
    const auto it = map.find(std::string{key});
    if (it == map.end()) {
      return std::nullopt;
    }
    return it->second;
  };
}

// ---------------------------------------------------------------------------
// 1. BLAKE3 Official Test Vectors & mp1-lan/1 Golden PIN Proof
// ---------------------------------------------------------------------------

void test_blake3_and_pin_proof() {
  g_stage = "blake3_official_vectors";

  constexpr std::string_view kKeyStr = "whats the Elvish word for friend";
  static_assert(kKeyStr.size() == 32U);
  Blake3Key test_key{};
  std::memcpy(test_key.data(), kKeyStr.data(), 32U);
  constexpr std::string_view kTestCtx =
      "BLAKE3 2019-12-27 16:29:52 test vectors context";

  // Empty & "abc"
  require(mp::hex_lower(blake3_hash({})) ==
              "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
          "blake3 empty");
  const auto abc = bytes_of("abc");
  require(mp::hex_lower(blake3_hash(abc)) ==
              "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
          "blake3 abc");
  require(mp::hex_lower(blake3_keyed_hash(test_key, {})) ==
              "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
          "blake3 keyed empty");
  require(mp::hex_lower(blake3_keyed_hash(test_key, abc)) ==
              "157f8b4b104070014ab0b3b7aff364f794e010e92b1c976318e892f380b53406",
          "blake3 keyed abc");
  require(mp::hex_lower(blake3_derive_key(kTestCtx, {})) ==
              "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
          "blake3 derive empty");
  require(mp::hex_lower(blake3_derive_key(kTestCtx, abc)) ==
              "221c3923b5f3358d596e6cbad6c20c2c63df740e7dc46a8f9ebab07d460ba827",
          "blake3 derive abc");

  struct PaintedVector {
    std::size_t len;
    std::string_view hash_hex;
    std::string_view keyed_hex;
    std::string_view derive_hex;
  };
  const std::array<PaintedVector, 8> vectors = {{
      {63U, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
       "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
       "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"},
      {64U, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
       "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
       "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"},
      {65U, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
       "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
       "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"},
      {1024U, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
       "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
       "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"},
      {1025U, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
       "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
       "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb"},
      {2048U, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
       "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
       "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23"},
      {2049U, "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
       "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
       "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273"},
      {102400U, "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
       "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7",
       "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6"},
  }};

  for (const auto &vec : vectors) {
    const auto data = paint_input(vec.len);
    require(mp::hex_lower(blake3_hash(data)) == vec.hash_hex, "blake3 painted hash");
    require(mp::hex_lower(blake3_keyed_hash(test_key, data)) == vec.keyed_hex,
            "blake3 painted keyed");
    require(mp::hex_lower(blake3_derive_key(kTestCtx, data)) == vec.derive_hex,
            "blake3 painted derive");
  }

  g_stage = "lan_pin_golden_proof";
  const LanPinProofInput golden_in{
      "424242",
      "0102030405060708",
      seq_bytes_32(0x00U),
      seq_bytes_32(0x20U),
      seq_bytes_32(0x40U),
  };
  const auto golden_proof = must(compute_lan_pin_proof(golden_in), "golden pin proof");
  const std::string golden_hex = mp::hex_lower(golden_proof);
  std::cout << "GOLDEN_PIN_PROOF=" << golden_hex << "\n";
  require(golden_hex ==
              "13615bcb4c8793ecbd26103a9abdeb767bfd40bdf73820116b0081319d2549c8",
          "golden mp1-lan/1 PIN proof parity with Rust blake3");

  require(must(verify_lan_pin_proof(golden_in, golden_proof), "verify valid proof"),
          "valid proof must verify");

  LanPinProof tampered = golden_proof;
  tampered[31] ^= 0x01U;
  require(!must(verify_lan_pin_proof(golden_in, tampered), "verify flipped bit"),
          "flipped bit must not verify");

  LanPinProofInput wrong_pin = golden_in;
  wrong_pin.pin = "424243";
  require(!must(verify_lan_pin_proof(wrong_pin, golden_proof), "verify wrong pin"),
          "wrong PIN must not verify");

  LanPinProofInput wrong_nonce = golden_in;
  wrong_nonce.host_nonce[0] ^= 0x80U;
  require(!must(verify_lan_pin_proof(wrong_nonce, golden_proof), "verify wrong nonce"),
          "wrong nonce must not verify");

  // PIN validation & CleansedPin
  g_stage = "lan_pin_validation";
  expect_lan_err(validate_lan_pin(""), LanError::invalid_pin, "empty pin");
  expect_lan_err(validate_lan_pin(std::string(65U, 'a')), LanError::invalid_pin,
                 "pin > 64B");
  expect_lan_err(validate_lan_pin(std::string_view{"ab\x00cd", 5U}),
                 LanError::invalid_pin, "pin with NUL");
  expect_lan_err(validate_lan_pin("ab\x1b[31m"), LanError::invalid_pin, "pin with ESC");
  expect_lan_err(validate_lan_pin("ab\ncd"), LanError::invalid_pin, "pin with LF");
  expect_lan_err(validate_lan_pin("ab\x7f"), LanError::invalid_pin, "pin with DEL");
  expect_lan_err(validate_lan_pin("\xc2\x85"), LanError::invalid_pin,
                 "pin with C1 control");
  expect_lan_err(validate_lan_pin("abc\xe2\x80\xae"
                                  "123"),
                 LanError::invalid_pin, "pin with BiDi override");
  expect_lan_err(validate_lan_pin("\xff\xfe"), LanError::invalid_pin,
                 "pin invalid UTF-8");
  must_void(validate_lan_pin(std::string(64U, '9')), "64B pin valid");
  must_void(validate_lan_pin("caf\xc3\xa9-42"), "valid UTF-8 NFC pin");

  auto pin1 = must(CleansedPin::create("secret-42"), "create CleansedPin");
  require(pin1.view() == "secret-42" && pin1.size() == 9U, "CleansedPin view");
  CleansedPin pin2 = std::move(pin1);
  require(pin2.view() == "secret-42", "moved CleansedPin view");
  pin2.cleanse();
  require(pin2.empty(), "cleansed pin empty");

  // lan_party_id hex parsing
  const auto pid = must(parse_lan_party_id_hex("0102030405060708"), "parse party id");
  require(format_lan_party_id_hex(pid) == "0102030405060708", "format party id");
  expect_lan_err(parse_lan_party_id_hex("010203040506070G"),
                 LanError::invalid_lan_party_id, "uppercase/non-hex party id");
  expect_lan_err(parse_lan_party_id_hex("010203040506070A"),
                 LanError::invalid_lan_party_id, "uppercase hex party id");
  expect_lan_err(parse_lan_party_id_hex("01020304"), LanError::invalid_lan_party_id,
                 "short party id");
}

// ---------------------------------------------------------------------------
// 2. Policy Engine (Mandates #1, #2, #3, #6)
// ---------------------------------------------------------------------------

void test_policy_engine() {
  g_stage = "policy_toml_parser";

  const auto empty_cfg =
      must(parse_lan_policy_toml("# comment only\n\n"), "empty toml");
  require(empty_cfg == LanPolicyConfig{}, "empty toml defaults");

  const auto full_cfg = must(parse_lan_policy_toml("[lan]\r\n"
                                                   "disabled = true # kill\r\n"
                                                   "require_pin = true\n"
                                                   "require_local_auth = true\n"
                                                   "idle_timeout_sec = 420\n"
                                                   "scan_timeout_sec = 25\n"),
                             "full toml");
  require(full_cfg.disabled && full_cfg.require_pin && full_cfg.require_local_auth &&
              full_cfg.idle_timeout_sec == 420U && full_cfg.scan_timeout_sec == 25U,
          "parsed all fields");

  // Strict rejections
  expect_lan_err(parse_lan_policy_toml("disabled = true\n"),
                 LanError::policy_parse_error, "key outside [lan]");
  expect_lan_err(parse_lan_policy_toml("[other]\ndisabled = true\n"),
                 LanError::policy_parse_error, "unknown section");
  expect_lan_err(parse_lan_policy_toml("[lan]\nunknown_key = true\n"),
                 LanError::policy_parse_error, "unknown key");
  expect_lan_err(parse_lan_policy_toml("[lan]\ndisabled = true\ndisabled = false\n"),
                 LanError::policy_parse_error, "duplicate key");
  expect_lan_err(parse_lan_policy_toml("[lan]\n[lan]\n"), LanError::policy_parse_error,
                 "duplicate [lan] section");
  expect_lan_err(parse_lan_policy_toml("[lan]\ndisabled = \"true\"\n"),
                 LanError::policy_parse_error, "quoted bool");
  expect_lan_err(parse_lan_policy_toml("[lan]\ndisabled = True\n"),
                 LanError::policy_parse_error, "uppercase bool");
  expect_lan_err(parse_lan_policy_toml("[lan]\nidle_timeout_sec = 0\n"),
                 LanError::policy_parse_error, "zero timeout");
  expect_lan_err(parse_lan_policy_toml("[lan]\nscan_timeout_sec = -5\n"),
                 LanError::policy_parse_error, "negative timeout");
  expect_lan_err(parse_lan_policy_toml("[lan]\nmalformed line\n"),
                 LanError::policy_parse_error, "missing equals");
  expect_lan_err(parse_lan_policy_toml(std::string_view{"[lan]\0", 6U}),
                 LanError::policy_parse_error, "NUL byte");

  g_stage = "policy_floor_and_env";
  TempDir tmp{"policy"};
  const auto sys_path = tmp.path / "sys_lan.toml";
  const auto user_path = tmp.path / "user_lan.toml";
  const auto my_uid = static_cast<std::uint32_t>(::geteuid());

  // Neither file exists -> defaults
  {
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;
    const auto eff = must(load_effective_lan_policy(paths, make_env({})), "defaults");
    require(!eff.disabled && !eff.require_pin && !eff.require_local_auth &&
                eff.idle_timeout_sec == 300U && eff.scan_timeout_sec == 15U,
            "default policy values");
  }

  // Regression: absent system policy + user timeouts above defaults (300/15) must
  // NOT be clobbered back to defaults (clamped only to hard caps 1800/60).
  write_text_file(user_path,
                  "[lan]\n"
                  "idle_timeout_sec = 900\n"
                  "scan_timeout_sec = 45\n",
                  mode_t{0644});
  {
    LanPolicyPaths paths;
    paths.system_policy_path = tmp.path / "absent_sys.toml";
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;
    const auto eff = must(load_effective_lan_policy(paths, make_env({})),
                          "absent sys + user timeouts above defaults");
    require(eff.idle_timeout_sec == 900U && eff.scan_timeout_sec == 45U,
            "user timeouts above default preserved when system absent");
  }

  // Regression: system timeouts above defaults + absent user policy must NOT be
  // clobbered back to defaults.
  write_text_file(sys_path,
                  "[lan]\n"
                  "idle_timeout_sec = 600\n"
                  "scan_timeout_sec = 30\n",
                  mode_t{0644});
  {
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = tmp.path / "absent_user.toml";
    paths.expected_system_uid = my_uid;
    const auto eff = must(load_effective_lan_policy(paths, make_env({})),
                          "sys timeouts above defaults + absent user");
    require(eff.idle_timeout_sec == 600U && eff.scan_timeout_sec == 30U,
            "system timeouts above default preserved when user absent");
  }

  // System floor cannot be relaxed by user config; caps enforced
  write_text_file(sys_path,
                  "[lan]\n"
                  "disabled = false\n"
                  "require_pin = true\n"
                  "require_local_auth = true\n"
                  "idle_timeout_sec = 600\n"
                  "scan_timeout_sec = 999\n",
                  mode_t{0644});
  write_text_file(user_path,
                  "[lan]\n"
                  "disabled = false\n"
                  "require_pin = false\n"
                  "require_local_auth = false\n"
                  "idle_timeout_sec = 9999\n"
                  "scan_timeout_sec = 120\n",
                  mode_t{0644});
  {
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;
    const auto eff =
        must(load_effective_lan_policy(paths, make_env({})), "system floor");
    require(!eff.disabled, "enabled when both false");
    require(eff.require_pin, "sys require_pin floor preserved");
    require(eff.require_local_auth, "sys require_local_auth floor preserved");
    require(eff.idle_timeout_sec == 600U, "min(sys=600, user=9999, cap=1800) == 600");
    require(eff.scan_timeout_sec == 60U, "min(sys=999, user=120, cap=60) == 60");
  }

  // User can tighten below system floor
  write_text_file(user_path,
                  "[lan]\n"
                  "idle_timeout_sec = 120\n"
                  "scan_timeout_sec = 10\n",
                  mode_t{0644});
  {
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;
    const auto eff =
        must(load_effective_lan_policy(paths, make_env({})), "user tightens timeouts");
    require(eff.idle_timeout_sec == 120U && eff.scan_timeout_sec == 10U,
            "user tightened timeouts");
  }

  // System disabled=true cannot be overridden by user disabled=false
  write_text_file(sys_path, "[lan]\ndisabled = true\n", mode_t{0644});
  write_text_file(user_path, "[lan]\ndisabled = false\n", mode_t{0644});
  {
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;
    const auto eff =
        must(load_effective_lan_policy(paths, make_env({})), "sys disabled floor");
    require(eff.disabled, "sys disabled floor preserved");
  }

  // Env kill switches
  write_text_file(sys_path, "[lan]\ndisabled = false\n", mode_t{0644});
  {
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;

    for (const std::string_view val : {"1", "true", "TRUE", "yes", "Yes"}) {
      const auto e1 = must(load_effective_lan_policy(
                               paths, make_env({{"MP_DISABLE_LAN", std::string{val}}})),
                           "MP_DISABLE_LAN");
      require(e1.disabled, "MP_DISABLE_LAN disables LAN");
      const auto e2 =
          must(load_effective_lan_policy(
                   paths, make_env({{"BLACKBIRD_DISABLE_LAN", std::string{val}}})),
               "BLACKBIRD_DISABLE_LAN");
      require(e2.disabled, "BLACKBIRD_DISABLE_LAN disables LAN");
    }
    for (const std::string_view val : {"0", "false", "no", ""}) {
      const auto e =
          must(load_effective_lan_policy(
                   paths, make_env({{"MP_DISABLE_LAN", std::string{val}},
                                    {"BLACKBIRD_DISABLE_LAN", std::string{val}}})),
               "env kill switch off");
      require(!e.disabled, "0/false/no/empty does not disable LAN");
    }
  }

  // XDG_CONFIG_HOME auto-resolution
  {
    const auto xdg_dir = tmp.path / "xdg";
    write_text_file(xdg_dir / "blackbird" / "lan.toml",
                    "[lan]\nrequire_pin = true\nscan_timeout_sec = 9\n", mode_t{0644});
    LanPolicyPaths paths;
    paths.system_policy_path = tmp.path / "nonexistent_sys.toml";
    paths.user_policy_path = std::nullopt;
    const auto eff = must(load_effective_lan_policy(
                              paths, make_env({{"XDG_CONFIG_HOME", xdg_dir.string()}})),
                          "XDG_CONFIG_HOME resolution");
    require(eff.require_pin && eff.scan_timeout_sec == 9U, "XDG user policy loaded");
  }

  // Tamper / security checks (fail closed!)
  g_stage = "policy_tamper_checks";
  {
    // Group-writable system policy rejected
    write_text_file(sys_path, "[lan]\ndisabled = false\n", mode_t{0664});
    LanPolicyPaths paths;
    paths.system_policy_path = sys_path;
    paths.user_policy_path = user_path;
    paths.expected_system_uid = my_uid;
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_insecure_file, "group-writable sys policy");

    // World-writable system policy rejected
    write_text_file(sys_path, "[lan]\ndisabled = false\n", mode_t{0646});
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_insecure_file, "world-writable sys policy");

    // Wrong UID system policy rejected
    write_text_file(sys_path, "[lan]\ndisabled = false\n", mode_t{0644});
    paths.expected_system_uid = my_uid + 1U;
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_insecure_file, "wrong uid sys policy");

    // Symlink system policy rejected
    const auto sys_link = tmp.path / "sys_link.toml";
    std::filesystem::create_symlink(sys_path, sys_link);
    paths.system_policy_path = sys_link;
    paths.expected_system_uid = my_uid;
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_symlink_rejected, "symlink sys policy");

    // Malformed system policy rejected
    write_text_file(sys_path, "[lan]\nnot_valid = ???\n", mode_t{0644});
    paths.system_policy_path = sys_path;
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_parse_error, "malformed sys policy");

    // User symlink rejected
    const auto user_link = tmp.path / "user_link.toml";
    std::filesystem::create_symlink(user_path, user_link);
    paths.system_policy_path = tmp.path / "missing_sys.toml";
    paths.user_policy_path = user_link;
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_symlink_rejected, "symlink user policy");

    // User wrong UID rejected
    paths.user_policy_path = user_path;
    paths.expected_user_uid = my_uid + 1U;
    expect_lan_err(load_effective_lan_policy(paths, make_env({})),
                   LanError::policy_insecure_file, "wrong uid user policy");
  }
}

// ---------------------------------------------------------------------------
// 3. Local-Only LAN Identity & Canonical Safety Number
// ---------------------------------------------------------------------------

void test_identity_and_safety_number() {
  g_stage = "lan_safety_number";

  const auto pk = valid_test_pubkey(0x11U);
  const auto acct_id = mp::AccountId::create(424242U);
  require(acct_id.has_value(), "create AccountId");
  const auto mp_sn = mp::compute_safety_number(acct_id.value(), pk);
  require(mp_sn.has_value(), "mp::compute_safety_number");
  const auto lan_sn_online =
      must(compute_lan_safety_number(424242U, pk), "lan online sn");
  require(lan_sn_online == mp_sn.value(), "online safety number matches mp_protocol");

  // account_id == 0 local-only safety number
  const auto lan_sn_zero = must(compute_lan_safety_number(0U, pk), "lan zero sn");
  require(lan_sn_zero.size() == mp::kSafetyNumberFormattedLength,
          "safety number length 39");
  require(lan_sn_zero != lan_sn_online, "account_id=0 differs from account_id>0");
  // Verify exact hyphen placement (groups of 4)
  for (std::size_t i = 0U; i < lan_sn_zero.size(); ++i) {
    if ((i + 1U) % 5U == 0U) {
      require(lan_sn_zero[i] == '-', "hyphen separator");
    } else {
      require(lan_sn_zero[i] != '-', "Crockford char");
    }
  }

  // Weak/invalid pubkey rejected (small-order all-zero point)
  mp::Ed25519PubKey zero_pk{};
  require(!compute_lan_safety_number(0U, zero_pk).has_value(), "reject weak pubkey");
  require(!compute_lan_safety_number(mp::kMaxSafeId + 1U, pk).has_value(),
          "reject > kMaxSafeId");

  // Display name sanitization
  require(sanitize_lan_display_name("  \x1b[31mQuake\nHero\x7f  ") == "[31mQuakeHero",
          "sanitize ANSI/control chars");
  require(sanitize_lan_display_name("   \x01\x02   ") == "lan-player",
          "sanitize empty fallback");
  require(sanitize_lan_display_name(std::string(50U, 'x')).size() == 32U,
          "sanitize truncate 32");

  g_stage = "lan_local_identity_create_reload";
  TempDir tmp{"identity"};
  const auto lan_dir = tmp.path / "lan_state";

  const auto id1 = must(load_or_create_lan_identity(LanIdentityRequest{
                            std::nullopt, lan_dir, "  Alice\x1b[0m  "}),
                        "create local LAN identity");
  require(id1.account_id == 0U && !id1.is_online_identity, "local-only identity");
  require(id1.display_name == "Alice[0m", "sanitized display name");
  require(id1.safety_number ==
              must(compute_lan_safety_number(0U, id1.public_key), "verify local sn"),
          "local safety number matches");

  // Verify 0700 dir and 0600 file permissions
  struct stat dir_st{};
  require(::lstat(lan_dir.c_str(), &dir_st) == 0 && (dir_st.st_mode & 0777) == 0700,
          "lan_state_dir is 0700");
  const auto id_file = lan_dir / "identity.json";
  struct stat file_st{};
  require(::lstat(id_file.c_str(), &file_st) == 0 && (file_st.st_mode & 0777) == 0600,
          "identity.json is 0600");

  // Reloading returns identical identity
  const auto id2 = must(
      load_or_create_lan_identity(LanIdentityRequest{std::nullopt, lan_dir, "Ignored"}),
      "reload local LAN identity");
  require(id1 == id2, "reloaded LAN identity matches exactly");
  const auto sk = id2.signing_key();
  require(sk.has_value() && sk.value().public_key() == id2.public_key,
          "signing_key derives matching public_key");

  // Insecure permissions on identity.json rejected fail-closed
  require(::chmod(id_file.c_str(), mode_t{0644}) == 0, "loosen perms");
  expect_lan_err(
      load_or_create_lan_identity(LanIdentityRequest{std::nullopt, lan_dir, "Alice"}),
      LanError::identity_insecure_permissions, "reject 0644 identity.json");
  require(::chmod(id_file.c_str(), mode_t{0600}) == 0, "restore perms");

  // Symlink identity.json rejected
  const auto sym_dir = tmp.path / "lan_symlink";
  std::filesystem::create_directories(sym_dir);
  require(::chmod(sym_dir.c_str(), mode_t{0700}) == 0, "chmod sym_dir");
  std::filesystem::create_symlink(id_file, sym_dir / "identity.json");
  expect_lan_err(
      load_or_create_lan_identity(LanIdentityRequest{std::nullopt, sym_dir, "Alice"}),
      LanError::identity_symlink_rejected, "reject symlink identity.json");

  // Online MpIdentityStore takes precedence when present with account_id
  g_stage = "lan_online_identity_derivation";
  const auto online_dir = tmp.path / "online_state";
  mp::MpIdentityState online_st{};
  online_st.root_seed = mp::CleansedSeed{
      mp::Ed25519Seed{1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                      17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}};
  online_st.device_seed = mp::CleansedSeed{
      mp::Ed25519Seed{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
                      16, 15, 14, 13, 12, 11, 10, 9,  8,  7,  6,  5,  4,  3,  2,  1}};
  online_st.account_id = acct_id.value();
  online_st.handle = "patrick";
  const auto saved = mp::MpIdentityStore::save(online_dir, online_st);
  require(saved.has_value(), "save online MpIdentityStore");

  const auto derived = must(
      load_or_create_lan_identity(LanIdentityRequest{online_dir, lan_dir, "Fallback"}),
      "derive from online store");
  const auto root_key = mp::Ed25519SigningKey::from_seed(online_st.root_seed->bytes());
  require(root_key.has_value(), "root_key");
  require(derived.is_online_identity, "is_online_identity == true");
  require(derived.account_id == 424242U, "real account_id");
  require(derived.display_name == "patrick", "handle preserved");
  require(derived.public_key == root_key.value().public_key(), "root pubkey used");
  const auto expected_online_sn =
      mp::compute_safety_number(acct_id.value(), root_key.value().public_key());
  require(expected_online_sn.has_value() &&
              derived.safety_number == expected_online_sn.value(),
          "canonical online Safety Number matches");
}

// ---------------------------------------------------------------------------
// 4. Mandate #6 Local OS Presence Guard
// ---------------------------------------------------------------------------

void test_local_os_presence_guard() {
  g_stage = "local_os_presence";

  std::string captured_reason;
  LocalAuthOptions ok_opts{};
  ok_opts.reason = "Host LAN lobby quake-night";
  ok_opts.prompt_override = [&](std::string_view reason) -> Result<void> {
    captured_reason = std::string{reason};
    return Result<void>::success();
  };
  must_void(verify_local_os_presence(ok_opts), "injectable local auth success");
  require(captured_reason == "Host LAN lobby quake-night", "reason propagated");

  LocalAuthOptions deny_opts{};
  deny_opts.reason = "Join LAN lobby";
  deny_opts.prompt_override = [](std::string_view) -> Result<void> {
    return Result<void>::failure(
        {ErrorCode::provider_auth,
         static_cast<std::int64_t>(LanError::local_auth_denied)});
  };
  expect_lan_err(verify_local_os_presence(deny_opts), LanError::local_auth_denied,
                 "injectable local auth denied");

  // Bad reason rejected before prompt
  LocalAuthOptions bad_reason{};
  bad_reason.reason = "";
  bad_reason.prompt_override = ok_opts.prompt_override;
  expect_lan_err(verify_local_os_presence(bad_reason), LanError::local_auth_failed,
                 "empty reason rejected");
  bad_reason.reason = "bad\x1b[31mreason";
  expect_lan_err(verify_local_os_presence(bad_reason), LanError::local_auth_failed,
                 "control char in reason rejected");

  // Headless SSH path with sudo fallback disabled -> deterministic unavailable
  LocalAuthOptions ssh_opts{};
  ssh_opts.reason = "Headless test";
  ssh_opts.env_lookup = make_env({{"SSH_CONNECTION", "10.0.0.1 12345 10.0.0.2 22"}});
  ssh_opts.allow_sudo_fallback = false;
  expect_lan_err(verify_local_os_presence(ssh_opts), LanError::local_auth_unavailable,
                 "headless SSH without sudo fallback returns unavailable");
}

// ---------------------------------------------------------------------------
// 5. In-TLS Handshake Framing & PIN Rate Limiter
// ---------------------------------------------------------------------------

void test_handshake_framing_and_rate_limiter() {
  g_stage = "handshake_roundtrips";

  const auto host_pk = valid_test_pubkey(0x21U);
  const auto joiner_pk = valid_test_pubkey(0x22U);

  // 0x10 lan_hello
  const LanHelloMessage hello{
      "0102030405060708",
      "quake-night",
      "patrick",
      424242U,
      host_pk,
      true,
      seq_bytes_32(0x40U),
      8U,
  };
  const auto hello_wire = must(encode_lan_handshake_frame(hello), "encode hello");
  require(hello_wire.size() > 4U && hello_wire[0] == 0x01U && hello_wire[1] == 0x10U &&
              hello_wire[2] == 0x00U && hello_wire[3] == 0x00U,
          "hello 4-byte header");
  require(is_lan_handshake_frame(hello_wire), "is_lan_handshake_frame(hello)");
  const auto hello_dec =
      must(decode_lan_handshake_frame(P2pLane::control, hello_wire), "decode hello");
  require(lan_handshake_kind(hello_dec) == LanHandshakeKind::lan_hello &&
              std::get<LanHelloMessage>(hello_dec) == hello,
          "hello roundtrip exact");

  // 0x11 lan_join (with & without pin_proof)
  const LanJoinMessage join_with_pin{"0102030405060708", "alice", 0U,
                                     seq_bytes_32(0x80U)};
  const auto join_wire = must(encode_lan_handshake_frame(join_with_pin), "encode join");
  require(join_wire[1] == 0x11U, "join kind 0x11");
  const auto join_dec =
      must(decode_lan_handshake_frame(P2pLane::control, join_wire), "decode join");
  require(std::get<LanJoinMessage>(join_dec) == join_with_pin,
          "join with pin roundtrip");

  const LanJoinMessage join_no_pin{"0102030405060708", "bob", 77U, std::nullopt};
  const auto join_no_pin_wire =
      must(encode_lan_handshake_frame(join_no_pin), "encode join no pin");
  const auto join_no_pin_dec =
      must(decode_lan_handshake_frame(P2pLane::control, join_no_pin_wire),
           "decode join no pin");
  require(std::get<LanJoinMessage>(join_no_pin_dec) == join_no_pin,
          "join without pin roundtrip");

  // 0x12 lan_welcome (accepted & rejected)
  const LanWelcomeMessage welcome_ok{
      "0102030405060708",
      true,
      "",
      3U,
      {
          LanMemberInfo{424242U, "patrick", host_pk, true},
          LanMemberInfo{0U, "alice", joiner_pk, false},
      },
  };
  const auto welcome_wire =
      must(encode_lan_handshake_frame(welcome_ok), "encode welcome ok");
  require(welcome_wire[1] == 0x12U, "welcome kind 0x12");
  const auto welcome_dec = must(
      decode_lan_handshake_frame(P2pLane::control, welcome_wire), "decode welcome ok");
  require(std::get<LanWelcomeMessage>(welcome_dec) == welcome_ok,
          "welcome ok roundtrip");

  const LanWelcomeMessage welcome_rej{"0102030405060708", false, "pin_invalid", 3U, {}};
  const auto welcome_rej_wire =
      must(encode_lan_handshake_frame(welcome_rej), "encode welcome rej");
  const auto welcome_rej_dec =
      must(decode_lan_handshake_frame(P2pLane::control, welcome_rej_wire),
           "decode welcome rej");
  require(std::get<LanWelcomeMessage>(welcome_rej_dec) == welcome_rej,
          "welcome reject roundtrip");

  // 0x13 lan_roster (12 members max)
  std::vector<LanMemberInfo> twelve_members;
  for (std::uint8_t i = 0U; i < 12U; ++i) {
    twelve_members.push_back(LanMemberInfo{
        i, "player-" + std::to_string(i),
        valid_test_pubkey(static_cast<std::uint8_t>(0x30U + i)), i == 0U});
  }
  const LanRosterMessage roster{"0102030405060708", 9U, true, twelve_members};
  const auto roster_wire = must(encode_lan_handshake_frame(roster), "encode roster 12");
  require(roster_wire[1] == 0x13U, "roster kind 0x13");
  const auto roster_dec = must(
      decode_lan_handshake_frame(P2pLane::control, roster_wire), "decode roster 12");
  require(std::get<LanRosterMessage>(roster_dec) == roster, "roster 12 roundtrip");

  // Strict rejection tests
  g_stage = "handshake_rejections";
  expect_lan_err(decode_lan_handshake_frame(P2pLane::causal, hello_wire),
                 LanError::frame_lane_mismatch, "causal lane rejected");
  expect_lan_err(decode_lan_handshake_frame(P2pLane::ephemeral, hello_wire),
                 LanError::frame_lane_mismatch, "ephemeral lane rejected");

  const std::array<std::uint8_t, 3> too_short = {0x01U, 0x10U, 0x00U};
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, too_short),
                 LanError::frame_truncated, "<4B truncated");
  const std::array<std::uint8_t, 4> hdr_only = {0x01U, 0x10U, 0x00U, 0x00U};
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, hdr_only),
                 LanError::frame_truncated, "header-only truncated");

  std::vector<std::uint8_t> too_big(kLanHandshakeMaxFrameBytes + 1U, ' ');
  too_big[0] = 0x01U;
  too_big[1] = 0x10U;
  too_big[2] = 0x00U;
  too_big[3] = 0x00U;
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, too_big),
                 LanError::frame_too_large, ">64 KiB rejected");

  auto bad_ver = hello_wire;
  bad_ver[0] = 0x02U;
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, bad_ver),
                 LanError::frame_unsupported_version, "bad version");

  auto bad_kind = hello_wire;
  bad_kind[1] = 0x01U;
  require(!is_lan_handshake_frame(bad_kind), "0x01 is not LAN handshake");
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, bad_kind),
                 LanError::frame_unknown_kind, "unknown kind 0x01");
  bad_kind[1] = 0x14U;
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, bad_kind),
                 LanError::frame_unknown_kind, "unknown kind 0x14");

  auto bad_flags = hello_wire;
  bad_flags[2] = 0x01U;
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, bad_flags),
                 LanError::frame_non_zero_reserved, "non-zero flags");
  auto bad_res = hello_wire;
  bad_res[3] = 0x80U;
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, bad_res),
                 LanError::frame_non_zero_reserved, "non-zero reserved");

  const std::vector<std::uint8_t> bad_utf8 = {0x01U, 0x11U, 0x00U, 0x00U, 0xffU, 0xfeU};
  expect_lan_err(decode_lan_handshake_frame(P2pLane::control, bad_utf8),
                 LanError::frame_invalid_utf8, "invalid UTF-8");

  auto make_raw_frame = [](std::uint8_t kind, std::string_view json) {
    std::vector<std::uint8_t> out = {0x01U, kind, 0x00U, 0x00U};
    for (const char ch : json) {
      out.push_back(static_cast<std::uint8_t>(ch));
    }
    return out;
  };
  expect_lan_err(
      decode_lan_handshake_frame(P2pLane::control, make_raw_frame(0x11U, "{bad json")),
      LanError::frame_invalid_json, "malformed JSON");
  expect_lan_err(
      decode_lan_handshake_frame(P2pLane::control, make_raw_frame(0x11U, "[1,2,3]")),
      LanError::frame_invalid_json, "non-object JSON");
  expect_lan_err(
      decode_lan_handshake_frame(
          P2pLane::control,
          make_raw_frame(0x11U,
                         "{\"lan_party_id\":\"0102030405060708\",\"display_name\":"
                         "\"alice\",\"account_id\":0,\"extra\":1}")),
      LanError::frame_invalid_field, "unknown field rejected");
  expect_lan_err(
      decode_lan_handshake_frame(
          P2pLane::control,
          make_raw_frame(0x11U,
                         "{\"lan_party_id\":\"0102030405060708\",\"display_name\":"
                         "\"alice\",\"display_name\":\"bob\",\"account_id\":0}")),
      LanError::frame_invalid_json, "duplicate field rejected");

  // Weak all-zero pubkey rejected in lan_hello
  LanHelloMessage weak_hello = hello;
  weak_hello.host_pubkey.fill(0U);
  expect_lan_err(encode_lan_handshake_frame(weak_hello), LanError::invalid_pubkey,
                 "weak host_pubkey rejected");

  // Welcome invariants: accepted=true requires >=1 member, accepted=false requires 0
  expect_lan_err(encode_lan_handshake_frame(
                     LanWelcomeMessage{"0102030405060708", true, "", 1U, {}}),
                 LanError::frame_invalid_field,
                 "accepted welcome with empty members rejected");
  expect_lan_err(encode_lan_handshake_frame(LanWelcomeMessage{
                     "0102030405060708", false, "pin_invalid", 1U, welcome_ok.members}),
                 LanError::frame_invalid_field,
                 "rejected welcome with non-empty members rejected");

  // 13 members rejected
  auto thirteen = twelve_members;
  thirteen.push_back(LanMemberInfo{13U, "player-13", valid_test_pubkey(0x55U), false});
  expect_lan_err(encode_lan_handshake_frame(
                     LanRosterMessage{"0102030405060708", 1U, false, thirteen}),
                 LanError::frame_too_many_members, "13 members rejected");

  // Duplicate pubkey in roster rejected
  auto dup_members = welcome_ok.members;
  dup_members[1].pubkey = dup_members[0].pubkey;
  expect_lan_err(encode_lan_handshake_frame(
                     LanRosterMessage{"0102030405060708", 1U, false, dup_members}),
                 LanError::frame_invalid_field, "duplicate pubkey rejected");

  // PIN rate limiter (5 per peer, 15 per lobby)
  g_stage = "pin_rate_limiter";
  LanPinRateLimiter limiter{};
  const LanPinPeerKey peer_a{valid_test_pubkey(0x61U), "192.168.1.10"};
  const LanPinPeerKey peer_b{valid_test_pubkey(0x61U),
                             "192.168.1.11"}; // same pk, diff IP
  const LanPinPeerKey peer_c{valid_test_pubkey(0x62U), "192.168.1.12"};
  const LanPinPeerKey peer_d{valid_test_pubkey(0x63U), "192.168.1.13"};

  require(limiter.check(peer_a) == LanPinLockoutStatus::allowed, "initial allowed");
  for (int i = 0; i < 4; ++i) {
    require(limiter.record_failure(peer_a) == LanPinLockoutStatus::allowed,
            "peer_a fails 1..4 allowed");
  }
  require(limiter.record_failure(peer_a) == LanPinLockoutStatus::peer_locked,
          "peer_a 5th failure locks peer");
  require(limiter.is_peer_locked(peer_a) && !limiter.is_lobby_locked(),
          "peer_a locked, lobby still open");
  require(limiter.check(peer_a) == LanPinLockoutStatus::peer_locked,
          "check(peer_a) peer_locked");
  // record_success cannot unlock a locked peer
  limiter.record_success(peer_a);
  require(limiter.is_peer_locked(peer_a), "locked peer stays locked");

  // peer_b (different IP) gets its own 5 attempts (total 6..10)
  require(limiter.check(peer_b) == LanPinLockoutStatus::allowed, "peer_b allowed");
  for (int i = 0; i < 4; ++i) {
    require(limiter.record_failure(peer_b) == LanPinLockoutStatus::allowed,
            "peer_b fails 1..4");
  }
  require(limiter.record_failure(peer_b) == LanPinLockoutStatus::peer_locked,
          "peer_b 5th failure locks peer_b");
  require(limiter.total_failures() == 10U && !limiter.is_lobby_locked(),
          "total failures 10");

  // peer_c records 2 failures then succeeds (clears peer_c count, keeps total=12!)
  require(limiter.record_failure(peer_c) == LanPinLockoutStatus::allowed,
          "peer_c fail 1");
  require(limiter.record_failure(peer_c) == LanPinLockoutStatus::allowed,
          "peer_c fail 2");
  limiter.record_success(peer_c);
  require(limiter.peer_failures(peer_c) == 0U && limiter.total_failures() == 12U,
          "success clears peer count but total stays monotonic");

  // 3 more failures hit 15 -> lobby locked!
  require(limiter.record_failure(peer_c) == LanPinLockoutStatus::allowed, "total 13");
  require(limiter.record_failure(peer_c) == LanPinLockoutStatus::allowed, "total 14");
  require(limiter.record_failure(peer_c) == LanPinLockoutStatus::lobby_locked,
          "total 15 locks lobby");
  require(limiter.is_lobby_locked(), "lobby_locked flag");
  require(limiter.check(peer_d) == LanPinLockoutStatus::lobby_locked,
          "brand new peer blocked when lobby locked");

  limiter.reset();
  require(limiter.total_failures() == 0U && !limiter.is_lobby_locked() &&
              limiter.check(peer_a) == LanPinLockoutStatus::allowed,
          "reset clears state");
}

} // namespace

int main() {
  try {
    test_blake3_and_pin_proof();
    test_policy_engine();
    test_identity_and_safety_number();
    test_local_os_presence_guard();
    test_handshake_framing_and_rate_limiter();
    std::cout << "lan_party_protocol_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL: " << ex.what() << "\n";
    return 1;
  }
}
