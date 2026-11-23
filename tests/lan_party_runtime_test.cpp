#include "blackbird/lan_party_runtime.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace blackbird;
using namespace blackbird::lan;

namespace {

const char *g_stage = "startup";
std::atomic<std::uint64_t> g_tmp_seq{0U};

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(std::string{g_stage} + ": " + message);
  }
}

template <typename T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context + "]: code=" +
                             std::to_string(static_cast<int>(result.error().code)) +
                             " detail=" + std::to_string(result.error().detail));
  }
  return std::move(result).value();
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context + "]: code=" +
                             std::to_string(static_cast<int>(result.error().code)) +
                             " detail=" + std::to_string(result.error().detail));
  }
}
#endif

int count_open_fds() {
#if defined(__APPLE__)
  constexpr const char *kFdDir = "/dev/fd";
#else
  constexpr const char *kFdDir = "/proc/self/fd";
#endif
  DIR *dir = ::opendir(kFdDir);
  require(dir != nullptr, "opendir for FD count must succeed");
  int count = 0;
  while (const dirent *ent = ::readdir(dir)) {
    const std::string_view name(ent->d_name);
    if (name == "." || name == "..") {
      continue;
    }
    ++count;
  }
  (void)::closedir(dir);
  return count > 0 ? count - 1 : 0;
}

class ScopedTempDir {
public:
  explicit ScopedTempDir(std::string_view tag) {
    const auto seq = g_tmp_seq.fetch_add(1U, std::memory_order_relaxed);
    path_ = std::filesystem::temp_directory_path() /
            ("bb_lan_rt_" + std::string{tag} + "_" + std::to_string(::getpid()) + "_" +
             std::to_string(seq));
    std::filesystem::create_directories(path_);
    (void)::chmod(path_.c_str(), mode_t{0700});
  }
  ScopedTempDir(const ScopedTempDir &) = delete;
  ScopedTempDir &operator=(const ScopedTempDir &) = delete;
  ~ScopedTempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path_, ec);
  }
  const std::filesystem::path &path() const noexcept { return path_; }

private:
  std::filesystem::path path_;
};

void write_policy_file(const std::filesystem::path &path, std::string_view content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  require(out.good(), "write_policy_file open must succeed");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.close();
  require(::chmod(path.c_str(), mode_t{0600}) == 0, "chmod 0600 on policy file");
}

void write_user_policy_file(const LanPolicyPaths &paths, std::string_view content) {
  if (!paths.user_policy_path.has_value()) {
    throw std::runtime_error(std::string{g_stage} + ": user_policy_path unset");
  }
  write_policy_file(*paths.user_policy_path, content);
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
template <typename T>
const T &must_opt(const std::optional<T> &opt, const char *message) {
  if (!opt.has_value()) {
    throw std::runtime_error(std::string{g_stage} + ": " + message);
  }
  return *opt;
}
#endif

LanPolicyPaths make_isolated_policy_paths(const std::filesystem::path &dir) {
  LanPolicyPaths paths{};
  paths.system_policy_path = dir / "system_lan.toml";
  paths.user_policy_path = dir / "user_lan.toml";
  paths.expected_system_uid = static_cast<std::uint32_t>(::geteuid());
  paths.expected_user_uid = static_cast<std::uint32_t>(::geteuid());
  return paths;
}

EnvLookupFn make_empty_env() {
  return [](std::string_view) -> std::optional<std::string> { return std::nullopt; };
}

struct TestAccountId {
  std::uint64_t value = 0U;
};

LanIdentity make_test_identity(std::string_view display_name, std::uint8_t seed_byte,
                               TestAccountId account_id = {}) {
  mp::Ed25519Seed raw_seed{};
  for (std::size_t i = 0U; i < raw_seed.size(); ++i) {
    raw_seed[i] = static_cast<std::uint8_t>((seed_byte + i * 13U) & 0xffU);
  }
  const auto sk = must(mp::Ed25519SigningKey::from_seed(raw_seed), "signing key");
  const auto pk = sk.public_key();
  const auto sn =
      must(compute_lan_safety_number(account_id.value, pk), "safety number");

  LanIdentity id{};
  id.account_id = account_id.value;
  id.is_online_identity = account_id.value > 0U;
  id.display_name = std::string{display_name};
  id.public_key = pk;
  id.signing_seed = mp::CleansedSeed{raw_seed};
  id.safety_number = sn;
  return id;
}

LanMdnsSocketConfig make_loopback_mdns_cfg(std::uint16_t target_port = 0U) {
  LanMdnsSocketConfig cfg{};
  cfg.bind_address = "127.0.0.1";
  cfg.bind_port = 0U;
  cfg.target_address = "127.0.0.1";
  cfg.target_port = target_port;
  cfg.enable_multicast = false;
  cfg.advertise_addrs = {P2pDirectAddr::ipv4({127U, 0U, 0U, 1U}, 1U)};
  return cfg;
}

void test_policy_kill_switch_and_local_auth_zero_sockets() {
  g_stage = "policy_kill_switch_and_local_auth_zero_sockets";

  ScopedTempDir dir("policy");
  const LanPolicyPaths isolated = make_isolated_policy_paths(dir.path());
  const LanIdentity host_id = make_test_identity("host-alice", 0x11U);
  const LanIdentity joiner_id = make_test_identity("joiner-bob", 0x22U);

  const int fds_before = count_open_fds();

  // 1. MP_DISABLE_LAN=1 fails closed across start, join, and scan with ZERO sockets.
  auto env_disabled = [](std::string_view key) -> std::optional<std::string> {
    if (key == "MP_DISABLE_LAN") {
      return std::string{"1"};
    }
    return std::nullopt;
  };
  {
    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "quake-night";
    hcfg.pin = "424242";
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = env_disabled;
    hcfg.mdns_socket_cfg = make_loopback_mdns_cfg();
    const auto hres = LanPartyHost::start(std::move(hcfg));
    require(!hres.has_value() && lan_error_of(hres.error()) == LanError::lan_disabled,
            "MP_DISABLE_LAN=1 must fail host start with lan_disabled");
    require(count_open_fds() == fds_before, "host kill-switch must open 0 FDs");

    LanClientConfig ccfg{};
    ccfg.identity = joiner_id;
    ccfg.host_pubkey = host_id.public_key;
    ccfg.direct_targets = {"127.0.0.1:51820"};
    ccfg.policy_paths = isolated;
    ccfg.env_lookup = env_disabled;
    ccfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };
    const auto cres = LanPartyClient::join(std::move(ccfg));
    require(!cres.has_value() && lan_error_of(cres.error()) == LanError::lan_disabled,
            "MP_DISABLE_LAN=1 must fail client join with lan_disabled");
    require(count_open_fds() == fds_before, "client kill-switch must open 0 FDs");

    LanScanConfig scfg{};
    scfg.policy_paths = isolated;
    scfg.env_lookup = env_disabled;
    scfg.mdns_socket_cfg = make_loopback_mdns_cfg();
    const auto sres = scan_lan_lobbies(scfg);
    require(!sres.has_value() && lan_error_of(sres.error()) == LanError::lan_disabled,
            "MP_DISABLE_LAN=1 must fail scan with lan_disabled");
    require(count_open_fds() == fds_before, "scan kill-switch must open 0 FDs");
  }

  // 2. System lan.toml disabled=true overrides user disabled=false (non-overridable
  // floor).
  write_policy_file(isolated.system_policy_path, "[lan]\ndisabled = true\n");
  write_user_policy_file(isolated, "[lan]\ndisabled = false\n");
  {
    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "quake-night";
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = make_empty_env();
    const auto hres = LanPartyHost::start(std::move(hcfg));
    require(!hres.has_value() && lan_error_of(hres.error()) == LanError::lan_disabled,
            "system floor disabled=true must override user disabled=false");

    LanScanConfig scfg{};
    scfg.policy_paths = isolated;
    scfg.env_lookup = make_empty_env();
    const auto sres = scan_lan_lobbies(scfg);
    require(!sres.has_value() && lan_error_of(sres.error()) == LanError::lan_disabled,
            "system floor disabled=true must block scan");
    require(count_open_fds() == fds_before, "system floor disabled must open 0 FDs");
  }

  // 3. System policy require_local_auth=true -> denied prompt fails closed with 0 FDs.
  write_policy_file(isolated.system_policy_path,
                    "[lan]\ndisabled = false\nrequire_local_auth = true\n");
  write_user_policy_file(isolated, "[lan]\nrequire_local_auth = false\n");
  {
    int prompt_calls = 0;
    LocalAuthOptions denied_auth{};
    denied_auth.prompt_override = [&](std::string_view) -> Result<void> {
      ++prompt_calls;
      return Result<void>::failure(
          {ErrorCode::provider_auth,
           static_cast<std::int64_t>(LanError::local_auth_denied)});
    };

    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "quake-night";
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = make_empty_env();
    hcfg.local_auth_options = denied_auth;
    const auto hres = LanPartyHost::start(std::move(hcfg));
    require(!hres.has_value() &&
                lan_error_of(hres.error()) == LanError::local_auth_denied,
            "denied local auth must block host start");

    LanClientConfig ccfg{};
    ccfg.identity = joiner_id;
    ccfg.host_pubkey = host_id.public_key;
    ccfg.direct_targets = {"127.0.0.1:51820"};
    ccfg.policy_paths = isolated;
    ccfg.env_lookup = make_empty_env();
    ccfg.local_auth_options = denied_auth;
    ccfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };
    const auto cres = LanPartyClient::join(std::move(ccfg));
    require(!cres.has_value() &&
                lan_error_of(cres.error()) == LanError::local_auth_denied,
            "denied local auth must block client join");

    LanScanConfig scfg{};
    scfg.policy_paths = isolated;
    scfg.env_lookup = make_empty_env();
    scfg.local_auth_options = denied_auth;
    const auto sres = scan_lan_lobbies(scfg);
    require(!sres.has_value() &&
                lan_error_of(sres.error()) == LanError::local_auth_denied,
            "denied local auth must block scan");

    require(prompt_calls == 3,
            "local auth prompt must be invoked on all 3 entry points");
    require(count_open_fds() == fds_before, "denied local auth must open 0 FDs");
  }

  // 4. System policy require_pin=true rejects empty PIN with LanError::invalid_pin.
  write_policy_file(isolated.system_policy_path,
                    "[lan]\ndisabled = false\nrequire_pin = true\n");
  write_user_policy_file(isolated, "[lan]\nrequire_pin = false\n");
  {
    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "quake-night";
    hcfg.pin.clear();
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = make_empty_env();
    const auto hres = LanPartyHost::start(std::move(hcfg));
    require(!hres.has_value() && lan_error_of(hres.error()) == LanError::invalid_pin,
            "effective.require_pin=true with empty PIN must fail with invalid_pin");

    LanClientConfig ccfg{};
    ccfg.identity = joiner_id;
    ccfg.host_pubkey = host_id.public_key;
    ccfg.direct_targets = {"127.0.0.1:51820"};
    ccfg.pin.clear();
    ccfg.policy_paths = isolated;
    ccfg.env_lookup = make_empty_env();
    ccfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };
    const auto cres = LanPartyClient::join(std::move(ccfg));
    require(!cres.has_value() && lan_error_of(cres.error()) == LanError::invalid_pin,
            "client join with effective.require_pin=true and empty PIN must fail");
    require(count_open_fds() == fds_before, "invalid_pin failure must open 0 FDs");
  }

  // 5. Unpinned client with absent trust_callback fails closed with 0 FDs.
  write_policy_file(isolated.system_policy_path, "[lan]\ndisabled = false\n");
  write_user_policy_file(isolated, "[lan]\ndisabled = false\n");
  {
    LanClientConfig ccfg{};
    ccfg.identity = joiner_id;
    ccfg.host_pubkey = host_id.public_key;
    ccfg.direct_targets = {"127.0.0.1:51820"};
    ccfg.policy_paths = isolated;
    ccfg.env_lookup = make_empty_env();
    ccfg.trust_callback = {};
    const auto cres = LanPartyClient::join(std::move(ccfg));
    require(!cres.has_value() &&
                lan_runtime_error_of(cres.error()) == LanRuntimeError::peer_rejected,
            "unpinned client without trust_callback must fail closed");
    require(count_open_fds() == fds_before,
            "absent trust_callback failure must open 0 FDs");
  }
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

void pump_pair_until(LanPartyHost &host, LanPartyClient &client,
                     const std::function<bool()> &done, int max_ms = 5000) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(max_ms);
  while (std::chrono::steady_clock::now() < deadline && !done()) {
    if (host.active()) {
      (void)host.pump_once(15U);
    }
    if (client.active()) {
      (void)client.pump_once(15U);
    }
  }
}

void test_idle_timeout_auto_shutoff_and_timeout_cap() {
  g_stage = "idle_timeout_auto_shutoff_and_timeout_cap";

  ScopedTempDir dir("idle");
  const LanPolicyPaths isolated = make_isolated_policy_paths(dir.path());
  write_policy_file(isolated.system_policy_path,
                    "[lan]\ndisabled = false\nidle_timeout_sec = 5\n");
  write_user_policy_file(isolated, "[lan]\nidle_timeout_sec = 600\n");

  const int fds_before = count_open_fds();
  {
    LanHostConfig cfg{};
    cfg.identity = make_test_identity("idle-host", 0x31U);
    cfg.lobby_name = "idle-room";
    cfg.idle_timeout_sec = 900U; // Must be capped to system policy floor (5s).
    cfg.policy_paths = isolated;
    cfg.env_lookup = make_empty_env();
    cfg.mdns_socket_cfg = make_loopback_mdns_cfg();

    auto host = must(LanPartyHost::start(std::move(cfg)), "host start idle test");
    require(host.active(), "host must be active after start");
    require(host.effective_idle_timeout_sec() == 5U,
            "host idle_timeout_sec must be capped to system floor 5s");

    // Advance clock past 5s with zero joined peers -> immediate auto-shutoff.
    const auto after_idle = std::chrono::steady_clock::now() + std::chrono::seconds(6);
    (void)must(host.pump_once(0U, after_idle), "pump idle expiry");
    require(host.state() == LanSessionState::timed_out,
            "host must transition to LanSessionState::timed_out on idle expiry");
    require(!host.active(), "timed-out host must not be active");
    const auto events = host.drain_events();
    require(events.size() == 1U && events[0].kind == LanEventKind::lobby_timed_out,
            "host must emit lobby_timed_out event");

    // Subsequent pump after timeout fails closed cleanly.
    const auto after_pump = host.pump_once(0U);
    require(!after_pump.has_value() && lan_runtime_error_of(after_pump.error()) ==
                                           LanRuntimeError::not_running,
            "pump after timeout must return not_running");
    host.stop();
  }
  require(count_open_fds() == fds_before,
          "zero leaked FDs after idle-timeout auto-shutoff");
}

void test_live_iroh_lan_party_e2e() {
  g_stage = "live_iroh_lan_party_e2e";

  ScopedTempDir dir("e2e");
  const LanPolicyPaths isolated = make_isolated_policy_paths(dir.path());
  write_policy_file(isolated.system_policy_path,
                    "[lan]\ndisabled = false\nrequire_pin = true\n"
                    "idle_timeout_sec = 300\nscan_timeout_sec = 10\n");
  write_user_policy_file(isolated, "[lan]\ndisabled = false\n");

  const LanIdentity host_id = make_test_identity("host-alice", 0x41U);
  const LanIdentity bad_pin_id = make_test_identity("wrong-pin-eve", 0x42U);
  const LanIdentity untrusted_id = make_test_identity("untrusted-mallory", 0x43U);
  const LanIdentity joiner_id = make_test_identity("joiner-bob", 0x44U);
  const LanIdentity latecomer_id = make_test_identity("late-charlie", 0x45U);

  const std::string expected_host_sn =
      must(compute_lan_safety_number(0U, host_id.public_key), "expected host sn");
  const std::string expected_joiner_sn =
      must(compute_lan_safety_number(0U, joiner_id.public_key), "expected joiner sn");

  const int fds_before = count_open_fds();
  {
    // Host trusts joiner-bob, rejects untrusted-mallory.
    bool host_rejected_mallory = false;
    bool host_approved_bob = false;
    const auto host_known_peers_dir = dir.path() / "host_known_peers";

    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "Quake 1998";
    hcfg.pin = "424242";
    hcfg.require_pin = true;
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = make_empty_env();
    hcfg.mdns_socket_cfg = make_loopback_mdns_cfg(0U);
    hcfg.known_peers_path = host_known_peers_dir;
    hcfg.trust_callback = [&](const LanPeerTrustPrompt &prompt) -> bool {
      require(prompt.safety_number.size() == mp::kSafetyNumberFormattedLength,
              "host trust prompt must carry canonical 39-char safety number");
      if (prompt.pubkey == untrusted_id.public_key) {
        host_rejected_mallory = true;
        return false;
      }
      if (prompt.pubkey == joiner_id.public_key) {
        require(prompt.safety_number == expected_joiner_sn,
                "host trust prompt safety number for bob must match");
        host_approved_bob = true;
        return true;
      }
      return false;
    };

    auto host = must(LanPartyHost::start(std::move(hcfg)), "start live LAN host");
    require(host.active() && host.pin_required() && host.service_port() > 0U,
            "host must be active with PIN required and bound UDP port");
    require(!host.direct_targets().empty(), "host must expose direct ip:port targets");
    require(host.lan_party_id().size() == kLanPartyIdHexLen,
            "host must generate 16-hex lan_party_id");
    require(host.mdns_bound_port() > 0U,
            "host mDNS advertiser must bind loopback port");

    // 1. scan_lan_lobbies discovers host via loopback mDNS + verifies canonical Safety
    // Number!
    LanScanConfig scfg{};
    scfg.scan_timeout_sec = 5U;
    scfg.poll_step_ms = 20U;
    scfg.query_interval_ms = 100U;
    scfg.policy_paths = isolated;
    scfg.env_lookup = make_empty_env();
    scfg.mdns_socket_cfg = make_loopback_mdns_cfg(host.mdns_bound_port());
    scfg.on_poll_tick = [&]() { (void)host.pump_once(10U); };
    scfg.stop_when = [](const std::vector<DiscoveredLanLobbyInfo> &found) {
      return !found.empty();
    };

    const auto lobbies = must(scan_lan_lobbies(scfg), "scan_lan_lobbies");
    require(lobbies.size() == 1U, "scanner must discover exactly 1 LAN lobby");
    const auto &discovered = lobbies[0];
    require(discovered.lobby.beacon.lan_party_id == host.lan_party_id(),
            "discovered lan_party_id must match host");
    require(discovered.lobby.beacon.lobby_name == "Quake 1998",
            "discovered lobby_name must match");
    require(discovered.lobby.beacon.host_pubkey == host_id.public_key,
            "discovered host_pubkey must match");
    require(discovered.lobby.beacon.require_pin, "discovered beacon must set pin=1");
    require(discovered.lobby.service_port == host.service_port(),
            "discovered service port must match iroh bound port");
    require(discovered.safety_number == expected_host_sn,
            "discovered canonical Safety Number must match host pubkey");

    // 2. Wrong-PIN joiner is rejected ("invalid_pin"), increments rate limiter, and
    // disconnects cleanly.
    {
      LanClientConfig bad_cfg{};
      bad_cfg.identity = bad_pin_id;
      bad_cfg.host_pubkey = host_id.public_key;
      bad_cfg.host_addrs = host.direct_addrs();
      bad_cfg.expected_lan_party_id = host.lan_party_id();
      bad_cfg.pin = "000000";
      bad_cfg.policy_paths = isolated;
      bad_cfg.env_lookup = make_empty_env();
      bad_cfg.trust_callback = [&](const LanPeerTrustPrompt &p) {
        return p.safety_number == expected_host_sn;
      };

      auto bad_client =
          must(LanPartyClient::join(std::move(bad_cfg)), "wrong-pin join");
      pump_pair_until(host, bad_client, [&]() {
        return bad_client.state() == LanSessionState::rejected ||
               bad_client.state() == LanSessionState::disconnected;
      });
      require(bad_client.state() == LanSessionState::rejected,
              "wrong-PIN client must transition to rejected");
      require(bad_client.last_rejection_reason() == "invalid_pin",
              "wrong-PIN client must receive invalid_pin rejection reason");
      require(host.pin_rate_limiter().total_failures() == 1U,
              "host PIN rate limiter must increment total failures to 1");
      require(host.members().size() == 1U,
              "wrong-PIN peer must not be added to host roster");
      bad_client.stop();
    }

    // 3a. Unpinned peer rejected by HOST trust callback fails closed cleanly.
    {
      LanClientConfig mal_cfg{};
      mal_cfg.identity = untrusted_id;
      mal_cfg.host_pubkey = host_id.public_key;
      mal_cfg.host_addrs = host.direct_addrs();
      mal_cfg.expected_lan_party_id = host.lan_party_id();
      mal_cfg.pin = "424242";
      mal_cfg.policy_paths = isolated;
      mal_cfg.env_lookup = make_empty_env();
      mal_cfg.trust_callback = [&](const LanPeerTrustPrompt &p) {
        return p.safety_number == expected_host_sn;
      };

      auto mal_client =
          must(LanPartyClient::join(std::move(mal_cfg)), "untrusted peer join");
      pump_pair_until(host, mal_client, [&]() {
        return mal_client.state() == LanSessionState::rejected ||
               mal_client.state() == LanSessionState::disconnected;
      });
      require(host_rejected_mallory, "host trust callback must be called for mallory");
      require(mal_client.state() == LanSessionState::rejected &&
                  mal_client.last_rejection_reason() == "rejected",
              "untrusted peer must receive rejected welcome and disconnect");
      require(host.members().size() == 1U,
              "rejected unpinned peer must not enter host roster");
      mal_client.stop();
    }

    // 3b. Unpinned host rejected by CLIENT trust callback fails closed BEFORE sending
    // LAN_JOIN/PIN proof!
    {
      bool client_rejected_host = false;
      LanClientConfig rej_cfg{};
      rej_cfg.identity = joiner_id;
      rej_cfg.host_pubkey = host_id.public_key;
      rej_cfg.host_addrs = host.direct_addrs();
      rej_cfg.expected_lan_party_id = host.lan_party_id();
      rej_cfg.pin =
          "999999"; // Even wrong PIN must never be sent if client rejects host!
      rej_cfg.policy_paths = isolated;
      rej_cfg.env_lookup = make_empty_env();
      rej_cfg.trust_callback = [&](const LanPeerTrustPrompt &p) {
        require(p.safety_number == expected_host_sn && p.is_host,
                "client trust prompt must present host canonical Safety Number");
        client_rejected_host = true;
        return false;
      };

      auto rej_client =
          must(LanPartyClient::join(std::move(rej_cfg)), "client rejects host");
      pump_pair_until(host, rej_client, [&]() {
        return rej_client.state() == LanSessionState::rejected;
      });
      require(client_rejected_host, "client trust callback must be invoked");
      require(rej_client.state() == LanSessionState::rejected &&
                  rej_client.last_rejection_reason() == "rejected",
              "client rejecting host must transition to rejected");
      require(host.pin_rate_limiter().total_failures() == 1U,
              "client rejecting host must NEVER send PIN proof to host");
      rej_client.stop();
    }

    // 4. Correct-PIN + approved Safety Number joiner completes LAN_HELLO -> LAN_JOIN ->
    //    LAN_WELCOME, joins roster, exchanges bidirectional P2pPartyFrame chat with
    //    ANSI/BiDi sanitization + strict anti-spoofing, and host lock_lobby() blocks a
    //    3rd joiner while keeping bob live!
    {
      (void)host.drain_events();
      const auto client_known_peers_dir = dir.path() / "client_known_peers";
      bool client_approved_host = false;

      LanClientConfig bob_cfg{};
      bob_cfg.identity = joiner_id;
      bob_cfg.host_pubkey = host_id.public_key;
      bob_cfg.direct_targets = host.direct_targets(); // Exercises Quake ip:port parser!
      bob_cfg.expected_lan_party_id = host.lan_party_id();
      bob_cfg.pin = "424242";
      bob_cfg.policy_paths = isolated;
      bob_cfg.env_lookup = make_empty_env();
      bob_cfg.known_peers_path = client_known_peers_dir;
      bob_cfg.trust_callback = [&](const LanPeerTrustPrompt &p) {
        require(p.safety_number == expected_host_sn,
                "bob trust prompt must show host safety number");
        client_approved_host = true;
        return true;
      };

      auto bob = must(LanPartyClient::join(std::move(bob_cfg)), "bob join");
      pump_pair_until(host, bob,
                      [&]() { return bob.connected() && host.members().size() == 2U; });
      require(client_approved_host && host_approved_bob,
              "both host and bob must verify Safety Numbers");
      require(bob.connected(), "bob must reach LanSessionState::connected");
      require(host.members().size() == 2U && bob.members().size() == 2U,
              "host and bob must both have 2 roster members");

      const auto host_join_events = host.drain_events();
      bool saw_member_joined = false;
      for (const auto &ev : host_join_events) {
        if (ev.kind == LanEventKind::member_joined &&
            ev.peer_pubkey == joiner_id.public_key && ev.sender_name == "joiner-bob") {
          saw_member_joined = true;
        }
      }
      require(saw_member_joined, "host must emit member_joined for bob");
      (void)bob.drain_events();

      // Bidirectional chat with hostile ANSI ESC + BiDi RLO payload -> sanitized!
      const std::string hostile_body = "gg \x1b[31mred\x1b[0m \xe2\x80\xaespoofed";
      must_void(bob.send_chat(hostile_body, "@all"), "bob send_chat");

      std::optional<LanEvent> host_chat_ev;
      pump_pair_until(host, bob, [&]() {
        for (auto &ev : host.drain_events()) {
          if (ev.kind == LanEventKind::chat_received) {
            host_chat_ev = std::move(ev);
            return true;
          }
        }
        return false;
      });
      const auto &host_chat = must_opt(host_chat_ev, "host must receive bob chat");
      const auto &host_chat_msg = must_opt(host_chat.chat, "host chat payload");
      require(host_chat.sender_name == "joiner-bob" &&
                  host_chat_msg.sender_handle == "joiner-bob",
              "host must strictly attribute sender from authenticated members_ table");
      require(host_chat_msg.body.find('\x1b') == std::string::npos,
              "ANSI ESC must be sanitized from chat body");
      require(host_chat_msg.body.find("\xe2\x80\xae") == std::string::npos,
              "Unicode BiDi RLO must be sanitized from chat body");
      require(host_chat_msg.body.find("gg ") != std::string::npos,
              "printable chat text must be preserved");

      // Host replies to bob via send_chat.
      must_void(host.send_chat("welcome to 1998", "@all"), "host send_chat");
      std::optional<LanEvent> bob_chat_ev;
      pump_pair_until(host, bob, [&]() {
        for (auto &ev : bob.drain_events()) {
          if (ev.kind == LanEventKind::chat_received) {
            bob_chat_ev = std::move(ev);
            return true;
          }
        }
        return false;
      });
      const auto &bob_chat = must_opt(bob_chat_ev, "bob must receive host chat");
      const auto &bob_chat_msg = must_opt(bob_chat.chat, "bob chat payload");
      require(bob_chat_msg.sender_handle == "host-alice" &&
                  bob_chat_msg.body == "welcome to 1998",
              "bob received chat sender/body must match");

      // Ephemeral pulse from bob -> host.
      must_void(bob.send_pulse(P2pPartyActivityState::working, "compiling"),
                "bob send_pulse");
      std::optional<LanEvent> host_pulse_ev;
      pump_pair_until(host, bob, [&]() {
        for (auto &ev : host.drain_events()) {
          if (ev.kind == LanEventKind::pulse_received) {
            host_pulse_ev = std::move(ev);
            return true;
          }
        }
        return false;
      });
      const auto &host_pulse = must_opt(host_pulse_ev, "host must receive pulse");
      const auto &host_pulse_msg = must_opt(host_pulse.pulse, "host pulse payload");
      require(host_pulse_msg.activity_state == P2pPartyActivityState::working &&
                  host_pulse_msg.status == "compiling",
              "host must receive bob ephemeral pulse");

      // 5. host.lock_lobby() blocks a 3rd joiner while keeping bob live!
      must_void(host.lock_lobby(), "host lock_lobby");
      require(host.locked(), "host must report locked()==true");

      // Bob receives updated locked roster.
      pump_pair_until(host, bob, [&]() { return bob.lobby_locked(); });
      require(bob.lobby_locked(), "bob must observe lobby_locked==true via LAN_ROSTER");

      // Latecomer is immediately blocked by iroh closed open-admission.
      LanClientConfig late_cfg{};
      late_cfg.identity = latecomer_id;
      late_cfg.host_pubkey = host_id.public_key;
      late_cfg.host_addrs = host.direct_addrs();
      late_cfg.pin = "424242";
      late_cfg.policy_paths = isolated;
      late_cfg.env_lookup = make_empty_env();
      late_cfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };
      const auto late_res = LanPartyClient::join(std::move(late_cfg));
      require(!late_res.has_value(),
              "locked lobby must block un-allowlisted 3rd joiner");

      // Bob remains connected and can still exchange chat after lobby lock!
      must_void(bob.send_chat("still live after lock", "@all"), "bob chat after lock");
      std::optional<LanEvent> post_lock_ev;
      pump_pair_until(host, bob, [&]() {
        for (auto &ev : host.drain_events()) {
          if (ev.kind == LanEventKind::chat_received) {
            post_lock_ev = std::move(ev);
            return true;
          }
        }
        return false;
      });
      const auto &post_lock = must_opt(post_lock_ev, "post-lock chat event");
      const auto &post_lock_msg = must_opt(post_lock.chat, "post-lock chat payload");
      require(post_lock_msg.body == "still live after lock",
              "admitted bob must remain live after lock_lobby");

      // 6. Host kicks bob -> bob observes disconnect and host roster drops back to 1.
      must_void(host.kick_peer(joiner_id.public_key), "host kick bob");
      require(host.members().size() == 1U,
              "kicked bob must be removed from host roster");
      pump_pair_until(host, bob,
                      [&]() { return bob.state() == LanSessionState::disconnected; });
      require(bob.state() == LanSessionState::disconnected,
              "kicked bob must transition to disconnected");

      bob.stop();
      bob.stop(); // idempotent
    }

    host.stop();
    host.stop(); // idempotent
  }
  require(count_open_fds() == fds_before,
          "zero leaked FDs after full live LAN Party E2E");
}

void test_anti_spoofing_raw_forged_sender_handle() {
  g_stage = "anti_spoofing_raw_forged_sender_handle";

  ScopedTempDir dir("antispoof");
  const LanPolicyPaths isolated = make_isolated_policy_paths(dir.path());
  write_policy_file(isolated.system_policy_path, "[lan]\ndisabled = false\n");
  write_user_policy_file(isolated, "[lan]\ndisabled = false\n");

  const LanIdentity host_id = make_test_identity("real-host", 0x51U);
  const LanIdentity spoof_id = make_test_identity("real-eve", 0x52U);

  const int fds_before = count_open_fds();
  {
    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "antispoof-room";
    hcfg.enable_mdns = false;
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = make_empty_env();
    hcfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

    auto host = must(LanPartyHost::start(std::move(hcfg)), "start antispoof host");

    // Raw P2pEndpoint impersonating "real-host" in P2pPartyChatMessage::sender_handle!
    P2pEndpointConfig ep_cfg{};
    ep_cfg.relay_policy = P2pRelayPolicy::no_relays;
    ep_cfg.secret_key = spoof_id.signing_seed.bytes();
    auto raw_eve = must(P2pEndpoint::create(ep_cfg), "create raw eve");
    must_void(raw_eve.allow_peer(host_id.public_key), "eve allow host");
    P2pPeerTarget tgt{};
    tgt.pubkey = host_id.public_key;
    tgt.remote_relay_policy = P2pRelayPolicy::no_relays;
    tgt.direct_addrs = host.direct_addrs();
    must_void(raw_eve.connect_peer(tgt), "eve connect host");

    // Complete handshake manually.
    std::optional<LanHelloMessage> got_hello;
    const auto dl1 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < dl1 && !got_hello.has_value()) {
      (void)host.pump_once(15U);
      const auto ev = must(raw_eve.poll_event(15U), "eve poll hello");
      if (ev.has_value() && ev->kind == P2pEventKind::frame_received) {
        const auto dec =
            must(decode_lan_handshake_frame(ev->lane, ev->payload), "decode hello");
        got_hello = std::get<LanHelloMessage>(dec);
      }
    }
    const auto &hello_msg = must_opt(got_hello, "raw eve must receive LAN_HELLO");

    LanJoinMessage join{};
    join.lan_party_id = hello_msg.lan_party_id;
    join.display_name = "real-eve";
    join.account_id = 0U;
    const auto join_bytes = must(encode_lan_handshake_frame(join), "encode join");
    must_void(raw_eve.send_frame(host_id.public_key, P2pLane::control, join_bytes),
              "eve send join");

    bool welcomed = false;
    const auto dl2 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < dl2 && !welcomed) {
      (void)host.pump_once(15U);
      const auto ev = must(raw_eve.poll_event(15U), "eve poll welcome");
      if (ev.has_value() && ev->kind == P2pEventKind::frame_received) {
        const auto dec =
            must(decode_lan_handshake_frame(ev->lane, ev->payload), "decode welcome");
        if (const auto *w = std::get_if<LanWelcomeMessage>(&dec)) {
          welcomed = w->accepted;
        }
      }
    }
    require(welcomed, "raw eve must be admitted");
    (void)host.drain_events();

    // Send a chat frame with FORGED sender_handle = "real-host" + ANSI escape!
    P2pPartyChatMessage forged{};
    forged.room_scope = "lan/party";
    forged.target_selector = "@all";
    forged.sender_handle = "real-host";
    forged.timestamp_ns = 123456;
    forged.body = "forged \x1b]0;pwn\x07 msg";
    const auto forged_bytes = must(encode_p2p_party_frame(forged), "encode forged");
    must_void(raw_eve.send_frame(host_id.public_key, P2pLane::causal, forged_bytes),
              "eve send forged chat");

    std::optional<LanEvent> got_chat;
    const auto dl3 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < dl3 && !got_chat.has_value()) {
      (void)host.pump_once(15U);
      for (auto &ev : host.drain_events()) {
        if (ev.kind == LanEventKind::chat_received) {
          got_chat = std::move(ev);
          break;
        }
      }
    }
    const auto &chat_ev = must_opt(got_chat, "host must receive forged chat");
    const auto &chat_msg = must_opt(chat_ev.chat, "forged chat payload");
    require(chat_ev.sender_name == "real-eve" && chat_msg.sender_handle == "real-eve",
            "host MUST overwrite forged sender_handle with authenticated roster name");
    require(chat_msg.body.find('\x1b') == std::string::npos &&
                chat_msg.body.find('\x07') == std::string::npos,
            "host MUST sanitize OSC ESC/BEL sequences from body");

    raw_eve.close();
    host.stop();
  }
  require(count_open_fds() == fds_before, "zero leaked FDs after anti-spoofing test");
}

void test_pin_lobby_lockout_teardown_and_known_peers_pinning() {
  g_stage = "pin_lobby_lockout_teardown_and_known_peers_pinning";

  ScopedTempDir dir("lockout");
  const LanPolicyPaths isolated = make_isolated_policy_paths(dir.path());
  write_policy_file(isolated.system_policy_path,
                    "[lan]\ndisabled = false\nrequire_pin = true\n");
  write_user_policy_file(isolated, "[lan]\ndisabled = false\n");

  const LanIdentity host_id = make_test_identity("lock-host", 0x61U);
  const LanIdentity attacker_id = make_test_identity("attacker", 0x62U);

  const int fds_before = count_open_fds();
  {
    // Configure tight lobby lockout threshold = 2 failures to test full lobby teardown
    // cleanly without waiting for 15 sequential QUIC handshakes.
    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "lockout-room";
    hcfg.pin = "secret99";
    hcfg.require_pin = true;
    hcfg.enable_mdns = false;
    hcfg.policy_paths = isolated;
    hcfg.env_lookup = make_empty_env();
    hcfg.pin_rate_limit =
        LanPinRateLimitConfig{.max_peer_failures = 5U, .max_lobby_failures = 2U};
    hcfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

    auto host = must(LanPartyHost::start(std::move(hcfg)), "start lockout host");

    for (int attempt = 0; attempt < 2; ++attempt) {
      LanClientConfig acfg{};
      acfg.identity = attacker_id;
      acfg.host_pubkey = host_id.public_key;
      acfg.host_addrs = host.direct_addrs();
      acfg.pin = "wrongpin";
      acfg.policy_paths = isolated;
      acfg.env_lookup = make_empty_env();
      acfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

      auto att = must(LanPartyClient::join(std::move(acfg)), "attacker attempt");
      pump_pair_until(host, att, [&]() {
        return att.state() == LanSessionState::rejected ||
               att.state() == LanSessionState::disconnected;
      });
      require(att.state() == LanSessionState::rejected,
              "attacker must be rejected on wrong PIN");
      if (attempt == 0) {
        require(att.last_rejection_reason() == "invalid_pin",
                "first wrong PIN must return invalid_pin");
        require(host.active(), "host stays active after 1st failure");
      } else {
        require(att.last_rejection_reason() == "locked",
                "lobby lockout threshold must return locked");
      }
      att.stop();
    }

    require(host.state() == LanSessionState::locked_out && !host.active(),
            "host must tear down and transition to locked_out on lobby PIN lockout");
    host.stop();
  }

  // KnownPeersStore auto-trust on reconnect (no trust_callback needed once pinned),
  // revoked peer fail-closed, and lobby-full ("full") rejection!
  {
    const auto host_kp = dir.path() / "kp_host";
    const auto bob_kp = dir.path() / "kp_bob";
    const LanIdentity bob_id = make_test_identity("pinned-bob", 0x63U);
    const LanIdentity carol_id = make_test_identity("overflow-carol", 0x64U);

    // 1. First session pins bob on host and host on bob.
    {
      LanHostConfig hcfg{};
      hcfg.identity = host_id;
      hcfg.lobby_name = "pin-store-room";
      hcfg.pin = "123456";
      hcfg.require_pin = true;
      hcfg.max_members = 2U; // host + 1 peer -> tests "full"!
      hcfg.enable_mdns = false;
      hcfg.policy_paths = isolated;
      hcfg.env_lookup = make_empty_env();
      hcfg.known_peers_path = host_kp;
      hcfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

      auto host = must(LanPartyHost::start(std::move(hcfg)), "start kp host 1");

      LanClientConfig bcfg{};
      bcfg.identity = bob_id;
      bcfg.host_pubkey = host_id.public_key;
      bcfg.host_addrs = host.direct_addrs();
      bcfg.pin = "123456";
      bcfg.policy_paths = isolated;
      bcfg.env_lookup = make_empty_env();
      bcfg.known_peers_path = bob_kp;
      bcfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

      auto bob = must(LanPartyClient::join(std::move(bcfg)), "bob kp join 1");
      pump_pair_until(host, bob, [&]() { return bob.connected(); });
      require(bob.connected(), "bob must connect and get pinned in KnownPeersStore");

      // While bob is connected (2/2 members), carol must be rejected with "full"!
      LanClientConfig ccfg{};
      ccfg.identity = carol_id;
      ccfg.host_pubkey = host_id.public_key;
      ccfg.host_addrs = host.direct_addrs();
      ccfg.pin = "123456";
      ccfg.policy_paths = isolated;
      ccfg.env_lookup = make_empty_env();
      ccfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

      auto carol = must(LanPartyClient::join(std::move(ccfg)), "carol full join");
      pump_pair_until(host, carol, [&]() {
        return carol.state() == LanSessionState::rejected ||
               carol.state() == LanSessionState::disconnected;
      });
      require(carol.state() == LanSessionState::rejected &&
                  carol.last_rejection_reason() == "full",
              "overflow joiner must be rejected with reason 'full'");
      carol.stop();
      bob.stop();
      host.stop();
    }

    // 2. Second session reconnects with ABSENT trust_callback on both sides using
    //    KnownPeersStore pinning!
    {
      LanHostConfig hcfg{};
      hcfg.identity = host_id;
      hcfg.lobby_name = "pin-store-room-2";
      hcfg.pin = "123456";
      hcfg.require_pin = true;
      hcfg.enable_mdns = false;
      hcfg.policy_paths = isolated;
      hcfg.env_lookup = make_empty_env();
      hcfg.known_peers_path = host_kp;
      hcfg.trust_callback = {}; // Pinned peer must NOT require callback!

      auto host = must(LanPartyHost::start(std::move(hcfg)), "start kp host 2");

      LanClientConfig bcfg{};
      bcfg.identity = bob_id;
      bcfg.host_pubkey = host_id.public_key;
      bcfg.host_addrs = host.direct_addrs();
      bcfg.pin = "123456";
      bcfg.policy_paths = isolated;
      bcfg.env_lookup = make_empty_env();
      bcfg.known_peers_path = bob_kp;
      bcfg.trust_callback = {}; // Pinned host must NOT require callback!

      auto bob = must(LanPartyClient::join(std::move(bcfg)), "bob pinned reconnect");
      pump_pair_until(host, bob, [&]() { return bob.connected(); });
      require(bob.connected(), "pinned bob must reconnect without trust_callback");
      bob.stop();

      // 3. Revoking bob in host's KnownPeersStore blocks bob even if trust_callback
      //    returns true!
      auto store = must(KnownPeersStore::open(host_kp), "open host KnownPeersStore");
      const auto bob_ssh =
          must(lan_pubkey_to_ssh_ed25519(bob_id.public_key), "bob ssh");
      const auto bob_fp = must(peer_fingerprint_from_public_key(bob_ssh), "bob fp");
      (void)must(store.revoke_peer({bob_fp, "compromised"}), "revoke bob");

      LanClientConfig rev_cfg{};
      rev_cfg.identity = bob_id;
      rev_cfg.host_pubkey = host_id.public_key;
      rev_cfg.host_addrs = host.direct_addrs();
      rev_cfg.pin = "123456";
      rev_cfg.policy_paths = isolated;
      rev_cfg.env_lookup = make_empty_env();
      rev_cfg.known_peers_path = bob_kp;
      auto rev_bob = must(LanPartyClient::join(std::move(rev_cfg)), "revoked bob join");
      pump_pair_until(host, rev_bob, [&]() {
        return rev_bob.state() == LanSessionState::rejected ||
               rev_bob.state() == LanSessionState::disconnected;
      });
      require(rev_bob.state() == LanSessionState::rejected &&
                  rev_bob.last_rejection_reason() == "rejected",
              "revoked peer in KnownPeersStore must be rejected fail-closed");
      rev_bob.stop();
      host.stop();
    }
  }
  require(count_open_fds() == fds_before, "zero leaked FDs after PIN lockout test");
}

void test_policy_pin_floor_online_safety_number_and_pending_timeout() {
  g_stage = "policy_pin_floor_online_safety_number_and_pending_timeout";

  ScopedTempDir dir("hardening");
  const LanPolicyPaths open_policy = make_isolated_policy_paths(dir.path());
  write_policy_file(open_policy.system_policy_path,
                    "[lan]\ndisabled = false\nrequire_pin = false\n");
  write_user_policy_file(open_policy, "[lan]\ndisabled = false\n");

  const auto strict_dir = dir.path() / "strict";
  std::filesystem::create_directories(strict_dir);
  (void)::chmod(strict_dir.c_str(), mode_t{0700});
  const LanPolicyPaths strict_policy = make_isolated_policy_paths(strict_dir);
  write_policy_file(strict_policy.system_policy_path,
                    "[lan]\ndisabled = false\nrequire_pin = true\n");
  write_user_policy_file(strict_policy, "[lan]\nrequire_pin = false\n");

  const int fds_before = count_open_fds();

  // 1. Client effective.require_pin=true MUST reject a PIN-less host (hello.require_pin
  //    == false) with reason "pin_required" instead of downgrading!
  {
    const LanIdentity host_id = make_test_identity("pinless-host", 0x81U);
    const LanIdentity client_id = make_test_identity("strict-client", 0x82U);

    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "no-pin-lobby";
    hcfg.pin.clear();
    hcfg.require_pin = false;
    hcfg.enable_mdns = false;
    hcfg.policy_paths = open_policy;
    hcfg.env_lookup = make_empty_env();
    hcfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

    auto host = must(LanPartyHost::start(std::move(hcfg)), "start pinless host");
    require(!host.pin_required(), "host must be PIN-less");

    bool trust_cb_called = false;
    LanClientConfig ccfg{};
    ccfg.identity = client_id;
    ccfg.host_pubkey = host_id.public_key;
    ccfg.host_addrs = host.direct_addrs();
    ccfg.pin = "123456"; // Client supplied a PIN to satisfy local policy.
    ccfg.policy_paths = strict_policy;
    ccfg.env_lookup = make_empty_env();
    ccfg.trust_callback = [&](const LanPeerTrustPrompt &) {
      trust_cb_called = true;
      return true;
    };

    auto client = must(LanPartyClient::join(std::move(ccfg)), "strict client dials");
    pump_pair_until(host, client, [&]() {
      return client.state() == LanSessionState::rejected ||
             client.state() == LanSessionState::disconnected;
    });
    require(client.state() == LanSessionState::rejected &&
                client.last_rejection_reason() == "pin_required",
            "client with policy require_pin=true must reject PIN-less host");
    require(!trust_cb_called,
            "policy require_pin downgrade must fail before trust callback/LAN_JOIN");
    require(host.members().size() == 1U, "strict client must not join PIN-less host");
    client.stop();
    host.stop();
  }

  // 2. Registered online identities (account_id > 0) MUST match Safety Numbers across
  //    host.safety_number(), host trust prompt, and client trust prompt!
  {
    const LanIdentity online_host =
        make_test_identity("online-alice", 0x83U, TestAccountId{1001U});
    const LanIdentity online_bob =
        make_test_identity("online-bob", 0x84U, TestAccountId{2002U});
    const std::string sn_zero_host =
        must(compute_lan_safety_number(0U, online_host.public_key), "zero sn host");
    require(online_host.safety_number != sn_zero_host,
            "online account_id > 0 safety number must differ from account_id == 0");

    bool host_verified_bob_sn = false;
    bool client_verified_host_sn = false;

    LanHostConfig hcfg{};
    hcfg.identity = online_host;
    hcfg.lobby_name = "online-sn-room";
    hcfg.pin = "777888";
    hcfg.require_pin = true;
    hcfg.enable_mdns = false;
    hcfg.policy_paths = open_policy;
    hcfg.env_lookup = make_empty_env();
    hcfg.trust_callback = [&](const LanPeerTrustPrompt &prompt) {
      require(prompt.account_id == 2002U, "host prompt must carry joiner account_id");
      require(prompt.safety_number == online_bob.safety_number,
              "host prompt Safety Number must match registered joiner account_id > 0");
      host_verified_bob_sn = true;
      return true;
    };

    auto host = must(LanPartyHost::start(std::move(hcfg)), "start online-id host");
    require(host.safety_number() == online_host.safety_number,
            "host.safety_number() must use host account_id");

    LanClientConfig ccfg{};
    ccfg.identity = online_bob;
    ccfg.host_pubkey = online_host.public_key;
    ccfg.host_addrs = host.direct_addrs();
    ccfg.pin = "777888";
    ccfg.policy_paths = open_policy;
    ccfg.env_lookup = make_empty_env();
    ccfg.trust_callback = [&](const LanPeerTrustPrompt &prompt) {
      require(prompt.account_id == 1001U, "client prompt must carry host account_id");
      require(prompt.safety_number == host.safety_number(),
              "client prompt Safety Number must match host.safety_number()");
      client_verified_host_sn = true;
      return true;
    };

    auto bob = must(LanPartyClient::join(std::move(ccfg)), "online bob join");
    pump_pair_until(host, bob, [&]() { return bob.connected(); });
    require(bob.connected(), "online-identity bob must connect");
    require(host_verified_bob_sn && client_verified_host_sn,
            "both sides must verify matching account_id > 0 Safety Numbers");
    require(bob.host_safety_number() == host.safety_number(),
            "client host_safety_number() must equal host.safety_number()");
    bob.stop();
    host.stop();
  }

  // 3. Pending-handshake Slowloris protection: silent peer never sending LAN_JOIN is
  //    evicted and revoked once now >= connected_at + kLanPendingHandshakeTimeoutSec!
  {
    const LanIdentity host_id = make_test_identity("slowloris-host", 0x85U);
    const LanIdentity silent_id = make_test_identity("silent-peer", 0x86U);

    LanHostConfig hcfg{};
    hcfg.identity = host_id;
    hcfg.lobby_name = "slowloris-room";
    hcfg.enable_mdns = false;
    hcfg.policy_paths = open_policy;
    hcfg.env_lookup = make_empty_env();
    hcfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };

    auto host = must(LanPartyHost::start(std::move(hcfg)), "start slowloris host");

    P2pEndpointConfig ep_cfg{};
    ep_cfg.relay_policy = P2pRelayPolicy::no_relays;
    ep_cfg.secret_key = silent_id.signing_seed.bytes();
    auto silent = must(P2pEndpoint::create(ep_cfg), "create silent peer");
    must_void(silent.allow_peer(host_id.public_key), "silent allow host");
    P2pPeerTarget tgt{};
    tgt.pubkey = host_id.public_key;
    tgt.remote_relay_policy = P2pRelayPolicy::no_relays;
    tgt.direct_addrs = host.direct_addrs();
    must_void(silent.connect_peer(tgt), "silent connect host");

    // Wait for host to accept pending connection and send LAN_HELLO.
    const auto dl = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < dl && host.pending_peer_count() == 0U) {
      (void)host.pump_once(15U);
    }
    require(host.pending_peer_count() == 1U,
            "host must track silent peer in pending_peers_");
    (void)host.drain_events();

    // Advance deterministic clock past kLanPendingHandshakeTimeoutSec (15s).
    const auto expired_now = std::chrono::steady_clock::now() +
                             std::chrono::seconds(kLanPendingHandshakeTimeoutSec + 1U);
    (void)must(host.pump_once(0U, expired_now), "pump pending handshake timeout");
    require(host.pending_peer_count() == 0U,
            "stalled pending peer must be evicted after handshake timeout");

    bool saw_timeout_reject = false;
    for (const auto &ev : host.drain_events()) {
      if (ev.kind == LanEventKind::member_rejected &&
          ev.peer_pubkey == silent_id.public_key && ev.reason == "handshake_timeout") {
        saw_timeout_reject = true;
      }
    }
    require(saw_timeout_reject,
            "host must emit member_rejected with reason handshake_timeout");

    // Silent peer must observe disconnect after host revocation.
    bool saw_disc = false;
    const auto dl2 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < dl2 && !saw_disc) {
      const auto ev = must(silent.poll_event(25U), "silent poll disconnect");
      if (ev.has_value() && ev->kind == P2pEventKind::peer_disconnected) {
        saw_disc = true;
      }
    }
    require(saw_disc, "revoked silent peer must observe peer_disconnected");

    silent.close();
    host.stop();
  }

  require(count_open_fds() == fds_before,
          "zero leaked FDs after hardening regression tests");
}

#else

void test_without_iroh_fails_closed_cleanly() {
  g_stage = "without_iroh_fails_closed_cleanly";

  ScopedTempDir dir("noiroh");
  const LanPolicyPaths isolated = make_isolated_policy_paths(dir.path());
  write_policy_file(isolated.system_policy_path, "[lan]\ndisabled = false\n");
  write_user_policy_file(isolated, "[lan]\ndisabled = false\n");

  const int fds_before = count_open_fds();
  LanHostConfig hcfg{};
  hcfg.identity = make_test_identity("noiroh-host", 0x71U);
  hcfg.lobby_name = "noiroh-room";
  hcfg.policy_paths = isolated;
  hcfg.env_lookup = make_empty_env();
  const auto hres = LanPartyHost::start(std::move(hcfg));
  require(!hres.has_value() && hres.error().code == ErrorCode::unsupported,
          "LanPartyHost::start without iroh must return ErrorCode::unsupported");

  LanClientConfig ccfg{};
  ccfg.identity = make_test_identity("noiroh-joiner", 0x72U);
  ccfg.host_pubkey = make_test_identity("noiroh-host", 0x71U).public_key;
  ccfg.direct_targets = {"127.0.0.1:51820"};
  ccfg.policy_paths = isolated;
  ccfg.env_lookup = make_empty_env();
  ccfg.trust_callback = [](const LanPeerTrustPrompt &) { return true; };
  const auto cres = LanPartyClient::join(std::move(ccfg));
  require(!cres.has_value() && cres.error().code == ErrorCode::unsupported,
          "LanPartyClient::join without iroh must return ErrorCode::unsupported");
  require(count_open_fds() == fds_before,
          "without-iroh fail-closed must leak zero FDs");
}

#endif

} // namespace

int main() {
  try {
    test_policy_kill_switch_and_local_auth_zero_sockets();
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
    test_idle_timeout_auto_shutoff_and_timeout_cap();
    test_live_iroh_lan_party_e2e();
    test_anti_spoofing_raw_forged_sender_handle();
    test_pin_lobby_lockout_teardown_and_known_peers_pinning();
    test_policy_pin_floor_online_safety_number_and_pending_timeout();
#else
    test_without_iroh_fails_closed_cleanly();
#endif
    std::cout << "lan_party_runtime_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "lan_party_runtime_test FAILED: " << ex.what() << "\n";
    return 1;
  }
}
