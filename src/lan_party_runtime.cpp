#include "blackbird/lan_party_runtime.hpp"

#include "blackbird/party_chat.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace blackbird::lan {

namespace {

constexpr std::uint32_t kRejectFlushGraceMs = 20U;
constexpr std::string_view kDefaultPeerSourceAddr = "lan-direct";

template <typename T> Result<T> fail_lan(ErrorCode code, LanError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

template <typename T> Result<T> fail_rt(ErrorCode code, LanRuntimeError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> fail_rt_void(ErrorCode code, LanRuntimeError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

class CleanseStringGuard {
public:
  explicit CleanseStringGuard(std::string &buf) noexcept : buf_(buf) {}
  CleanseStringGuard(const CleanseStringGuard &) = delete;
  CleanseStringGuard &operator=(const CleanseStringGuard &) = delete;
  ~CleanseStringGuard() {
    if (!buf_.empty()) {
      OPENSSL_cleanse(buf_.data(), buf_.size());
      buf_.clear();
    }
  }

private:
  std::string &buf_;
};

class CleanseOptionalSecretGuard {
public:
  explicit CleanseOptionalSecretGuard(std::optional<P2pSecretKey> &key) noexcept
      : key_(key) {}
  CleanseOptionalSecretGuard(const CleanseOptionalSecretGuard &) = delete;
  CleanseOptionalSecretGuard &operator=(const CleanseOptionalSecretGuard &) = delete;
  ~CleanseOptionalSecretGuard() {
    if (key_.has_value()) {
      OPENSSL_cleanse(key_->data(), key_->size());
      key_.reset();
    }
  }

private:
  std::optional<P2pSecretKey> &key_;
};

std::int64_t now_unix_ns() noexcept {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
}

Result<LanPartyId> generate_random_party_id() {
  LanPartyId id{};
  if (RAND_bytes(id.data(), static_cast<int>(id.size())) != 1) {
    return fail_lan<LanPartyId>(ErrorCode::external_unknown, LanError::crypto_internal);
  }
  return Result<LanPartyId>::success(id);
}

Result<LanNonce> generate_random_nonce() {
  LanNonce nonce{};
  if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
    return fail_lan<LanNonce>(ErrorCode::external_unknown, LanError::crypto_internal);
  }
  return Result<LanNonce>::success(nonce);
}

Result<void> validate_local_identity(const LanIdentity &identity) {
  if (!is_valid_lan_name(identity.display_name)) {
    return Result<void>::failure(
        {ErrorCode::invalid_identity,
         static_cast<std::int64_t>(LanError::invalid_display_name)});
  }
  if (identity.account_id > mp::kMaxSafeId) {
    return fail_rt_void(ErrorCode::invalid_range, LanRuntimeError::invalid_config);
  }
  if (!mp::validate_ed25519_pubkey_strict(identity.public_key).has_value()) {
    return Result<void>::failure({ErrorCode::invalid_identity,
                                  static_cast<std::int64_t>(LanError::invalid_pubkey)});
  }
  const auto sk = identity.signing_key();
  if (!sk.has_value() || sk.value().public_key() != identity.public_key) {
    return Result<void>::failure({ErrorCode::invalid_identity,
                                  static_cast<std::int64_t>(LanError::invalid_pubkey)});
  }
  return Result<void>::success();
}

std::string encode_standard_base64(std::span<const std::uint8_t> bytes) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  std::size_t i = 0U;
  while (i + 3U <= bytes.size()) {
    const std::uint32_t v = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(bytes[i + 2U]);
    out.push_back(kTable[(v >> 18U) & 0x3fU]);
    out.push_back(kTable[(v >> 12U) & 0x3fU]);
    out.push_back(kTable[(v >> 6U) & 0x3fU]);
    out.push_back(kTable[v & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = bytes.size() - i;
  if (rem == 1U) {
    const std::uint32_t v = static_cast<std::uint32_t>(bytes[i]) << 16U;
    out.push_back(kTable[(v >> 18U) & 0x3fU]);
    out.push_back(kTable[(v >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t v = (static_cast<std::uint32_t>(bytes[i]) << 16U) |
                            (static_cast<std::uint32_t>(bytes[i + 1U]) << 8U);
    out.push_back(kTable[(v >> 18U) & 0x3fU]);
    out.push_back(kTable[(v >> 12U) & 0x3fU]);
    out.push_back(kTable[(v >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

enum class KnownPeerLookup : std::uint8_t {
  not_pinned = 0,
  pinned_trusted = 1,
  pinned_revoked_or_corrupt = 2,
};

KnownPeerLookup check_known_peer(const std::optional<KnownPeersStore> &store,
                                 const mp::Ed25519PubKey &pubkey,
                                 std::string *out_ssh_key = nullptr) {
  if (!store.has_value()) {
    return KnownPeerLookup::not_pinned;
  }
  const auto ssh_key = lan_pubkey_to_ssh_ed25519(pubkey);
  if (!ssh_key.has_value()) {
    return KnownPeerLookup::pinned_revoked_or_corrupt;
  }
  if (out_ssh_key != nullptr) {
    *out_ssh_key = ssh_key.value();
  }
  const auto fp = peer_fingerprint_from_public_key(ssh_key.value());
  if (!fp.has_value()) {
    return KnownPeerLookup::pinned_revoked_or_corrupt;
  }
  const auto found = store->find_by_fingerprint(fp.value());
  if (!found.has_value()) {
    return KnownPeerLookup::pinned_revoked_or_corrupt;
  }
  if (!found.value().has_value()) {
    return KnownPeerLookup::not_pinned;
  }
  const PinnedPeer &pinned = *found.value();
  if (pinned.revoked || pinned.public_key != ssh_key.value()) {
    return KnownPeerLookup::pinned_revoked_or_corrupt;
  }
  return KnownPeerLookup::pinned_trusted;
}

void pin_peer_best_effort(std::optional<KnownPeersStore> &store,
                          const mp::Ed25519PubKey &pubkey,
                          std::string_view safety_number) {
  if (!store.has_value()) {
    return;
  }
  const auto ssh_key = lan_pubkey_to_ssh_ed25519(pubkey);
  if (!ssh_key.has_value()) {
    return;
  }
  const std::string pk_hex = mp::hex_lower(pubkey);
  PinPeerRequest req{};
  req.alias = "lan-" + pk_hex.substr(0U, 16U);
  req.public_key = ssh_key.value();
  req.trust_note = "lan-safety-number:" + std::string{safety_number};
  (void)store->pin_peer(req);
}

Result<LanPolicyConfig>
run_policy_and_auth_gate(const LanPolicyPaths &policy_paths,
                         const EnvLookupFn &env_lookup, bool cfg_require_local_auth,
                         const LocalAuthOptions &local_auth_opts,
                         std::string_view default_auth_reason) {
  auto policy_res = load_effective_lan_policy(policy_paths, env_lookup);
  if (!policy_res.has_value()) {
    return Result<LanPolicyConfig>::failure(policy_res.error());
  }
  const LanPolicyConfig effective = policy_res.value();
  if (effective.disabled) {
    return fail_lan<LanPolicyConfig>(ErrorCode::conflict, LanError::lan_disabled);
  }
  if (effective.require_local_auth || cfg_require_local_auth) {
    LocalAuthOptions auth_opts = local_auth_opts;
    if (auth_opts.reason.empty()) {
      auth_opts.reason = default_auth_reason;
    }
    if (!auth_opts.env_lookup) {
      auth_opts.env_lookup = env_lookup;
    }
    const auto auth_res = verify_local_os_presence(auth_opts);
    if (!auth_res.has_value()) {
      return Result<LanPolicyConfig>::failure(auth_res.error());
    }
  }
  return Result<LanPolicyConfig>::success(effective);
}

std::vector<DiscoveredLanLobbyInfo>
enrich_discovered_lobbies(const std::vector<DiscoveredLanLobby> &raw) {
  std::vector<DiscoveredLanLobbyInfo> out;
  out.reserve(raw.size());
  for (const auto &entry : raw) {
    const auto sn = compute_lan_safety_number(0U, entry.beacon.host_pubkey);
    if (!sn.has_value()) {
      continue;
    }
    DiscoveredLanLobbyInfo info{};
    info.lobby = entry;
    info.safety_number = sn.value();
    info.direct_targets.reserve(entry.addrs.size());
    for (const auto &addr : entry.addrs) {
      const auto formatted = format_lan_direct_target(addr);
      if (formatted.has_value()) {
        info.direct_targets.push_back(formatted.value());
      }
    }
    out.push_back(std::move(info));
  }
  return out;
}

} // namespace

// ---------------------------------------------------------------------------
// Name & conversion helpers
// ---------------------------------------------------------------------------

std::string_view lan_runtime_error_name(LanRuntimeError detail) noexcept {
  switch (detail) {
  case LanRuntimeError::none:
    return "none";
  case LanRuntimeError::invalid_config:
    return "invalid_config";
  case LanRuntimeError::invalid_timeout:
    return "invalid_timeout";
  case LanRuntimeError::invalid_direct_target:
    return "invalid_direct_target";
  case LanRuntimeError::not_running:
    return "not_running";
  case LanRuntimeError::not_connected:
    return "not_connected";
  case LanRuntimeError::peer_rejected:
    return "peer_rejected";
  case LanRuntimeError::peer_not_found:
    return "peer_not_found";
  case LanRuntimeError::lobby_full:
    return "lobby_full";
  case LanRuntimeError::lobby_locked:
    return "lobby_locked";
  case LanRuntimeError::timed_out:
    return "timed_out";
  case LanRuntimeError::handshake_failed:
    return "handshake_failed";
  case LanRuntimeError::trust_store_failed:
    return "trust_store_failed";
  case LanRuntimeError::p2p_unavailable:
    return "p2p_unavailable";
  case LanRuntimeError::self_target_disallowed:
    return "self_target_disallowed";
  }
  return "unknown";
}

std::string_view lan_session_state_name(LanSessionState state) noexcept {
  switch (state) {
  case LanSessionState::stopped:
    return "stopped";
  case LanSessionState::hosting:
    return "hosting";
  case LanSessionState::connecting:
    return "connecting";
  case LanSessionState::handshaking:
    return "handshaking";
  case LanSessionState::connected:
    return "connected";
  case LanSessionState::timed_out:
    return "timed_out";
  case LanSessionState::locked_out:
    return "locked_out";
  case LanSessionState::rejected:
    return "rejected";
  case LanSessionState::disconnected:
    return "disconnected";
  }
  return "unknown";
}

std::string_view lan_event_kind_name(LanEventKind kind) noexcept {
  switch (kind) {
  case LanEventKind::member_joined:
    return "member_joined";
  case LanEventKind::member_left:
    return "member_left";
  case LanEventKind::member_kicked:
    return "member_kicked";
  case LanEventKind::member_rejected:
    return "member_rejected";
  case LanEventKind::roster_updated:
    return "roster_updated";
  case LanEventKind::chat_received:
    return "chat_received";
  case LanEventKind::pulse_received:
    return "pulse_received";
  case LanEventKind::lobby_locked:
    return "lobby_locked";
  case LanEventKind::lobby_timed_out:
    return "lobby_timed_out";
  case LanEventKind::lobby_pin_locked_out:
    return "lobby_pin_locked_out";
  case LanEventKind::connected:
    return "connected";
  case LanEventKind::disconnected:
    return "disconnected";
  case LanEventKind::welcome_rejected:
    return "welcome_rejected";
  case LanEventKind::frame_dropped:
    return "frame_dropped";
  }
  return "unknown";
}

Result<std::string> lan_pubkey_to_ssh_ed25519(const mp::Ed25519PubKey &pubkey) {
  if (!mp::validate_ed25519_pubkey_strict(pubkey).has_value()) {
    return fail_lan<std::string>(ErrorCode::invalid_identity, LanError::invalid_pubkey);
  }
  static constexpr std::array<std::uint8_t, 19> kPrefix = {
      0x00U, 0x00U, 0x00U, 0x0bU, 's', 's',   'h',   '-',   'e',   'd',
      '2',   '5',   '5',   '1',   '9', 0x00U, 0x00U, 0x00U, 0x20U,
  };
  std::array<std::uint8_t, 51> wire{};
  std::memcpy(wire.data(), kPrefix.data(), kPrefix.size());
  std::memcpy(wire.data() + kPrefix.size(), pubkey.data(), pubkey.size());
  const std::string raw_ssh = "ssh-ed25519 " + encode_standard_base64(wire);
  return canonicalize_ed25519_public_key(raw_ssh);
}

// ---------------------------------------------------------------------------
// scan_lan_lobbies
// ---------------------------------------------------------------------------

Result<std::vector<DiscoveredLanLobbyInfo>> scan_lan_lobbies(const LanScanConfig &cfg) {
  const auto policy_res = run_policy_and_auth_gate(
      cfg.policy_paths, cfg.env_lookup, cfg.require_local_auth, cfg.local_auth_options,
      "Authorize Blackbird LAN Party scan");
  if (!policy_res.has_value()) {
    return Result<std::vector<DiscoveredLanLobbyInfo>>::failure(policy_res.error());
  }
  const LanPolicyConfig effective = policy_res.value();

  if (cfg.scan_timeout_sec < kLanMinScanTimeoutSec) {
    return fail_rt<std::vector<DiscoveredLanLobbyInfo>>(
        ErrorCode::invalid_range, LanRuntimeError::invalid_timeout);
  }
  const std::uint32_t effective_scan_sec = std::min(
      {cfg.scan_timeout_sec, effective.scan_timeout_sec, kMaxLanScanTimeoutSec});

  LanMdnsScanner scanner;
  const auto started = scanner.start(effective_scan_sec, cfg.mdns_socket_cfg);
  if (!started.has_value()) {
    return Result<std::vector<DiscoveredLanLobbyInfo>>::failure(started.error());
  }

  const std::uint32_t step_ms = cfg.poll_step_ms == 0U ? 10U : cfg.poll_step_ms;
  const std::uint32_t query_interval_ms =
      cfg.query_interval_ms == 0U ? 1000U : cfg.query_interval_ms;
  auto last_query_at = std::chrono::steady_clock::now();

  std::vector<DiscoveredLanLobbyInfo> discovered;
  while (scanner.active()) {
    if (cfg.on_poll_tick) {
      cfg.on_poll_tick();
    }
    const auto pumped = scanner.pump_once(step_ms);
    if (!pumped.has_value()) {
      scanner.stop();
      return Result<std::vector<DiscoveredLanLobbyInfo>>::failure(pumped.error());
    }
    discovered = enrich_discovered_lobbies(scanner.lobbies());
    if (cfg.stop_when && cfg.stop_when(discovered)) {
      break;
    }
    if (!scanner.active()) {
      break;
    }
    const auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_query_at)
            .count() >= static_cast<std::int64_t>(query_interval_ms)) {
      (void)scanner.send_query();
      last_query_at = now;
    }
  }

  scanner.stop();
  return Result<std::vector<DiscoveredLanLobbyInfo>>::success(std::move(discovered));
}

// ---------------------------------------------------------------------------
// LanPartyHost
// ---------------------------------------------------------------------------

LanPartyHost::LanPartyHost(LanPartyHost &&other) noexcept
    : state_(std::exchange(other.state_, LanSessionState::stopped)),
      identity_(std::move(other.identity_)),
      lan_party_id_(std::move(other.lan_party_id_)),
      lobby_name_(std::move(other.lobby_name_)),
      room_scope_(std::move(other.room_scope_)), pin_(std::move(other.pin_)),
      pin_required_(std::exchange(other.pin_required_, false)),
      locked_(std::exchange(other.locked_, false)),
      has_peer_joined_(std::exchange(other.has_peer_joined_, false)),
      max_members_(other.max_members_),
      effective_idle_timeout_sec_(other.effective_idle_timeout_sec_),
      service_port_(std::exchange(other.service_port_, 0U)),
      started_at_(other.started_at_), endpoint_(std::move(other.endpoint_)),
      advertiser_(std::move(other.advertiser_)),
      direct_addrs_(std::move(other.direct_addrs_)),
      direct_targets_(std::move(other.direct_targets_)),
      trust_callback_(std::move(other.trust_callback_)),
      known_peers_(std::move(other.known_peers_)),
      pin_approved_peers_(other.pin_approved_peers_),
      pin_limiter_(std::move(other.pin_limiter_)),
      roster_epoch_(std::exchange(other.roster_epoch_, 0U)),
      members_(std::move(other.members_)),
      pending_peers_(std::move(other.pending_peers_)),
      events_(std::move(other.events_)) {
  other.identity_.signing_seed.cleanse();
  other.pin_.cleanse();
}

LanPartyHost &LanPartyHost::operator=(LanPartyHost &&other) noexcept {
  if (this != &other) {
    stop();
    state_ = std::exchange(other.state_, LanSessionState::stopped);
    identity_ = std::move(other.identity_);
    lan_party_id_ = std::move(other.lan_party_id_);
    lobby_name_ = std::move(other.lobby_name_);
    room_scope_ = std::move(other.room_scope_);
    pin_ = std::move(other.pin_);
    pin_required_ = std::exchange(other.pin_required_, false);
    locked_ = std::exchange(other.locked_, false);
    has_peer_joined_ = std::exchange(other.has_peer_joined_, false);
    max_members_ = other.max_members_;
    effective_idle_timeout_sec_ = other.effective_idle_timeout_sec_;
    service_port_ = std::exchange(other.service_port_, 0U);
    started_at_ = other.started_at_;
    endpoint_ = std::move(other.endpoint_);
    advertiser_ = std::move(other.advertiser_);
    direct_addrs_ = std::move(other.direct_addrs_);
    direct_targets_ = std::move(other.direct_targets_);
    trust_callback_ = std::move(other.trust_callback_);
    known_peers_ = std::move(other.known_peers_);
    pin_approved_peers_ = other.pin_approved_peers_;
    pin_limiter_ = std::move(other.pin_limiter_);
    roster_epoch_ = std::exchange(other.roster_epoch_, 0U);
    members_ = std::move(other.members_);
    pending_peers_ = std::move(other.pending_peers_);
    events_ = std::move(other.events_);
    other.identity_.signing_seed.cleanse();
    other.pin_.cleanse();
  }
  return *this;
}

LanPartyHost::~LanPartyHost() noexcept { stop(); }

Result<LanPartyHost> LanPartyHost::start(LanHostConfig cfg) {
  CleanseStringGuard raw_pin_guard{cfg.pin};

  // 1. Strict Policy & Mandate Gate FIRST (ZERO sockets opened on denial).
  const auto policy_res = run_policy_and_auth_gate(
      cfg.policy_paths, cfg.env_lookup, cfg.require_local_auth, cfg.local_auth_options,
      "Authorize Blackbird LAN Party host");
  if (!policy_res.has_value()) {
    return Result<LanPartyHost>::failure(policy_res.error());
  }
  const LanPolicyConfig effective = policy_res.value();

  // 2. Validate PIN policy, timeouts, identity, and lobby metadata (ZERO sockets).
  const bool pin_required =
      effective.require_pin || cfg.require_pin || !cfg.pin.empty();
  CleansedPin cleansed_pin;
  if (pin_required) {
    if (cfg.pin.empty()) {
      return fail_lan<LanPartyHost>(ErrorCode::invalid_identity, LanError::invalid_pin);
    }
    auto pin_res = CleansedPin::create(cfg.pin);
    if (!pin_res.has_value()) {
      return Result<LanPartyHost>::failure(pin_res.error());
    }
    cleansed_pin = std::move(pin_res).value();
  }

  if (cfg.idle_timeout_sec < kLanMinIdleTimeoutSec) {
    return fail_rt<LanPartyHost>(ErrorCode::invalid_range,
                                 LanRuntimeError::invalid_timeout);
  }
  const std::uint32_t effective_idle = std::min(
      {cfg.idle_timeout_sec, effective.idle_timeout_sec, kMaxLanIdleTimeoutSec});

  if (!is_valid_lan_name(cfg.lobby_name)) {
    return fail_lan<LanPartyHost>(ErrorCode::invalid_identity,
                                  LanError::invalid_display_name);
  }
  if (const auto id_ok = validate_local_identity(cfg.identity); !id_ok.has_value()) {
    return Result<LanPartyHost>::failure(id_ok.error());
  }
  if (cfg.max_members == 0U || cfg.max_members > kLanMaxMembers) {
    return fail_rt<LanPartyHost>(ErrorCode::invalid_range,
                                 LanRuntimeError::invalid_config);
  }

  std::string party_id_hex;
  if (!cfg.lan_party_id_override.empty()) {
    const auto parsed_id = parse_lan_party_id_hex(cfg.lan_party_id_override);
    if (!parsed_id.has_value()) {
      return Result<LanPartyHost>::failure(parsed_id.error());
    }
    party_id_hex = format_lan_party_id_hex(parsed_id.value());
  } else {
    const auto rand_id = generate_random_party_id();
    if (!rand_id.has_value()) {
      return Result<LanPartyHost>::failure(rand_id.error());
    }
    party_id_hex = format_lan_party_id_hex(rand_id.value());
  }

  const auto sn_res =
      compute_lan_safety_number(cfg.identity.account_id, cfg.identity.public_key);
  if (!sn_res.has_value()) {
    return Result<LanPartyHost>::failure(sn_res.error());
  }
  cfg.identity.safety_number = sn_res.value();

  // 3. Create iroh P2P endpoint in strict no_relays mode + opt-in LAN open admission.
  P2pEndpointConfig ep_cfg{};
  ep_cfg.relay_policy = P2pRelayPolicy::no_relays;
  ep_cfg.secret_key = cfg.identity.signing_seed.bytes();
  ep_cfg.relay_url.clear();
  CleanseOptionalSecretGuard ep_secret_guard{ep_cfg.secret_key};

  auto ep_res = P2pEndpoint::create(ep_cfg);
  if (!ep_res.has_value()) {
    return Result<LanPartyHost>::failure(ep_res.error());
  }
  P2pEndpoint endpoint = std::move(ep_res).value();

  const auto bound_pk = endpoint.local_pubkey();
  if (!bound_pk.has_value() || bound_pk.value() != cfg.identity.public_key) {
    endpoint.close();
    return fail_lan<LanPartyHost>(ErrorCode::invalid_identity,
                                  LanError::invalid_pubkey);
  }

  if (const auto open_res = endpoint.set_lan_open_admission(true);
      !open_res.has_value()) {
    endpoint.close();
    return Result<LanPartyHost>::failure(open_res.error());
  }

  auto direct_addrs_res = endpoint.local_direct_addrs();
  if (!direct_addrs_res.has_value() || direct_addrs_res.value().empty()) {
    endpoint.close();
    return fail_rt<LanPartyHost>(ErrorCode::io, LanRuntimeError::p2p_unavailable);
  }
  std::vector<P2pDirectAddr> direct_addrs = std::move(direct_addrs_res).value();

  std::uint16_t service_port = 0U;
  std::vector<std::string> direct_targets;
  direct_targets.reserve(direct_addrs.size());
  for (const auto &addr : direct_addrs) {
    if (service_port == 0U && addr.port != 0U) {
      service_port = addr.port;
    }
    const auto formatted = format_lan_direct_target(addr);
    if (formatted.has_value()) {
      direct_targets.push_back(formatted.value());
    }
  }
  if (service_port == 0U) {
    endpoint.close();
    return fail_rt<LanPartyHost>(ErrorCode::io, LanRuntimeError::p2p_unavailable);
  }

  // 4. Open optional KnownPeersStore only after endpoint succeeds.
  std::optional<KnownPeersStore> known_peers;
  if (cfg.known_peers_path.has_value() && !cfg.known_peers_path->empty()) {
    auto kp_res = KnownPeersStore::open(*cfg.known_peers_path);
    if (!kp_res.has_value()) {
      endpoint.close();
      return fail_rt<LanPartyHost>(kp_res.error().code,
                                   LanRuntimeError::trust_store_failed);
    }
    known_peers.emplace(std::move(kp_res).value());
  }

  // 5. Start mDNS advertiser when enabled.
  LanMdnsAdvertiser advertiser;
  if (cfg.enable_mdns) {
    LanBeaconRecord beacon{};
    beacon.version = kLanBeaconVersion;
    beacon.lan_party_id = party_id_hex;
    beacon.lobby_name = cfg.lobby_name;
    beacon.host_name = cfg.identity.display_name;
    beacon.host_pubkey = cfg.identity.public_key;
    beacon.require_pin = pin_required;
    beacon.alpn = std::string{kP2pAlpn};

    const auto adv_res =
        advertiser.start(beacon, LanServicePort{service_port},
                         LanIdleTimeoutSec{effective_idle}, cfg.mdns_socket_cfg);
    if (!adv_res.has_value()) {
      endpoint.close();
      known_peers.reset();
      return Result<LanPartyHost>::failure(adv_res.error());
    }
  }

  LanPartyHost host;
  host.state_ = LanSessionState::hosting;
  host.identity_ = std::move(cfg.identity);
  host.lan_party_id_ = std::move(party_id_hex);
  host.lobby_name_ = std::move(cfg.lobby_name);
  host.room_scope_ =
      cfg.room_scope.empty()
          ? std::string{kLanDefaultRoomScope}
          : party_chat_sanitize(cfg.room_scope, kP2pPartyMaxRoomScopeBytes);
  host.pin_ = std::move(cleansed_pin);
  host.pin_required_ = pin_required;
  host.locked_ = false;
  host.has_peer_joined_ = false;
  host.max_members_ = cfg.max_members;
  host.effective_idle_timeout_sec_ = effective_idle;
  host.service_port_ = service_port;
  host.started_at_ = std::chrono::steady_clock::now();
  host.endpoint_ = std::move(endpoint);
  host.advertiser_ = std::move(advertiser);
  host.direct_addrs_ = std::move(direct_addrs);
  host.direct_targets_ = std::move(direct_targets);
  host.trust_callback_ = std::move(cfg.trust_callback);
  host.known_peers_ = std::move(known_peers);
  host.pin_approved_peers_ = cfg.pin_approved_peers;
  host.pin_limiter_ = LanPinRateLimiter{cfg.pin_rate_limit};
  host.roster_epoch_ = 1U;
  host.members_.push_back(LanMemberInfo{
      host.identity_.account_id,
      host.identity_.display_name,
      host.identity_.public_key,
      true,
  });

  return Result<LanPartyHost>::success(std::move(host));
}

void LanPartyHost::push_event(LanEvent event) {
  if (events_.size() >= kLanRuntimeMaxQueuedEvents) {
    events_.pop_front();
  }
  events_.push_back(std::move(event));
}

void LanPartyHost::close_resources_noexcept() noexcept {
  advertiser_.stop();
  endpoint_.close();
  known_peers_.reset();
  pin_.cleanse();
  pending_peers_.clear();
}

void LanPartyHost::transition_timed_out() noexcept {
  close_resources_noexcept();
  state_ = LanSessionState::timed_out;
  LanEvent ev{};
  ev.kind = LanEventKind::lobby_timed_out;
  ev.reason = "idle_timeout";
  try {
    push_event(std::move(ev));
  } catch (...) {
  }
}

void LanPartyHost::transition_pin_locked_out() noexcept {
  locked_ = true;
  close_resources_noexcept();
  state_ = LanSessionState::locked_out;
  LanEvent ev{};
  ev.kind = LanEventKind::lobby_pin_locked_out;
  ev.lobby_locked = true;
  ev.reason = "locked";
  try {
    push_event(std::move(ev));
  } catch (...) {
  }
}

void LanPartyHost::stop() noexcept {
  close_resources_noexcept();
  identity_.signing_seed.cleanse();
  state_ = LanSessionState::stopped;
}

const LanMemberInfo *
LanPartyHost::find_member(const mp::Ed25519PubKey &pubkey) const noexcept {
  for (const auto &member : members_) {
    if (member.pubkey == pubkey) {
      return &member;
    }
  }
  return nullptr;
}

void LanPartyHost::broadcast_roster_best_effort() {
  if (!endpoint_.valid() || members_.empty()) {
    return;
  }
  LanRosterMessage msg{};
  msg.lan_party_id = lan_party_id_;
  msg.roster_epoch = roster_epoch_;
  msg.locked = locked_;
  msg.members = members_;
  const auto encoded = encode_lan_handshake_frame(msg);
  if (!encoded.has_value()) {
    return;
  }
  for (const auto &member : members_) {
    if (member.is_host || member.pubkey == identity_.public_key) {
      continue;
    }
    (void)endpoint_.send_frame(member.pubkey, P2pLane::control, encoded.value());
  }
}

void LanPartyHost::reject_pending_peer(const mp::Ed25519PubKey &pubkey,
                                       std::string_view reason) {
  pending_peers_.erase(pubkey);
  bool sent_welcome = false;
  if (endpoint_.valid()) {
    LanWelcomeMessage welcome{};
    welcome.lan_party_id = lan_party_id_;
    welcome.accepted = false;
    welcome.reason = std::string{reason};
    welcome.roster_epoch = roster_epoch_;
    const auto encoded = encode_lan_handshake_frame(welcome);
    if (encoded.has_value()) {
      sent_welcome =
          endpoint_.send_frame(pubkey, P2pLane::control, encoded.value()).has_value();
    }
    if (sent_welcome) {
      std::this_thread::sleep_for(std::chrono::milliseconds(kRejectFlushGraceMs));
    }
    (void)endpoint_.revoke_peer(pubkey);
  }

  LanEvent ev{};
  ev.kind = LanEventKind::member_rejected;
  ev.peer_pubkey = pubkey;
  ev.reason = std::string{reason};
  const auto sn = compute_lan_safety_number(0U, pubkey);
  if (sn.has_value()) {
    ev.safety_number = sn.value();
  }
  push_event(std::move(ev));
}

bool LanPartyHost::verify_or_pin_peer(const LanPeerTrustPrompt &prompt) {
  const KnownPeerLookup status = check_known_peer(known_peers_, prompt.pubkey);
  if (status == KnownPeerLookup::pinned_trusted) {
    return true;
  }
  if (status == KnownPeerLookup::pinned_revoked_or_corrupt) {
    return false;
  }
  if (!trust_callback_) {
    return false;
  }
  if (!trust_callback_(prompt)) {
    return false;
  }
  if (pin_approved_peers_) {
    pin_peer_best_effort(known_peers_, prompt.pubkey, prompt.safety_number);
  }
  return true;
}

Result<std::size_t> LanPartyHost::pump_once(
    std::uint32_t timeout_ms,
    std::optional<std::chrono::steady_clock::time_point> now_override) {
  if (state_ != LanSessionState::hosting) {
    return fail_rt<std::size_t>(ErrorCode::stale_handle, LanRuntimeError::not_running);
  }

  const std::size_t before = events_.size();
  const auto now = now_override.value_or(std::chrono::steady_clock::now());

  // 1. Pump mDNS advertiser and enforce idle-timeout auto-shutoff.
  if (advertiser_.active()) {
    const auto adv_res = advertiser_.pump_once(0U, now_override);
    if (!adv_res.has_value()) {
      return Result<std::size_t>::failure(adv_res.error());
    }
    if (advertiser_.expired()) {
      transition_timed_out();
      return Result<std::size_t>::success(events_.size() - before);
    }
  }

  if (!has_peer_joined_ && !locked_ &&
      now >= started_at_ + std::chrono::seconds(effective_idle_timeout_sec_)) {
    transition_timed_out();
    return Result<std::size_t>::success(events_.size() - before);
  }

  // 1b. Evict stalled pending handshakes (anti-Slowloris pending-slot protection).
  {
    std::vector<mp::Ed25519PubKey> stalled_keys;
    for (const auto &[pk, pending] : pending_peers_) {
      if (now >=
          pending.connected_at + std::chrono::seconds(kLanPendingHandshakeTimeoutSec)) {
        stalled_keys.push_back(pk);
      }
    }
    for (const auto &pk : stalled_keys) {
      reject_pending_peer(pk, "handshake_timeout");
    }
  }

  // 2. Pump iroh P2P endpoint events.
  for (std::size_t i = 0U; i < kLanRuntimeMaxEventsPerPump &&
                           state_ == LanSessionState::hosting && endpoint_.valid();
       ++i) {
    const std::uint32_t poll_ms = (i == 0U) ? timeout_ms : 0U;
    const auto polled = endpoint_.poll_event(poll_ms);
    if (!polled.has_value()) {
      return Result<std::size_t>::failure(polled.error());
    }
    if (!polled.value().has_value()) {
      break;
    }
    handle_transport_event(*polled.value(), now);
  }

  return Result<std::size_t>::success(events_.size() >= before ? events_.size() - before
                                                               : 0U);
}

void LanPartyHost::handle_transport_event(const P2pEvent &ev,
                                          std::chrono::steady_clock::time_point now) {
  switch (ev.kind) {
  case P2pEventKind::none:
    return;

  case P2pEventKind::peer_connected: {
    if (ev.peer_pubkey == identity_.public_key ||
        find_member(ev.peer_pubkey) != nullptr) {
      return;
    }
    if (locked_ || pin_limiter_.is_lobby_locked()) {
      (void)endpoint_.revoke_peer(ev.peer_pubkey);
      return;
    }
    const LanPinPeerKey peer_key{ev.peer_pubkey, std::string{kDefaultPeerSourceAddr}};
    if (pin_limiter_.is_peer_locked(peer_key)) {
      reject_pending_peer(ev.peer_pubkey, "locked");
      return;
    }
    const auto nonce_res = generate_random_nonce();
    if (!nonce_res.has_value()) {
      (void)endpoint_.revoke_peer(ev.peer_pubkey);
      return;
    }
    pending_peers_[ev.peer_pubkey] = PendingPeer{nonce_res.value(), now};

    LanHelloMessage hello{};
    hello.lan_party_id = lan_party_id_;
    hello.lobby_name = lobby_name_;
    hello.host_name = identity_.display_name;
    hello.host_account_id = identity_.account_id;
    hello.host_pubkey = identity_.public_key;
    hello.require_pin = pin_required_;
    hello.host_nonce = nonce_res.value();
    hello.max_members = max_members_;

    const auto encoded = encode_lan_handshake_frame(hello);
    if (!encoded.has_value() ||
        !endpoint_.send_frame(ev.peer_pubkey, P2pLane::control, encoded.value())
             .has_value()) {
      pending_peers_.erase(ev.peer_pubkey);
      (void)endpoint_.revoke_peer(ev.peer_pubkey);
    }
    return;
  }

  case P2pEventKind::peer_disconnected: {
    pending_peers_.erase(ev.peer_pubkey);
    const auto it =
        std::find_if(members_.begin(), members_.end(), [&](const LanMemberInfo &m) {
          return !m.is_host && m.pubkey == ev.peer_pubkey;
        });
    if (it != members_.end()) {
      LanMemberInfo left = *it;
      members_.erase(it);
      ++roster_epoch_;
      broadcast_roster_best_effort();

      LanEvent out{};
      out.kind = LanEventKind::member_left;
      out.peer_pubkey = left.pubkey;
      out.sender_name = left.display_name;
      out.sender_account_id = left.account_id;
      out.member = std::move(left);
      out.roster = members_;
      out.roster_epoch = roster_epoch_;
      out.lobby_locked = locked_;
      out.reason_code = ev.reason_code;
      push_event(std::move(out));
    }
    return;
  }

  case P2pEventKind::frame_received: {
    if (pending_peers_.find(ev.peer_pubkey) != pending_peers_.end()) {
      handle_pending_control_frame(ev);
      return;
    }
    if (const LanMemberInfo *member = find_member(ev.peer_pubkey)) {
      handle_admitted_frame(ev, *member);
      return;
    }
    (void)endpoint_.revoke_peer(ev.peer_pubkey);
    LanEvent dropped{};
    dropped.kind = LanEventKind::frame_dropped;
    dropped.peer_pubkey = ev.peer_pubkey;
    dropped.reason = "unauthenticated_peer";
    push_event(std::move(dropped));
    return;
  }
  }
}

void LanPartyHost::handle_pending_control_frame(const P2pEvent &ev) {
  const auto pending_it = pending_peers_.find(ev.peer_pubkey);
  if (pending_it == pending_peers_.end()) {
    return;
  }
  const LanNonce host_nonce = pending_it->second.host_nonce;

  if (ev.lane != P2pLane::control) {
    reject_pending_peer(ev.peer_pubkey, "protocol_error");
    return;
  }

  const auto decoded = decode_lan_handshake_frame(ev.lane, ev.payload);
  if (!decoded.has_value()) {
    reject_pending_peer(ev.peer_pubkey, "protocol_error");
    return;
  }
  const auto *join = std::get_if<LanJoinMessage>(&decoded.value());
  if (join == nullptr) {
    reject_pending_peer(ev.peer_pubkey, "protocol_error");
    return;
  }
  if (join->lan_party_id != lan_party_id_) {
    reject_pending_peer(ev.peer_pubkey, "party_id_mismatch");
    return;
  }

  const LanPinPeerKey peer_key{ev.peer_pubkey, std::string{kDefaultPeerSourceAddr}};
  const LanPinLockoutStatus pre_status = pin_limiter_.check(peer_key);
  if (pre_status == LanPinLockoutStatus::lobby_locked) {
    reject_pending_peer(ev.peer_pubkey, "locked");
    transition_pin_locked_out();
    return;
  }
  if (pre_status == LanPinLockoutStatus::peer_locked) {
    reject_pending_peer(ev.peer_pubkey, "locked");
    return;
  }

  // 1. PIN verification (with brute-force rate limiting).
  if (pin_required_) {
    bool pin_ok = false;
    if (join->pin_proof.has_value()) {
      LanPinProofInput proof_in{};
      proof_in.pin = pin_.view();
      proof_in.lan_party_id_hex = lan_party_id_;
      proof_in.host_pubkey = identity_.public_key;
      proof_in.joiner_pubkey = ev.peer_pubkey;
      proof_in.host_nonce = host_nonce;
      const auto verified = verify_lan_pin_proof(proof_in, *join->pin_proof);
      pin_ok = verified.has_value() && verified.value();
    }
    if (!pin_ok) {
      const LanPinLockoutStatus post_status = pin_limiter_.record_failure(peer_key);
      const std::string_view reason =
          (post_status == LanPinLockoutStatus::allowed) ? "invalid_pin" : "locked";
      reject_pending_peer(ev.peer_pubkey, reason);
      if (post_status == LanPinLockoutStatus::lobby_locked) {
        transition_pin_locked_out();
      }
      return;
    }
  }

  // 2. Lobby capacity check.
  if (members_.size() >= static_cast<std::size_t>(max_members_)) {
    reject_pending_peer(ev.peer_pubkey, "full");
    return;
  }

  // 3. Canonical Safety Number pinning / trust callback (Mandate #5).
  const auto sn_res = compute_lan_safety_number(join->account_id, ev.peer_pubkey);
  if (!sn_res.has_value()) {
    reject_pending_peer(ev.peer_pubkey, "rejected");
    return;
  }
  const std::string clean_name = sanitize_lan_display_name(join->display_name);
  LanPeerTrustPrompt prompt{};
  prompt.display_name = clean_name;
  prompt.account_id = join->account_id;
  prompt.pubkey = ev.peer_pubkey;
  prompt.safety_number = sn_res.value();
  prompt.source_addr = std::string{kDefaultPeerSourceAddr};
  prompt.is_host = false;
  if (!verify_or_pin_peer(prompt)) {
    reject_pending_peer(ev.peer_pubkey, "rejected");
    return;
  }

  // 4. Promote peer into iroh allowlist & admit to roster.
  if (!endpoint_.allow_peer(ev.peer_pubkey).has_value()) {
    reject_pending_peer(ev.peer_pubkey, "rejected");
    return;
  }

  pin_limiter_.record_success(peer_key);
  pending_peers_.erase(ev.peer_pubkey);
  has_peer_joined_ = true;
  if (advertiser_.active()) {
    advertiser_.mark_peer_joined();
  }

  LanMemberInfo member{};
  member.account_id = join->account_id;
  member.display_name = clean_name;
  member.pubkey = ev.peer_pubkey;
  member.is_host = false;
  members_.push_back(member);
  ++roster_epoch_;

  // Send LAN_WELCOME to newly admitted peer.
  LanWelcomeMessage welcome{};
  welcome.lan_party_id = lan_party_id_;
  welcome.accepted = true;
  welcome.reason.clear();
  welcome.roster_epoch = roster_epoch_;
  welcome.members = members_;
  if (const auto enc_welcome = encode_lan_handshake_frame(welcome);
      enc_welcome.has_value()) {
    (void)endpoint_.send_frame(ev.peer_pubkey, P2pLane::control, enc_welcome.value());
  }

  // Broadcast updated LAN_ROSTER to all other admitted members.
  LanRosterMessage roster{};
  roster.lan_party_id = lan_party_id_;
  roster.roster_epoch = roster_epoch_;
  roster.locked = locked_;
  roster.members = members_;
  if (const auto enc_roster = encode_lan_handshake_frame(roster);
      enc_roster.has_value()) {
    for (const auto &m : members_) {
      if (m.is_host || m.pubkey == ev.peer_pubkey) {
        continue;
      }
      (void)endpoint_.send_frame(m.pubkey, P2pLane::control, enc_roster.value());
    }
  }

  LanEvent joined_ev{};
  joined_ev.kind = LanEventKind::member_joined;
  joined_ev.peer_pubkey = member.pubkey;
  joined_ev.sender_name = member.display_name;
  joined_ev.sender_account_id = member.account_id;
  joined_ev.safety_number = sn_res.value();
  joined_ev.member = member;
  joined_ev.roster = members_;
  joined_ev.roster_epoch = roster_epoch_;
  joined_ev.lobby_locked = locked_;
  push_event(std::move(joined_ev));
}

void LanPartyHost::handle_admitted_frame(const P2pEvent &ev,
                                         const LanMemberInfo &member) {
  if (ev.lane == P2pLane::causal) {
    const auto decoded = decode_p2p_party_frame(P2pLane::causal, ev.payload);
    if (!decoded.has_value()) {
      LanEvent dropped{};
      dropped.kind = LanEventKind::frame_dropped;
      dropped.peer_pubkey = ev.peer_pubkey;
      dropped.sender_name = member.display_name;
      dropped.error = decoded.error();
      push_event(std::move(dropped));
      return;
    }
    const auto *chat = std::get_if<P2pPartyChatMessage>(&decoded.value());
    if (chat == nullptr) {
      LanEvent dropped{};
      dropped.kind = LanEventKind::frame_dropped;
      dropped.peer_pubkey = ev.peer_pubkey;
      dropped.sender_name = member.display_name;
      dropped.reason = "unexpected_causal_frame";
      push_event(std::move(dropped));
      return;
    }

    // Strict anti-spoofing: sender_handle ALWAYS comes from host's authenticated
    // members_ table, NEVER from the wire payload, and all text is sanitized
    // against ANSI/C0/C1/BiDi escape sequences.
    P2pPartyChatMessage clean_chat{};
    clean_chat.room_scope =
        party_chat_sanitize(chat->room_scope, kP2pPartyMaxRoomScopeBytes);
    clean_chat.target_selector =
        party_chat_sanitize(chat->target_selector, kP2pPartyMaxTargetSelectorBytes);
    clean_chat.sender_handle = member.display_name;
    clean_chat.timestamp_ns = chat->timestamp_ns;
    clean_chat.body = party_chat_sanitize(chat->body, kP2pPartyMaxChatBodyBytes);

    if (const auto relay_bytes = encode_p2p_party_frame(clean_chat);
        relay_bytes.has_value()) {
      for (const auto &peer : members_) {
        if (peer.is_host || peer.pubkey == ev.peer_pubkey) {
          continue;
        }
        (void)endpoint_.send_frame(peer.pubkey, P2pLane::causal, relay_bytes.value());
      }
    }

    LanEvent out{};
    out.kind = LanEventKind::chat_received;
    out.peer_pubkey = ev.peer_pubkey;
    out.sender_name = member.display_name;
    out.sender_account_id = member.account_id;
    out.chat = std::move(clean_chat);
    push_event(std::move(out));
    return;
  }

  if (ev.lane == P2pLane::ephemeral) {
    const auto decoded = decode_p2p_party_frame(P2pLane::ephemeral, ev.payload);
    if (!decoded.has_value()) {
      LanEvent dropped{};
      dropped.kind = LanEventKind::frame_dropped;
      dropped.peer_pubkey = ev.peer_pubkey;
      dropped.sender_name = member.display_name;
      dropped.error = decoded.error();
      push_event(std::move(dropped));
      return;
    }
    const auto *pulse = std::get_if<P2pPartyEphemeralPulse>(&decoded.value());
    if (pulse == nullptr) {
      LanEvent dropped{};
      dropped.kind = LanEventKind::frame_dropped;
      dropped.peer_pubkey = ev.peer_pubkey;
      dropped.sender_name = member.display_name;
      dropped.reason = "unexpected_ephemeral_frame";
      push_event(std::move(dropped));
      return;
    }

    P2pPartyEphemeralPulse clean_pulse{};
    clean_pulse.activity_state = pulse->activity_state;
    clean_pulse.timestamp_ns = pulse->timestamp_ns;
    clean_pulse.status =
        party_chat_sanitize(pulse->status, kP2pPartyMaxEphemeralStatusBytes);

    if (const auto relay_bytes = encode_p2p_party_frame(clean_pulse);
        relay_bytes.has_value()) {
      for (const auto &peer : members_) {
        if (peer.is_host || peer.pubkey == ev.peer_pubkey) {
          continue;
        }
        (void)endpoint_.send_frame(peer.pubkey, P2pLane::ephemeral,
                                   relay_bytes.value());
      }
    }

    LanEvent out{};
    out.kind = LanEventKind::pulse_received;
    out.peer_pubkey = ev.peer_pubkey;
    out.sender_name = member.display_name;
    out.sender_account_id = member.account_id;
    out.pulse = std::move(clean_pulse);
    push_event(std::move(out));
    return;
  }

  LanEvent dropped{};
  dropped.kind = LanEventKind::frame_dropped;
  dropped.peer_pubkey = ev.peer_pubkey;
  dropped.sender_name = member.display_name;
  dropped.reason = "unexpected_control_frame";
  push_event(std::move(dropped));
}

Result<void> LanPartyHost::send_chat(std::string_view body,
                                     const LanChatTarget &target) {
  if (state_ != LanSessionState::hosting || !endpoint_.valid()) {
    return fail_rt_void(ErrorCode::stale_handle, LanRuntimeError::not_running);
  }
  P2pPartyChatMessage msg{};
  msg.room_scope = room_scope_;
  msg.target_selector =
      party_chat_sanitize(target.value, kP2pPartyMaxTargetSelectorBytes);
  msg.sender_handle = identity_.display_name;
  msg.timestamp_ns = now_unix_ns();
  msg.body = party_chat_sanitize(body, kP2pPartyMaxChatBodyBytes);

  const auto encoded = encode_p2p_party_frame(msg);
  if (!encoded.has_value()) {
    return Result<void>::failure(encoded.error());
  }
  for (const auto &member : members_) {
    if (member.is_host || member.pubkey == identity_.public_key) {
      continue;
    }
    const auto sent =
        endpoint_.send_frame(member.pubkey, P2pLane::causal, encoded.value());
    if (!sent.has_value()) {
      return sent;
    }
  }
  return Result<void>::success();
}

Result<void> LanPartyHost::send_pulse(P2pPartyActivityState activity_state,
                                      std::string_view status) {
  if (state_ != LanSessionState::hosting || !endpoint_.valid()) {
    return fail_rt_void(ErrorCode::stale_handle, LanRuntimeError::not_running);
  }
  P2pPartyEphemeralPulse pulse{};
  pulse.activity_state = activity_state;
  pulse.timestamp_ns = now_unix_ns();
  pulse.status = party_chat_sanitize(status, kP2pPartyMaxEphemeralStatusBytes);

  const auto encoded = encode_p2p_party_frame(pulse);
  if (!encoded.has_value()) {
    return Result<void>::failure(encoded.error());
  }
  for (const auto &member : members_) {
    if (member.is_host || member.pubkey == identity_.public_key) {
      continue;
    }
    (void)endpoint_.send_frame(member.pubkey, P2pLane::ephemeral, encoded.value());
  }
  return Result<void>::success();
}

Result<void> LanPartyHost::lock_lobby() {
  if (state_ != LanSessionState::hosting || !endpoint_.valid()) {
    return fail_rt_void(ErrorCode::stale_handle, LanRuntimeError::not_running);
  }
  locked_ = true;
  advertiser_.lock_lobby();
  const auto close_open = endpoint_.set_lan_open_admission(false);
  if (!close_open.has_value()) {
    return close_open;
  }

  // Revoke any un-admitted pending peers immediately.
  std::vector<mp::Ed25519PubKey> pending_keys;
  pending_keys.reserve(pending_peers_.size());
  for (const auto &[pk, _] : pending_peers_) {
    pending_keys.push_back(pk);
  }
  for (const auto &pk : pending_keys) {
    reject_pending_peer(pk, "locked");
  }

  ++roster_epoch_;
  broadcast_roster_best_effort();

  LanEvent ev{};
  ev.kind = LanEventKind::lobby_locked;
  ev.roster = members_;
  ev.roster_epoch = roster_epoch_;
  ev.lobby_locked = true;
  push_event(std::move(ev));
  return Result<void>::success();
}

Result<void> LanPartyHost::kick_peer(const mp::Ed25519PubKey &pubkey) {
  if (state_ != LanSessionState::hosting || !endpoint_.valid()) {
    return fail_rt_void(ErrorCode::stale_handle, LanRuntimeError::not_running);
  }
  if (pubkey == identity_.public_key) {
    return fail_rt_void(ErrorCode::invalid_identity,
                        LanRuntimeError::self_target_disallowed);
  }
  const auto it =
      std::find_if(members_.begin(), members_.end(), [&](const LanMemberInfo &m) {
        return !m.is_host && m.pubkey == pubkey;
      });
  if (it == members_.end()) {
    return fail_rt_void(ErrorCode::invalid_identity, LanRuntimeError::peer_not_found);
  }
  LanMemberInfo kicked = *it;
  members_.erase(it);
  (void)endpoint_.revoke_peer(pubkey);

  ++roster_epoch_;
  broadcast_roster_best_effort();

  LanEvent ev{};
  ev.kind = LanEventKind::member_kicked;
  ev.peer_pubkey = kicked.pubkey;
  ev.sender_name = kicked.display_name;
  ev.sender_account_id = kicked.account_id;
  ev.member = std::move(kicked);
  ev.roster = members_;
  ev.roster_epoch = roster_epoch_;
  ev.lobby_locked = locked_;
  push_event(std::move(ev));
  return Result<void>::success();
}

std::optional<LanEvent> LanPartyHost::pop_event() {
  if (events_.empty()) {
    return std::nullopt;
  }
  LanEvent out = std::move(events_.front());
  events_.pop_front();
  return out;
}

std::vector<LanEvent> LanPartyHost::drain_events() {
  std::vector<LanEvent> out;
  out.reserve(events_.size());
  while (!events_.empty()) {
    out.push_back(std::move(events_.front()));
    events_.pop_front();
  }
  return out;
}

// ---------------------------------------------------------------------------
// LanPartyClient
// ---------------------------------------------------------------------------

LanPartyClient::LanPartyClient(LanPartyClient &&other) noexcept
    : state_(std::exchange(other.state_, LanSessionState::stopped)),
      identity_(std::move(other.identity_)), host_pubkey_(other.host_pubkey_),
      host_safety_number_(std::move(other.host_safety_number_)),
      source_addr_(std::move(other.source_addr_)),
      expected_lan_party_id_(std::move(other.expected_lan_party_id_)),
      expected_host_name_(std::move(other.expected_host_name_)),
      lan_party_id_(std::move(other.lan_party_id_)),
      lobby_name_(std::move(other.lobby_name_)),
      host_name_(std::move(other.host_name_)), host_account_id_(other.host_account_id_),
      room_scope_(std::move(other.room_scope_)), pin_(std::move(other.pin_)),
      policy_require_pin_(std::exchange(other.policy_require_pin_, false)),
      pin_required_(std::exchange(other.pin_required_, false)),
      join_sent_(std::exchange(other.join_sent_, false)),
      lobby_locked_(std::exchange(other.lobby_locked_, false)),
      last_rejection_reason_(std::move(other.last_rejection_reason_)),
      endpoint_(std::move(other.endpoint_)),
      trust_callback_(std::move(other.trust_callback_)),
      known_peers_(std::move(other.known_peers_)),
      pin_approved_peers_(other.pin_approved_peers_),
      roster_epoch_(std::exchange(other.roster_epoch_, 0U)),
      members_(std::move(other.members_)), events_(std::move(other.events_)) {
  other.identity_.signing_seed.cleanse();
  other.pin_.cleanse();
}

LanPartyClient &LanPartyClient::operator=(LanPartyClient &&other) noexcept {
  if (this != &other) {
    stop();
    state_ = std::exchange(other.state_, LanSessionState::stopped);
    identity_ = std::move(other.identity_);
    host_pubkey_ = other.host_pubkey_;
    host_safety_number_ = std::move(other.host_safety_number_);
    source_addr_ = std::move(other.source_addr_);
    expected_lan_party_id_ = std::move(other.expected_lan_party_id_);
    expected_host_name_ = std::move(other.expected_host_name_);
    lan_party_id_ = std::move(other.lan_party_id_);
    lobby_name_ = std::move(other.lobby_name_);
    host_name_ = std::move(other.host_name_);
    host_account_id_ = other.host_account_id_;
    room_scope_ = std::move(other.room_scope_);
    pin_ = std::move(other.pin_);
    policy_require_pin_ = std::exchange(other.policy_require_pin_, false);
    pin_required_ = std::exchange(other.pin_required_, false);
    join_sent_ = std::exchange(other.join_sent_, false);
    lobby_locked_ = std::exchange(other.lobby_locked_, false);
    last_rejection_reason_ = std::move(other.last_rejection_reason_);
    endpoint_ = std::move(other.endpoint_);
    trust_callback_ = std::move(other.trust_callback_);
    known_peers_ = std::move(other.known_peers_);
    pin_approved_peers_ = other.pin_approved_peers_;
    roster_epoch_ = std::exchange(other.roster_epoch_, 0U);
    members_ = std::move(other.members_);
    events_ = std::move(other.events_);
    other.identity_.signing_seed.cleanse();
    other.pin_.cleanse();
  }
  return *this;
}

LanPartyClient::~LanPartyClient() noexcept { stop(); }

Result<LanPartyClient> LanPartyClient::join(LanClientConfig cfg) {
  CleanseStringGuard raw_pin_guard{cfg.pin};

  // 1. Strict Policy & Mandate Gate FIRST (ZERO sockets opened on denial).
  const auto policy_res = run_policy_and_auth_gate(
      cfg.policy_paths, cfg.env_lookup, cfg.require_local_auth, cfg.local_auth_options,
      "Authorize Blackbird LAN Party join");
  if (!policy_res.has_value()) {
    return Result<LanPartyClient>::failure(policy_res.error());
  }
  const LanPolicyConfig effective = policy_res.value();

  // 2. Validate identity, host pubkey, PIN, expected party ID, and targets (ZERO
  // sockets).
  if (const auto id_ok = validate_local_identity(cfg.identity); !id_ok.has_value()) {
    return Result<LanPartyClient>::failure(id_ok.error());
  }
  if (!mp::validate_ed25519_pubkey_strict(cfg.host_pubkey).has_value()) {
    return fail_lan<LanPartyClient>(ErrorCode::invalid_identity,
                                    LanError::invalid_pubkey);
  }
  if (cfg.host_pubkey == cfg.identity.public_key) {
    return fail_rt<LanPartyClient>(ErrorCode::invalid_identity,
                                   LanRuntimeError::self_target_disallowed);
  }

  if (effective.require_pin && cfg.pin.empty()) {
    return fail_lan<LanPartyClient>(ErrorCode::invalid_identity, LanError::invalid_pin);
  }
  CleansedPin cleansed_pin;
  if (!cfg.pin.empty()) {
    auto pin_res = CleansedPin::create(cfg.pin);
    if (!pin_res.has_value()) {
      return Result<LanPartyClient>::failure(pin_res.error());
    }
    cleansed_pin = std::move(pin_res).value();
  }

  std::string expected_party_id;
  if (!cfg.expected_lan_party_id.empty()) {
    const auto parsed = parse_lan_party_id_hex(cfg.expected_lan_party_id);
    if (!parsed.has_value()) {
      return Result<LanPartyClient>::failure(parsed.error());
    }
    expected_party_id = format_lan_party_id_hex(parsed.value());
  }

  std::vector<P2pDirectAddr> target_addrs = cfg.host_addrs;
  for (const auto &raw_target : cfg.direct_targets) {
    const auto parsed = parse_lan_direct_target(raw_target);
    if (!parsed.has_value()) {
      return Result<LanPartyClient>::failure(parsed.error());
    }
    if (std::find(target_addrs.begin(), target_addrs.end(), parsed.value()) ==
        target_addrs.end()) {
      target_addrs.push_back(parsed.value());
    }
  }
  if (target_addrs.empty() || target_addrs.size() > kP2pMaxDirectAddrs) {
    return fail_rt<LanPartyClient>(ErrorCode::invalid_range,
                                   LanRuntimeError::invalid_direct_target);
  }

  std::string source_addr{kDefaultPeerSourceAddr};
  if (const auto fmt = format_lan_direct_target(target_addrs.front());
      fmt.has_value()) {
    source_addr = fmt.value();
  }

  const auto host_sn = compute_lan_safety_number(0U, cfg.host_pubkey);
  if (!host_sn.has_value()) {
    return Result<LanPartyClient>::failure(host_sn.error());
  }

  // Check optional KnownPeersStore BEFORE dialing.
  std::optional<KnownPeersStore> known_peers;
  if (cfg.known_peers_path.has_value() && !cfg.known_peers_path->empty()) {
    auto kp_res = KnownPeersStore::open(*cfg.known_peers_path);
    if (!kp_res.has_value()) {
      return fail_rt<LanPartyClient>(kp_res.error().code,
                                     LanRuntimeError::trust_store_failed);
    }
    known_peers.emplace(std::move(kp_res).value());
  }

  const KnownPeerLookup host_trust = check_known_peer(known_peers, cfg.host_pubkey);
  if (host_trust == KnownPeerLookup::pinned_revoked_or_corrupt) {
    known_peers.reset();
    return fail_rt<LanPartyClient>(ErrorCode::invalid_identity,
                                   LanRuntimeError::peer_rejected);
  }
  if (host_trust == KnownPeerLookup::not_pinned && !cfg.trust_callback) {
    // Unpinned peer with no trust callback MUST fail closed (ZERO sockets).
    known_peers.reset();
    return fail_rt<LanPartyClient>(ErrorCode::invalid_identity,
                                   LanRuntimeError::peer_rejected);
  }

  // 3. Create iroh P2P endpoint in strict no_relays mode, allow host, and dial.
  P2pEndpointConfig ep_cfg{};
  ep_cfg.relay_policy = P2pRelayPolicy::no_relays;
  ep_cfg.secret_key = cfg.identity.signing_seed.bytes();
  ep_cfg.relay_url.clear();
  CleanseOptionalSecretGuard ep_secret_guard{ep_cfg.secret_key};

  auto ep_res = P2pEndpoint::create(ep_cfg);
  if (!ep_res.has_value()) {
    known_peers.reset();
    return Result<LanPartyClient>::failure(ep_res.error());
  }
  P2pEndpoint endpoint = std::move(ep_res).value();

  if (const auto allow_res = endpoint.allow_peer(cfg.host_pubkey);
      !allow_res.has_value()) {
    endpoint.close();
    known_peers.reset();
    return Result<LanPartyClient>::failure(allow_res.error());
  }

  P2pPeerTarget peer_target{};
  peer_target.pubkey = cfg.host_pubkey;
  peer_target.remote_relay_policy = P2pRelayPolicy::no_relays;
  peer_target.relay_url.clear();
  peer_target.direct_addrs = std::move(target_addrs);
  peer_target.connect_timeout_ms = cfg.connect_timeout_ms;

  if (const auto conn_res = endpoint.connect_peer(peer_target); !conn_res.has_value()) {
    endpoint.close();
    known_peers.reset();
    return Result<LanPartyClient>::failure(conn_res.error());
  }

  LanPartyClient client;
  client.state_ = LanSessionState::handshaking;
  client.identity_ = std::move(cfg.identity);
  client.host_pubkey_ = cfg.host_pubkey;
  client.host_safety_number_ = host_sn.value();
  client.source_addr_ = std::move(source_addr);
  client.expected_lan_party_id_ = std::move(expected_party_id);
  client.expected_host_name_ = std::move(cfg.expected_host_name);
  client.room_scope_ =
      cfg.room_scope.empty()
          ? std::string{kLanDefaultRoomScope}
          : party_chat_sanitize(cfg.room_scope, kP2pPartyMaxRoomScopeBytes);
  client.pin_ = std::move(cleansed_pin);
  client.policy_require_pin_ = effective.require_pin;
  client.endpoint_ = std::move(endpoint);
  client.trust_callback_ = std::move(cfg.trust_callback);
  client.known_peers_ = std::move(known_peers);
  client.pin_approved_peers_ = cfg.pin_approved_peers;

  return Result<LanPartyClient>::success(std::move(client));
}

void LanPartyClient::push_event(LanEvent event) {
  if (events_.size() >= kLanRuntimeMaxQueuedEvents) {
    events_.pop_front();
  }
  events_.push_back(std::move(event));
}

void LanPartyClient::close_resources_noexcept() noexcept {
  endpoint_.close();
  known_peers_.reset();
  pin_.cleanse();
}

void LanPartyClient::stop() noexcept {
  close_resources_noexcept();
  identity_.signing_seed.cleanse();
  state_ = LanSessionState::stopped;
}

void LanPartyClient::fail_rejected(std::string_view reason) {
  if (endpoint_.valid()) {
    (void)endpoint_.revoke_peer(host_pubkey_);
  }
  last_rejection_reason_ = party_chat_sanitize(reason, kLanMaxRejectReasonBytes);
  close_resources_noexcept();
  state_ = LanSessionState::rejected;

  LanEvent ev{};
  ev.kind = LanEventKind::welcome_rejected;
  ev.peer_pubkey = host_pubkey_;
  ev.safety_number = host_safety_number_;
  ev.reason = last_rejection_reason_;
  push_event(std::move(ev));
}

bool LanPartyClient::verify_or_pin_host(std::string_view display_name,
                                        std::uint64_t account_id) {
  const KnownPeerLookup status = check_known_peer(known_peers_, host_pubkey_);
  if (status == KnownPeerLookup::pinned_trusted) {
    return true;
  }
  if (status == KnownPeerLookup::pinned_revoked_or_corrupt) {
    return false;
  }
  if (!trust_callback_) {
    return false;
  }
  LanPeerTrustPrompt prompt{};
  prompt.display_name = std::string{display_name};
  prompt.account_id = account_id;
  prompt.pubkey = host_pubkey_;
  prompt.safety_number = host_safety_number_;
  prompt.source_addr = source_addr_;
  prompt.is_host = true;
  if (!trust_callback_(prompt)) {
    return false;
  }
  if (pin_approved_peers_) {
    pin_peer_best_effort(known_peers_, host_pubkey_, host_safety_number_);
  }
  return true;
}

Result<std::size_t> LanPartyClient::pump_once(std::uint32_t timeout_ms) {
  if (!active() || !endpoint_.valid()) {
    return fail_rt<std::size_t>(ErrorCode::stale_handle, LanRuntimeError::not_running);
  }
  const std::size_t before = events_.size();
  for (std::size_t i = 0U;
       i < kLanRuntimeMaxEventsPerPump && active() && endpoint_.valid(); ++i) {
    const std::uint32_t poll_ms = (i == 0U) ? timeout_ms : 0U;
    const auto polled = endpoint_.poll_event(poll_ms);
    if (!polled.has_value()) {
      return Result<std::size_t>::failure(polled.error());
    }
    if (!polled.value().has_value()) {
      break;
    }
    handle_transport_event(*polled.value());
  }
  return Result<std::size_t>::success(events_.size() >= before ? events_.size() - before
                                                               : 0U);
}

void LanPartyClient::handle_transport_event(const P2pEvent &ev) {
  if (ev.peer_pubkey != host_pubkey_) {
    return;
  }
  switch (ev.kind) {
  case P2pEventKind::none:
  case P2pEventKind::peer_connected:
    return;

  case P2pEventKind::peer_disconnected: {
    close_resources_noexcept();
    state_ = LanSessionState::disconnected;
    LanEvent out{};
    out.kind = LanEventKind::disconnected;
    out.peer_pubkey = host_pubkey_;
    out.reason_code = ev.reason_code;
    push_event(std::move(out));
    return;
  }

  case P2pEventKind::frame_received: {
    if (ev.lane == P2pLane::control) {
      handle_control_frame(ev);
      return;
    }
    if (state_ != LanSessionState::connected) {
      LanEvent dropped{};
      dropped.kind = LanEventKind::frame_dropped;
      dropped.peer_pubkey = ev.peer_pubkey;
      dropped.reason = "data_before_welcome";
      push_event(std::move(dropped));
      return;
    }
    if (ev.lane == P2pLane::causal) {
      const auto decoded = decode_p2p_party_frame(P2pLane::causal, ev.payload);
      if (!decoded.has_value()) {
        LanEvent dropped{};
        dropped.kind = LanEventKind::frame_dropped;
        dropped.peer_pubkey = ev.peer_pubkey;
        dropped.error = decoded.error();
        push_event(std::move(dropped));
        return;
      }
      const auto *chat = std::get_if<P2pPartyChatMessage>(&decoded.value());
      if (chat == nullptr) {
        LanEvent dropped{};
        dropped.kind = LanEventKind::frame_dropped;
        dropped.peer_pubkey = ev.peer_pubkey;
        dropped.reason = "unexpected_causal_frame";
        push_event(std::move(dropped));
        return;
      }
      P2pPartyChatMessage clean{};
      clean.room_scope =
          party_chat_sanitize(chat->room_scope, kP2pPartyMaxRoomScopeBytes);
      clean.target_selector =
          party_chat_sanitize(chat->target_selector, kP2pPartyMaxTargetSelectorBytes);
      clean.sender_handle =
          party_chat_sanitize(chat->sender_handle, kP2pPartyMaxSenderHandleBytes);
      clean.timestamp_ns = chat->timestamp_ns;
      clean.body = party_chat_sanitize(chat->body, kP2pPartyMaxChatBodyBytes);

      LanEvent out{};
      out.kind = LanEventKind::chat_received;
      out.peer_pubkey = ev.peer_pubkey;
      out.sender_name = clean.sender_handle;
      out.chat = std::move(clean);
      push_event(std::move(out));
      return;
    }
    if (ev.lane == P2pLane::ephemeral) {
      const auto decoded = decode_p2p_party_frame(P2pLane::ephemeral, ev.payload);
      if (!decoded.has_value()) {
        LanEvent dropped{};
        dropped.kind = LanEventKind::frame_dropped;
        dropped.peer_pubkey = ev.peer_pubkey;
        dropped.error = decoded.error();
        push_event(std::move(dropped));
        return;
      }
      const auto *pulse = std::get_if<P2pPartyEphemeralPulse>(&decoded.value());
      if (pulse == nullptr) {
        LanEvent dropped{};
        dropped.kind = LanEventKind::frame_dropped;
        dropped.peer_pubkey = ev.peer_pubkey;
        dropped.reason = "unexpected_ephemeral_frame";
        push_event(std::move(dropped));
        return;
      }
      P2pPartyEphemeralPulse clean{};
      clean.activity_state = pulse->activity_state;
      clean.timestamp_ns = pulse->timestamp_ns;
      clean.status =
          party_chat_sanitize(pulse->status, kP2pPartyMaxEphemeralStatusBytes);

      LanEvent out{};
      out.kind = LanEventKind::pulse_received;
      out.peer_pubkey = ev.peer_pubkey;
      out.pulse = std::move(clean);
      push_event(std::move(out));
      return;
    }
    return;
  }
  }
}

void LanPartyClient::handle_control_frame(const P2pEvent &ev) {
  const auto decoded = decode_lan_handshake_frame(ev.lane, ev.payload);
  if (!decoded.has_value()) {
    LanEvent dropped{};
    dropped.kind = LanEventKind::frame_dropped;
    dropped.peer_pubkey = ev.peer_pubkey;
    dropped.error = decoded.error();
    push_event(std::move(dropped));
    return;
  }
  if (const auto *hello = std::get_if<LanHelloMessage>(&decoded.value())) {
    handle_hello(*hello);
  } else if (const auto *welcome = std::get_if<LanWelcomeMessage>(&decoded.value())) {
    handle_welcome(*welcome);
  } else if (const auto *roster = std::get_if<LanRosterMessage>(&decoded.value())) {
    handle_roster(*roster);
  } else {
    LanEvent dropped{};
    dropped.kind = LanEventKind::frame_dropped;
    dropped.peer_pubkey = ev.peer_pubkey;
    dropped.reason = "unexpected_lan_join_on_client";
    push_event(std::move(dropped));
  }
}

void LanPartyClient::handle_hello(const LanHelloMessage &hello) {
  if (state_ != LanSessionState::handshaking || join_sent_) {
    return;
  }
  if (hello.host_pubkey != host_pubkey_) {
    fail_rejected("host_pubkey_mismatch");
    return;
  }
  if (!expected_lan_party_id_.empty() && hello.lan_party_id != expected_lan_party_id_) {
    fail_rejected("party_id_mismatch");
    return;
  }

  lan_party_id_ = hello.lan_party_id;
  lobby_name_ = sanitize_lan_display_name(hello.lobby_name);
  host_name_ = sanitize_lan_display_name(hello.host_name);
  host_account_id_ = hello.host_account_id;
  pin_required_ = hello.require_pin;

  // Enforce non-overridable client policy floor: refuse PIN-less hosts when
  // effective.require_pin is enabled.
  if (policy_require_pin_ && !hello.require_pin) {
    fail_rejected("pin_required");
    return;
  }

  // Recompute canonical Safety Number using the host's account_id (0 for
  // unregistered LAN identities, >0 for registered online identities).
  const auto updated_sn =
      compute_lan_safety_number(hello.host_account_id, host_pubkey_);
  if (!updated_sn.has_value()) {
    fail_rejected("invalid_host_pubkey");
    return;
  }
  host_safety_number_ = updated_sn.value();

  // Mandate #5: Verify host Safety Number via trust_callback BEFORE sending
  // LAN_JOIN or any PIN proof!
  const std::string prompt_name =
      expected_host_name_.empty() ? host_name_ : expected_host_name_;
  if (!verify_or_pin_host(prompt_name, hello.host_account_id)) {
    fail_rejected("rejected");
    return;
  }

  if (hello.require_pin && pin_.empty()) {
    fail_rejected("pin_required");
    return;
  }

  LanJoinMessage join{};
  join.lan_party_id = lan_party_id_;
  join.display_name = identity_.display_name;
  join.account_id = identity_.account_id;
  if (hello.require_pin) {
    LanPinProofInput proof_in{};
    proof_in.pin = pin_.view();
    proof_in.lan_party_id_hex = lan_party_id_;
    proof_in.host_pubkey = host_pubkey_;
    proof_in.joiner_pubkey = identity_.public_key;
    proof_in.host_nonce = hello.host_nonce;
    const auto proof = compute_lan_pin_proof(proof_in);
    if (!proof.has_value()) {
      fail_rejected("invalid_pin");
      return;
    }
    join.pin_proof = proof.value();
  }

  const auto encoded = encode_lan_handshake_frame(join);
  if (!encoded.has_value() ||
      !endpoint_.send_frame(host_pubkey_, P2pLane::control, encoded.value())
           .has_value()) {
    fail_rejected("handshake_send_failed");
    return;
  }
  join_sent_ = true;
}

void LanPartyClient::handle_welcome(const LanWelcomeMessage &welcome) {
  if (state_ != LanSessionState::handshaking || !join_sent_) {
    return;
  }
  if (welcome.lan_party_id != lan_party_id_) {
    fail_rejected("party_id_mismatch");
    return;
  }
  if (!welcome.accepted) {
    const std::string_view why =
        welcome.reason.empty() ? std::string_view{"rejected"} : welcome.reason;
    fail_rejected(why);
    return;
  }

  members_ = welcome.members;
  roster_epoch_ = welcome.roster_epoch;
  state_ = LanSessionState::connected;
  pin_.cleanse();

  LanEvent ev{};
  ev.kind = LanEventKind::connected;
  ev.peer_pubkey = host_pubkey_;
  ev.sender_name = host_name_;
  ev.sender_account_id = host_account_id_;
  ev.safety_number = host_safety_number_;
  ev.roster = members_;
  ev.roster_epoch = roster_epoch_;
  push_event(std::move(ev));
}

void LanPartyClient::handle_roster(const LanRosterMessage &roster) {
  if (state_ != LanSessionState::connected) {
    return;
  }
  if (roster.lan_party_id != lan_party_id_ || roster.roster_epoch < roster_epoch_) {
    return;
  }
  members_ = roster.members;
  roster_epoch_ = roster.roster_epoch;
  lobby_locked_ = roster.locked;

  LanEvent ev{};
  ev.kind = LanEventKind::roster_updated;
  ev.peer_pubkey = host_pubkey_;
  ev.roster = members_;
  ev.roster_epoch = roster_epoch_;
  ev.lobby_locked = lobby_locked_;
  push_event(std::move(ev));
}

Result<void> LanPartyClient::send_chat(std::string_view body,
                                       const LanChatTarget &target) {
  if (state_ != LanSessionState::connected || !endpoint_.valid()) {
    return fail_rt_void(ErrorCode::stale_handle, LanRuntimeError::not_connected);
  }
  P2pPartyChatMessage msg{};
  msg.room_scope = room_scope_;
  msg.target_selector =
      party_chat_sanitize(target.value, kP2pPartyMaxTargetSelectorBytes);
  msg.sender_handle = identity_.display_name;
  msg.timestamp_ns = now_unix_ns();
  msg.body = party_chat_sanitize(body, kP2pPartyMaxChatBodyBytes);

  const auto encoded = encode_p2p_party_frame(msg);
  if (!encoded.has_value()) {
    return Result<void>::failure(encoded.error());
  }
  return endpoint_.send_frame(host_pubkey_, P2pLane::causal, encoded.value());
}

Result<void> LanPartyClient::send_pulse(P2pPartyActivityState activity_state,
                                        std::string_view status) {
  if (state_ != LanSessionState::connected || !endpoint_.valid()) {
    return fail_rt_void(ErrorCode::stale_handle, LanRuntimeError::not_connected);
  }
  P2pPartyEphemeralPulse pulse{};
  pulse.activity_state = activity_state;
  pulse.timestamp_ns = now_unix_ns();
  pulse.status = party_chat_sanitize(status, kP2pPartyMaxEphemeralStatusBytes);

  const auto encoded = encode_p2p_party_frame(pulse);
  if (!encoded.has_value()) {
    return Result<void>::failure(encoded.error());
  }
  return endpoint_.send_frame(host_pubkey_, P2pLane::ephemeral, encoded.value());
}

std::optional<LanEvent> LanPartyClient::pop_event() {
  if (events_.empty()) {
    return std::nullopt;
  }
  LanEvent out = std::move(events_.front());
  events_.pop_front();
  return out;
}

std::vector<LanEvent> LanPartyClient::drain_events() {
  std::vector<LanEvent> out;
  out.reserve(events_.size());
  while (!events_.empty()) {
    out.push_back(std::move(events_.front()));
    events_.pop_front();
  }
  return out;
}

} // namespace blackbird::lan
