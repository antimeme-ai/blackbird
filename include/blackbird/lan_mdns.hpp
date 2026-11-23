#pragma once

#include "blackbird/foundation.hpp"
#include "blackbird/p2p_transport.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace blackbird {

// ---------------------------------------------------------------------------
// Constants & error details (carried in blackbird::Error::detail)
// ---------------------------------------------------------------------------

inline constexpr std::string_view kLanMdnsServiceType = "_mp1-lan._udp.local.";
inline constexpr std::string_view kLanMdnsLocalDomain = ".local.";
inline constexpr std::string_view kLanMdnsMulticastGroup = "224.0.0.251";
inline constexpr std::uint16_t kLanMdnsDefaultPort = 5353U;

inline constexpr std::uint32_t kLanBeaconVersion = 1U;
inline constexpr std::size_t kLanMaxTxtBytes = 256U;
inline constexpr std::size_t kLanPartyIdHexLength = 16U;
inline constexpr std::size_t kLanMinDisplayTextLength = 1U;
inline constexpr std::size_t kLanMaxDisplayTextLength = 32U;
inline constexpr std::size_t kLanPubkeyB64UrlLength = 43U;

inline constexpr std::size_t kLanMdnsMaxPacketBytes = 4096U;
inline constexpr std::size_t kLanMdnsMaxNameLength = 255U;
inline constexpr std::size_t kLanMdnsMaxLabelLength = 63U;
inline constexpr std::size_t kLanMdnsMaxNameJumps = 16U;
inline constexpr std::size_t kLanMdnsMaxRecordsPerPacket = 128U;

inline constexpr std::uint32_t kLanMdnsDefaultTtlSec = 120U;
inline constexpr std::uint32_t kLanAnnounceRefreshIntervalSec = 30U;

inline constexpr std::uint32_t kLanMinIdleTimeoutSec = 1U;
inline constexpr std::uint32_t kLanDefaultIdleTimeoutSec = 300U;
inline constexpr std::uint32_t kLanMaxIdleTimeoutSec = 1800U;

inline constexpr std::uint32_t kLanMinScanTimeoutSec = 1U;
inline constexpr std::uint32_t kLanDefaultScanTimeoutSec = 15U;
inline constexpr std::uint32_t kLanMaxScanTimeoutSec = 60U;

inline constexpr std::size_t kLanMaxDiscoveredLobbies = 128U;

inline constexpr std::uint16_t kDnsTypeA = 1U;
inline constexpr std::uint16_t kDnsTypePtr = 12U;
inline constexpr std::uint16_t kDnsTypeTxt = 16U;
inline constexpr std::uint16_t kDnsTypeAaaa = 28U;
inline constexpr std::uint16_t kDnsTypeSrv = 33U;
inline constexpr std::uint16_t kDnsClassIn = 1U;
inline constexpr std::uint16_t kDnsClassMask = 0x7fffU;
inline constexpr std::uint16_t kDnsClassUnicastOrFlushBit = 0x8000U;

enum class LanMdnsError : std::int64_t {
  none = 0,

  // LanBeaconRecord & TXT codec
  invalid_version = 2200,
  invalid_party_id = 2201,
  invalid_lobby_name = 2202,
  invalid_host_name = 2203,
  invalid_pubkey = 2204,
  invalid_pin_flag = 2205,
  invalid_alpn = 2206,
  txt_too_large = 2207,
  txt_malformed = 2208,
  txt_duplicate_key = 2209,
  txt_missing_key = 2210,
  txt_unknown_key = 2211,

  // DNS / mDNS wire codec
  dns_truncated = 2220,
  dns_malformed_header = 2221,
  dns_name_too_long = 2222,
  dns_label_too_long = 2223,
  dns_pointer_loop = 2224,
  dns_pointer_oob = 2225,
  dns_invalid_record = 2226,
  dns_packet_too_large = 2227,

  // Socket, advertiser, scanner lifecycle
  invalid_timeout = 2240,
  invalid_port = 2241,
  invalid_socket_config = 2242,
  socket_open_failed = 2243,
  socket_config_failed = 2244,
  socket_bind_failed = 2245,
  socket_io_failed = 2246,
  already_running = 2247,
  not_running = 2248,

  // Direct ip:port target parser/formatter
  invalid_direct_target = 2260,
};

constexpr LanMdnsError lan_mdns_error_of(const Error &error) noexcept {
  return static_cast<LanMdnsError>(error.detail);
}

std::string_view lan_mdns_error_name(LanMdnsError detail) noexcept;

// Distinct non-mutually-convertible wrappers prevent parameter swapping while
// allowing callers to pass raw ports and timeouts ergonomically.
struct LanServicePort {
  std::uint16_t value = 0U;
  constexpr LanServicePort(std::uint16_t port) noexcept : value(port) {}
};

struct LanIdleTimeoutSec {
  std::uint32_t value = kLanDefaultIdleTimeoutSec;
  constexpr LanIdleTimeoutSec(std::uint32_t seconds) noexcept : value(seconds) {}
};

// ---------------------------------------------------------------------------
// 1. Strict LanBeaconRecord & TXT Codec (<= 256 B, zero secrets)
// ---------------------------------------------------------------------------

struct LanBeaconRecord {
  std::uint32_t version = kLanBeaconVersion;
  std::string lan_party_id;
  std::string lobby_name;
  std::string host_name;
  P2pPubkey host_pubkey{};
  bool require_pin = false;
  std::string alpn{kP2pAlpn};

  bool operator==(const LanBeaconRecord &) const = default;
};

std::string encode_lan_pubkey_base64url(const P2pPubkey &pubkey);
Result<P2pPubkey> decode_lan_pubkey_base64url(std::string_view encoded);

Result<void> validate_lan_beacon_record(const LanBeaconRecord &beacon);
Result<std::vector<std::uint8_t>> encode_lan_txt_record(const LanBeaconRecord &beacon);
Result<LanBeaconRecord> decode_lan_txt_record(std::span<const std::uint8_t> wire);

// ---------------------------------------------------------------------------
// 2. Zero-Dep RFC 6762 / 6763 DNS/mDNS Wire Packet Codec
// ---------------------------------------------------------------------------

struct LanMdnsQuestion {
  std::string qname;
  std::uint16_t qtype = 0U;
  std::uint16_t qclass = kDnsClassIn;
  bool unicast_response = false;

  bool operator==(const LanMdnsQuestion &) const = default;
};

struct LanMdnsAnnouncement {
  LanBeaconRecord beacon;
  std::uint16_t service_port = 0U;
  std::vector<P2pDirectAddr> addrs;
  std::uint32_t ttl_sec = kLanMdnsDefaultTtlSec;

  bool is_goodbye() const noexcept { return ttl_sec == 0U; }
  bool operator==(const LanMdnsAnnouncement &) const = default;
};

struct LanMdnsPacket {
  std::uint16_t transaction_id = 0U;
  bool is_response = false;
  std::vector<LanMdnsQuestion> questions;
  std::optional<LanMdnsAnnouncement> announcement = std::nullopt;
  // Populated when a minimal RFC 6762 PTR-only TTL=0 goodbye packet arrives
  // without an accompanying TXT record.
  std::vector<std::string> goodbye_party_ids;

  bool operator==(const LanMdnsPacket &) const = default;
};

bool dns_names_equal_ci(std::string_view lhs, std::string_view rhs) noexcept;

Result<std::vector<std::uint8_t>> encode_lan_ptr_query(bool unicast_response = false);

Result<std::vector<std::uint8_t>>
encode_lan_announcement(const LanMdnsAnnouncement &announcement);

Result<std::vector<std::uint8_t>>
encode_lan_goodbye(const LanBeaconRecord &beacon, LanServicePort service_port,
                   std::span<const P2pDirectAddr> addrs = {});

Result<LanMdnsPacket> decode_lan_mdns_packet(std::span<const std::uint8_t> packet);

// ---------------------------------------------------------------------------
// 3. Strictly Opt-In LanMdnsAdvertiser & LanMdnsScanner
// ---------------------------------------------------------------------------

struct LanMdnsSocketConfig {
  std::string bind_address = "0.0.0.0";
  std::uint16_t bind_port = kLanMdnsDefaultPort;
  std::string target_address{kLanMdnsMulticastGroup};
  std::uint16_t target_port = kLanMdnsDefaultPort;
  bool enable_multicast = true;
  // When empty, LanMdnsAdvertiser enumerates non-loopback local LAN IPv4
  // addresses via getifaddrs().
  std::vector<P2pDirectAddr> advertise_addrs;

  static LanMdnsSocketConfig production_multicast() { return LanMdnsSocketConfig{}; }
};

Result<std::vector<P2pDirectAddr>>
enumerate_lan_ipv4_addrs(LanServicePort service_port);

class LanMdnsAdvertiser {
public:
  // Strictly opt-in: zero sockets opened on construction.
  LanMdnsAdvertiser() noexcept = default;
  LanMdnsAdvertiser(const LanMdnsAdvertiser &) = delete;
  LanMdnsAdvertiser &operator=(const LanMdnsAdvertiser &) = delete;
  LanMdnsAdvertiser(LanMdnsAdvertiser &&other) noexcept;
  LanMdnsAdvertiser &operator=(LanMdnsAdvertiser &&other) noexcept;
  ~LanMdnsAdvertiser() noexcept;

  Result<void> start(const LanBeaconRecord &beacon, LanServicePort service_port,
                     LanIdleTimeoutSec idle_timeout_sec = kLanDefaultIdleTimeoutSec,
                     const LanMdnsSocketConfig &socket_cfg =
                         LanMdnsSocketConfig::production_multicast());

  Result<void> pump_once(
      std::uint32_t timeout_ms = 0U,
      std::optional<std::chrono::steady_clock::time_point> now_override = std::nullopt);

  void mark_peer_joined() noexcept;
  void lock_lobby() noexcept;
  void stop() noexcept;

  bool active() const noexcept { return running_; }
  bool expired() const noexcept { return expired_; }
  bool locked() const noexcept { return locked_; }
  bool has_peer_joined() const noexcept { return has_peer_joined_; }
  std::uint16_t bound_port() const noexcept { return bound_port_; }
  std::uint64_t announcements_sent() const noexcept { return announcements_sent_; }
  std::uint64_t queries_answered() const noexcept { return queries_answered_; }
  std::uint64_t goodbyes_sent() const noexcept { return goodbyes_sent_; }

private:
  void send_goodbye_best_effort() noexcept;
  void close_socket_noexcept() noexcept;

  int fd_ = -1;
  bool running_ = false;
  bool expired_ = false;
  bool locked_ = false;
  bool has_peer_joined_ = false;
  bool enable_multicast_ = true;
  bool has_target_ = false;
  bool has_last_unicast_peer_ = false;
  std::uint16_t bound_port_ = 0U;
  std::uint32_t target_ipv4_be_ = 0U;
  std::uint16_t target_port_ = 0U;
  std::uint32_t last_unicast_peer_ipv4_be_ = 0U;
  std::uint16_t last_unicast_peer_port_ = 0U;
  std::uint32_t idle_timeout_sec_ = kLanDefaultIdleTimeoutSec;
  std::chrono::steady_clock::time_point started_at_{};
  std::chrono::steady_clock::time_point last_announce_at_{};
  std::vector<std::uint8_t> announce_packet_;
  std::vector<std::uint8_t> goodbye_packet_;
  std::uint64_t announcements_sent_ = 0U;
  std::uint64_t queries_answered_ = 0U;
  std::uint64_t goodbyes_sent_ = 0U;
};

struct DiscoveredLanLobby {
  LanBeaconRecord beacon;
  std::uint16_t service_port = 0U;
  std::vector<P2pDirectAddr> addrs;
  std::uint32_t ttl_sec = 0U;
  std::chrono::steady_clock::time_point last_seen{};

  bool operator==(const DiscoveredLanLobby &) const = default;
};

class LanMdnsScanner {
public:
  // Strictly opt-in: zero sockets opened on construction.
  LanMdnsScanner() noexcept = default;
  LanMdnsScanner(const LanMdnsScanner &) = delete;
  LanMdnsScanner &operator=(const LanMdnsScanner &) = delete;
  LanMdnsScanner(LanMdnsScanner &&other) noexcept;
  LanMdnsScanner &operator=(LanMdnsScanner &&other) noexcept;
  ~LanMdnsScanner() noexcept;

  Result<void> start(std::uint32_t scan_timeout_sec = kLanDefaultScanTimeoutSec,
                     const LanMdnsSocketConfig &socket_cfg =
                         LanMdnsSocketConfig::production_multicast());

  Result<void> send_query();

  Result<void> pump_once(
      std::uint32_t timeout_ms = 0U,
      std::optional<std::chrono::steady_clock::time_point> now_override = std::nullopt);

  void stop() noexcept;

  bool active() const noexcept { return running_; }
  bool expired() const noexcept { return expired_; }
  std::uint16_t bound_port() const noexcept { return bound_port_; }
  std::uint64_t queries_sent() const noexcept { return queries_sent_; }
  std::vector<DiscoveredLanLobby> lobbies() const;

private:
  void close_socket_noexcept() noexcept;

  int fd_ = -1;
  bool running_ = false;
  bool expired_ = false;
  bool enable_multicast_ = true;
  bool has_target_ = false;
  std::uint16_t bound_port_ = 0U;
  std::uint32_t target_ipv4_be_ = 0U;
  std::uint16_t target_port_ = 0U;
  std::uint32_t scan_timeout_sec_ = kLanDefaultScanTimeoutSec;
  std::chrono::steady_clock::time_point started_at_{};
  std::vector<std::uint8_t> query_packet_;
  std::vector<DiscoveredLanLobby> lobbies_;
  std::uint64_t queries_sent_ = 0U;
};

// ---------------------------------------------------------------------------
// 4. Quake-Style Direct Target Parser & Formatter
// ---------------------------------------------------------------------------

Result<P2pDirectAddr> parse_lan_direct_target(std::string_view input);
Result<std::string> format_lan_direct_target(const P2pDirectAddr &addr);

} // namespace blackbird
