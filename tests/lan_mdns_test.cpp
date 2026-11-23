#include "blackbird/lan_mdns.hpp"

#include <arpa/inet.h>
#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <dirent.h>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void require(bool condition, const char *message) {
  if (!condition) {
    throw std::runtime_error(std::string{g_stage} + ": " + message);
  }
}

template <typename T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(
        std::string{g_stage} + " [" + context + "]: code=" +
        std::to_string(static_cast<int>(result.error().code)) + " detail=" +
        std::string{lan_mdns_error_name(lan_mdns_error_of(result.error()))});
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(
        std::string{g_stage} + " [" + context + "]: code=" +
        std::to_string(static_cast<int>(result.error().code)) + " detail=" +
        std::string{lan_mdns_error_name(lan_mdns_error_of(result.error()))});
  }
}

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
  // Subtract 1 for the DIR* fd itself that was open during enumeration.
  return count > 0 ? count - 1 : 0;
}

P2pPubkey make_test_pubkey(std::uint8_t seed_byte) {
  P2pPubkey pk{};
  for (std::size_t i = 0U; i < pk.size(); ++i) {
    pk[i] = static_cast<std::uint8_t>((seed_byte + i * 7U) & 0xffU);
  }
  if (pk[0] == 0U) {
    pk[0] = 1U;
  }
  return pk;
}

struct BeaconSpec {
  std::string_view id = "a1b2c3d4e5f60708";
  std::string_view lobby_name = "quake-night";
  std::string_view host_name = "alice";
  std::uint8_t key_seed = 0x11U;
  bool require_pin = true;
};

LanBeaconRecord make_valid_beacon(const BeaconSpec &spec = {}) {
  LanBeaconRecord beacon{};
  beacon.version = kLanBeaconVersion;
  beacon.lan_party_id = std::string{spec.id};
  beacon.lobby_name = std::string{spec.lobby_name};
  beacon.host_name = std::string{spec.host_name};
  beacon.host_pubkey = make_test_pubkey(spec.key_seed);
  beacon.require_pin = spec.require_pin;
  beacon.alpn = std::string{kP2pAlpn};
  return beacon;
}

std::vector<std::uint8_t> build_txt_wire(const std::vector<std::string> &entries) {
  std::vector<std::uint8_t> wire;
  for (const auto &entry : entries) {
    wire.push_back(static_cast<std::uint8_t>(entry.size()));
    for (const char ch : entry) {
      wire.push_back(static_cast<std::uint8_t>(ch));
    }
  }
  return wire;
}

void send_raw_udp_to_loopback(std::uint16_t port, std::span<const std::uint8_t> bytes) {
  const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  require(fd >= 0, "helper UDP socket must open");
  sockaddr_in dest{};
  dest.sin_family = AF_INET;
  require(::inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr) == 1,
          "inet_pton loopback must succeed");
  const std::uint16_t port_be =
      (std::endian::native == std::endian::little) ? std::byteswap(port) : port;
  dest.sin_port = static_cast<in_port_t>(port_be);
  const ssize_t sent =
      ::sendto(fd, bytes.data(), bytes.size(), 0,
               reinterpret_cast<const sockaddr *>(&dest), sizeof(dest));
  (void)::close(fd);
  require(sent == static_cast<ssize_t>(bytes.size()), "helper UDP sendto must succeed");
}

void test_pubkey_base64url_and_txt_codec() {
  g_stage = "pubkey_base64url_and_txt_codec";

  // 1. Canonical 43-char base64url round-trip for 32B pubkey.
  const P2pPubkey pk = make_test_pubkey(0x42U);
  const std::string encoded_pk = encode_lan_pubkey_base64url(pk);
  require(encoded_pk.size() == kLanPubkeyB64UrlLength,
          "encoded pubkey must be 43 chars");
  require(encoded_pk.find('=') == std::string::npos,
          "base64url pubkey must have no padding");
  const P2pPubkey decoded_pk =
      must(decode_lan_pubkey_base64url(encoded_pk), "decode valid pubkey");
  require(decoded_pk == pk, "decoded pubkey must match original");

  // Reject non-canonical trailing bits in 43rd base64url char.
  std::string non_canonical = encoded_pk;
  non_canonical[42] = 'B'; // value 1 -> low 2 bits non-zero
  require(!decode_lan_pubkey_base64url(non_canonical).has_value(),
          "non-canonical base64url trailing bits must fail");
  // Reject wrong length, standard base64 chars, and all-zero pubkey.
  require(!decode_lan_pubkey_base64url(encoded_pk + "=").has_value(),
          "padded pubkey must fail");
  const std::string zero_pk_b64 = encode_lan_pubkey_base64url(P2pPubkey{});
  require(!decode_lan_pubkey_base64url(zero_pk_b64).has_value(),
          "all-zero pubkey must fail");

  // 2. Valid TXT encode/decode round-trip (both pin=1 and pin=0).
  for (const bool pin_flag : {true, false}) {
    const LanBeaconRecord original = make_valid_beacon(BeaconSpec{
        .id = "0123456789abcdef",
        .lobby_name = "Quake Night 1998",
        .host_name = "player_one",
        .key_seed = 0x33U,
        .require_pin = pin_flag,
    });
    const auto wire = must(encode_lan_txt_record(original), "encode valid TXT");
    require(wire.size() <= kLanMaxTxtBytes, "TXT wire must be <= 256 B");
    const auto roundtrip = must(decode_lan_txt_record(wire), "decode valid TXT");
    require(roundtrip == original, "TXT round-trip must preserve all fields");
  }

  // Max-length valid names (32 chars each) still fit well within 256 B.
  const std::string max_lobby(32U, 'A');
  const std::string max_host(32U, 'Z');
  const LanBeaconRecord max_names = make_valid_beacon(BeaconSpec{
      .id = "fedcba9876543210",
      .lobby_name = max_lobby,
      .host_name = max_host,
      .key_seed = 0x77U,
      .require_pin = true,
  });
  const auto max_wire = must(encode_lan_txt_record(max_names), "encode max-name TXT");
  require(max_wire.size() <= kLanMaxTxtBytes,
          "max-length beacon TXT must fit <= 256 B");
  require(must(decode_lan_txt_record(max_wire), "decode max-name TXT") == max_names,
          "max-length beacon round-trip must match");

  // 3. Reject missing keys.
  const std::vector<std::string> base_entries = {
      "v=1",
      "id=a1b2c3d4e5f60708",
      "name=quake-night",
      "host=alice",
      "pk=" + encoded_pk,
      "pin=1",
      "alpn=blackbird-mp/1",
  };
  for (std::size_t skip = 0U; skip < base_entries.size(); ++skip) {
    std::vector<std::string> subset;
    for (std::size_t i = 0U; i < base_entries.size(); ++i) {
      if (i != skip) {
        subset.push_back(base_entries[i]);
      }
    }
    const auto res = decode_lan_txt_record(build_txt_wire(subset));
    require(!res.has_value(), "missing required TXT key must fail");
    require(lan_mdns_error_of(res.error()) == LanMdnsError::txt_missing_key,
            "missing key must report txt_missing_key");
  }

  // 4. Reject duplicate keys.
  {
    auto dup = base_entries;
    dup.push_back("pin=0");
    const auto res = decode_lan_txt_record(build_txt_wire(dup));
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::txt_duplicate_key,
            "duplicate TXT key must fail with txt_duplicate_key");
  }

  // 5. Reject unknown / forbidden secret/PIN keys.
  for (const char *extra :
       {"pin_hash=deadbeef", "secret=hunter2", "crit=1", "unknown=foo"}) {
    auto with_extra = base_entries;
    with_extra.emplace_back(extra);
    const auto res = decode_lan_txt_record(build_txt_wire(with_extra));
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::txt_unknown_key,
            "unknown or secret TXT key must fail closed");
  }

  // 6. Reject wrong version, wrong ALPN, bad party ID, bad pin flag.
  {
    auto bad_v = base_entries;
    bad_v[0] = "v=2";
    require(!decode_lan_txt_record(build_txt_wire(bad_v)).has_value(),
            "wrong v must fail");

    auto bad_id_upper = base_entries;
    bad_id_upper[1] = "id=A1B2C3D4E5F60708";
    require(!decode_lan_txt_record(build_txt_wire(bad_id_upper)).has_value(),
            "uppercase hex party id must fail");

    auto bad_pin = base_entries;
    bad_pin[5] = "pin=yes";
    require(!decode_lan_txt_record(build_txt_wire(bad_pin)).has_value(),
            "non-0/1 pin must fail");

    auto bad_alpn = base_entries;
    bad_alpn[6] = "alpn=other-proto/1";
    require(!decode_lan_txt_record(build_txt_wire(bad_alpn)).has_value(),
            "wrong alpn must fail");
  }

  // 7. Reject control, ANSI escape, DEL, and Unicode BiDi spoof characters.
  const std::vector<std::string> hostile_names = {
      std::string{"name=ok\x1b[31mred"}, // ANSI CSI escape
      std::string{"name=ok\nnewline"},   // LF control
      std::string{"name=ok\rreturn"},    // CR control
      std::string{"name=ok\x7f"
                  "del"}, // DEL
      std::string{"name=ok\xe2\x80\xae"
                  "spoof"}, // U+202E BiDi RLO
      std::string{"name=ok\xe2\x81\xa6"
                  "lri"},                           // U+2066 BiDi LRI
      std::string{"name=   "},                      // all spaces
      std::string{"name="} + std::string(33U, 'x'), // > 32 chars
      std::string{"name="},                         // empty
  };
  for (const auto &bad_name : hostile_names) {
    auto entries = base_entries;
    entries[2] = bad_name;
    require(!decode_lan_txt_record(build_txt_wire(entries)).has_value(),
            "hostile/invalid lobby name must be rejected");
  }

  // 8. Reject total TXT wire length > 256 B.
  {
    std::vector<std::uint8_t> oversize(kLanMaxTxtBytes + 1U, 0x41U);
    oversize[0] = 10U;
    const auto res = decode_lan_txt_record(oversize);
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::txt_too_large,
            "TXT > 256 B must fail with txt_too_large");
  }

  // 9. Reject truncated TXT entry length.
  {
    const std::vector<std::uint8_t> trunc = {10U, 'v', '=', '1'};
    require(!decode_lan_txt_record(trunc).has_value(), "truncated TXT wire must fail");
  }
}

void test_dns_wire_codec_and_fuzz_guards() {
  g_stage = "dns_wire_codec_and_fuzz_guards";

  // 1. PTR query encode/decode (QM and QU).
  for (const bool qu : {false, true}) {
    const auto query_wire = must(encode_lan_ptr_query(qu), "encode PTR query");
    const auto decoded = must(decode_lan_mdns_packet(query_wire), "decode PTR query");
    require(!decoded.is_response, "PTR query must have QR=0");
    require(decoded.questions.size() == 1U, "PTR query must have 1 question");
    require(dns_names_equal_ci(decoded.questions[0].qname, kLanMdnsServiceType),
            "PTR qname must match service type");
    require(decoded.questions[0].qtype == kDnsTypePtr, "qtype must be PTR");
    require(decoded.questions[0].qclass == kDnsClassIn, "qclass must be IN");
    require(decoded.questions[0].unicast_response == qu, "QU bit must round-trip");
  }

  // 2. Announcement encode/decode with both A (IPv4) and AAAA (IPv6) records.
  LanMdnsAnnouncement ann{};
  ann.beacon = make_valid_beacon(BeaconSpec{
      .id = "0011223344556677",
      .lobby_name = "lan-arena",
      .host_name = "bob",
      .key_seed = 0x55U,
      .require_pin = true,
  });
  ann.service_port = 51820U;
  ann.ttl_sec = 120U;
  ann.addrs = {
      P2pDirectAddr::ipv4({192U, 168U, 1U, 42U}, 51820U),
      P2pDirectAddr::ipv6(
          {0xfdU, 0x00U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U},
          51820U),
  };
  const auto ann_wire = must(encode_lan_announcement(ann), "encode announcement");
  const auto decoded_ann =
      must(decode_lan_mdns_packet(ann_wire), "decode announcement");
  require(decoded_ann.is_response, "announcement must have QR=1");
  require(decoded_ann.announcement.has_value(), "announcement must decode cleanly");
  if (decoded_ann.announcement.has_value()) {
    require(*decoded_ann.announcement == ann,
            "announcement round-trip must preserve beacon, port, A, AAAA, TTL");
  }

  // 3. Goodbye encode/decode (TTL = 0).
  const auto bye_wire = must(
      encode_lan_goodbye(ann.beacon, ann.service_port, ann.addrs), "encode goodbye");
  const auto decoded_bye = must(decode_lan_mdns_packet(bye_wire), "decode goodbye");
  require(decoded_bye.announcement.has_value(), "goodbye must decode");
  if (decoded_bye.announcement.has_value()) {
    require(decoded_bye.announcement->is_goodbye(), "goodbye TTL must be 0");
    require(decoded_bye.announcement->beacon == ann.beacon,
            "goodbye must preserve beacon identity");
  }

  // 4. Valid RFC 1035 compressed response (PTR + SRV + TXT + A using pointers).
  {
    const auto txt_wire = must(encode_lan_txt_record(ann.beacon), "encode TXT");
    std::vector<std::uint8_t> pkt = {
        0x00U, 0x00U, 0x84U, 0x00U, // id=0, QR=1 AA=1
        0x00U, 0x00U, 0x00U, 0x01U, // qd=0, an=1
        0x00U, 0x00U, 0x00U, 0x03U, // ns=0, ar=3 (SRV, TXT, A)
    };
    // Offset 12: _mp1-lan._udp.local. (22 bytes: 12..33)
    const std::size_t svc_off = pkt.size();
    pkt.insert(pkt.end(),
               {8U, '_', 'm', 'p', '1', '-', 'l', 'a', 'n', 4U, '_', 'u', 'd', 'p'});
    const std::size_t local_off = pkt.size();
    pkt.insert(pkt.end(), {5U, 'l', 'o', 'c', 'a', 'l', 0U});
    // PTR header (class IN, TTL=120, rdlen=19: [16][id][ptr->svc_off])
    pkt.insert(pkt.end(), {0U, 12U, 0U, 1U, 0U, 0U, 0U, 120U, 0U, 19U});
    const std::size_t inst_off = pkt.size();
    pkt.push_back(16U);
    for (const char ch : ann.beacon.lan_party_id) {
      pkt.push_back(static_cast<std::uint8_t>(ch));
    }
    pkt.push_back(static_cast<std::uint8_t>(0xc0U | ((svc_off >> 8U) & 0x3fU)));
    pkt.push_back(static_cast<std::uint8_t>(svc_off & 0xffU));

    // SRV: owner=ptr->inst_off, port=51820, target=[16][id][ptr->local_off]
    pkt.push_back(static_cast<std::uint8_t>(0xc0U | ((inst_off >> 8U) & 0x3fU)));
    pkt.push_back(static_cast<std::uint8_t>(inst_off & 0xffU));
    pkt.insert(pkt.end(),
               {0U, 33U, 0x80U, 1U, 0U, 0U, 0U, 120U, 0U, 25U, // rdlen = 6 + 19
                0U, 0U, 0U, 0U, 0xcaU, 0x6cU});                // port 51820
    const std::size_t host_off = pkt.size();
    pkt.push_back(16U);
    for (const char ch : ann.beacon.lan_party_id) {
      pkt.push_back(static_cast<std::uint8_t>(ch));
    }
    pkt.push_back(static_cast<std::uint8_t>(0xc0U | ((local_off >> 8U) & 0x3fU)));
    pkt.push_back(static_cast<std::uint8_t>(local_off & 0xffU));

    // TXT: owner=ptr->inst_off
    pkt.push_back(static_cast<std::uint8_t>(0xc0U | ((inst_off >> 8U) & 0x3fU)));
    pkt.push_back(static_cast<std::uint8_t>(inst_off & 0xffU));
    pkt.insert(pkt.end(), {0U, 16U, 0x80U, 1U, 0U, 0U, 0U, 120U,
                           static_cast<std::uint8_t>((txt_wire.size() >> 8U) & 0xffU),
                           static_cast<std::uint8_t>(txt_wire.size() & 0xffU)});
    pkt.insert(pkt.end(), txt_wire.begin(), txt_wire.end());

    // A: owner=ptr->host_off, IP=192.168.1.42
    pkt.push_back(static_cast<std::uint8_t>(0xc0U | ((host_off >> 8U) & 0x3fU)));
    pkt.push_back(static_cast<std::uint8_t>(host_off & 0xffU));
    pkt.insert(pkt.end(),
               {0U, 1U, 0x80U, 1U, 0U, 0U, 0U, 120U, 0U, 4U, 192U, 168U, 1U, 42U});

    const auto decoded = must(decode_lan_mdns_packet(pkt), "compressed mDNS response");
    require(decoded.announcement.has_value(),
            "compressed response must produce announcement");
    if (decoded.announcement.has_value()) {
      require(decoded.announcement->beacon == ann.beacon,
              "compressed response beacon mismatch");
      require(decoded.announcement->service_port == 51820U,
              "compressed response port mismatch");
      require(decoded.announcement->addrs.size() == 1U &&
                  decoded.announcement->addrs[0] ==
                      P2pDirectAddr::ipv4({192U, 168U, 1U, 42U}, 51820U),
              "compressed response A record mismatch");
    }
  }

  // 5. Fuzz / adversarial DNS compression attacks:
  // (a) Self-referencing pointer loop at offset 12 -> 12.
  {
    const std::vector<std::uint8_t> self_loop = {
        0U, 0U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0xc0U, 0x0cU, 0U, 12U, 0U, 1U,
    };
    const auto res = decode_lan_mdns_packet(self_loop);
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::dns_pointer_loop,
            "self-loop pointer must fail with dns_pointer_loop");
  }

  // (b) 2-node mutual pointer cycle: offset 12 -> 14, offset 14 -> 12.
  {
    const std::vector<std::uint8_t> mutual_loop = {
        0U, 0U, 0U,    0U,    0U,    1U,    0U, 0U,  0U, 0U,
        0U, 0U, 0xc0U, 0x0eU, 0xc0U, 0x0cU, 0U, 12U, 0U, 1U,
    };
    const auto res = decode_lan_mdns_packet(mutual_loop);
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::dns_pointer_loop,
            "2-node pointer loop must fail with dns_pointer_loop");
  }

  // (c) Pointer chain exceeding max jumps (> 16 jumps).
  {
    std::vector<std::uint8_t> long_chain = {
        0U, 0U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U,
    };
    // 18 pointer hops: 12->14->16->...->48 (zero terminator at 48)
    for (std::size_t hop = 0U; hop < 18U; ++hop) {
      const std::size_t target = 12U + (hop + 1U) * 2U;
      long_chain.push_back(static_cast<std::uint8_t>(0xc0U | ((target >> 8U) & 0x3fU)));
      long_chain.push_back(static_cast<std::uint8_t>(target & 0xffU));
    }
    long_chain.push_back(0U);
    long_chain.insert(long_chain.end(), {0U, 12U, 0U, 1U});
    const auto res = decode_lan_mdns_packet(long_chain);
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::dns_pointer_loop,
            "chain > 16 jumps must fail with dns_pointer_loop");
  }

  // (d) Out-of-bounds compression pointer offset.
  {
    const std::vector<std::uint8_t> oob_ptr = {
        0U, 0U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0xc0U, 0xffU, 0U, 12U, 0U, 1U,
    };
    const auto res = decode_lan_mdns_packet(oob_ptr);
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::dns_pointer_oob,
            "OOB pointer must fail with dns_pointer_oob");
  }

  // (e) Truncated packet at every prefix length of a valid announcement.
  for (std::size_t len = 0U; len < ann_wire.size(); ++len) {
    const auto res =
        decode_lan_mdns_packet(std::span<const std::uint8_t>(ann_wire.data(), len));
    require(!res.has_value(), "truncated announcement prefix must fail");
  }

  // (f) Invalid label tag prefix (0x40 / 0x80) and oversized packet (> 4096 B).
  {
    const std::vector<std::uint8_t> bad_tag = {
        0U, 0U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U, 0U, 0U, 0x40U, 'a', 0U, 0U, 12U, 0U, 1U,
    };
    require(!decode_lan_mdns_packet(bad_tag).has_value(),
            "reserved label prefix 0x40 must fail");

    std::vector<std::uint8_t> huge(kLanMdnsMaxPacketBytes + 1U, 0U);
    const auto res = decode_lan_mdns_packet(huge);
    require(!res.has_value() &&
                lan_mdns_error_of(res.error()) == LanMdnsError::dns_packet_too_large,
            "packet > 4096 B must fail");
  }
}

void test_opt_in_and_timeout_bounds() {
  g_stage = "opt_in_and_timeout_bounds";

  const int fds_before = count_open_fds();
  {
    // Construction MUST open zero sockets.
    LanMdnsAdvertiser adv;
    LanMdnsScanner scan;
    require(!adv.active() && !adv.expired(), "new advertiser must be inactive");
    require(!scan.active() && !scan.expired(), "new scanner must be inactive");
    require(count_open_fds() == fds_before,
            "constructing advertiser & scanner must open ZERO sockets");

    // Reject invalid timeout bounds, port 0, and non-multicast target when
    // enable_multicast=true, without leaking FDs.
    LanMdnsSocketConfig cfg{};
    cfg.bind_address = "127.0.0.1";
    cfg.bind_port = 0U;
    cfg.target_address = "127.0.0.1";
    cfg.target_port = 0U;
    cfg.enable_multicast = false;

    const auto beacon = make_valid_beacon();
    require(!adv.start(beacon, 0U, 300U, cfg).has_value(), "service_port 0 must fail");
    require(!adv.start(beacon, 51820U, 0U, cfg).has_value(),
            "idle_timeout_sec 0 must fail");
    require(!adv.start(beacon, 51820U, 1801U, cfg).has_value(),
            "idle_timeout_sec > 1800 must fail");

    require(!scan.start(0U, cfg).has_value(), "scan_timeout_sec 0 must fail");
    require(!scan.start(61U, cfg).has_value(), "scan_timeout_sec > 60 must fail");

    LanMdnsSocketConfig bad_mcast{};
    bad_mcast.bind_address = "127.0.0.1";
    bad_mcast.bind_port = 0U;
    bad_mcast.target_address = "127.0.0.1"; // not 224.0.0.0/4!
    bad_mcast.target_port = 5353U;
    bad_mcast.enable_multicast = true;
    require(!scan.start(15U, bad_mcast).has_value(),
            "enable_multicast with unicast target must fail closed");

    require(count_open_fds() == fds_before, "failed starts must not leak FDs");
  }
  require(count_open_fds() == fds_before, "FD count must match baseline");
}

void test_loopback_discovery_query_goodbye_and_idle_timeout() {
  g_stage = "loopback_discovery_query_goodbye_and_idle_timeout";

  const int fds_before = count_open_fds();

  // 1. Live push announcement + hostile packet resilience + goodbye + lock_lobby.
  {
    LanMdnsScanner scanner;
    LanMdnsSocketConfig scan_cfg{};
    scan_cfg.bind_address = "127.0.0.1";
    scan_cfg.bind_port = 0U;
    scan_cfg.target_address = "127.0.0.1";
    scan_cfg.target_port = 0U;
    scan_cfg.enable_multicast = false;
    must_void(scanner.start(15U, scan_cfg), "scanner start");
    require(scanner.active() && scanner.bound_port() > 0U,
            "scanner must bind ephemeral port");

    // Inject hostile self-looping DNS packet to scanner before legitimate host.
    const std::vector<std::uint8_t> hostile_loop = {
        0U, 0U, 0x84U, 0U, 0U, 0U, 0U, 1U, 0U, 0U, 0U, 0U, 0xc0U, 0x0cU,
    };
    send_raw_udp_to_loopback(scanner.bound_port(), hostile_loop);
    must_void(scanner.pump_once(50U), "scanner ignores hostile packet");
    require(scanner.lobbies().empty(), "hostile packet must not add lobby");

    const auto beacon = make_valid_beacon(BeaconSpec{
        .id = "1122334455667788",
        .lobby_name = "dojo-lan",
        .host_name = "host-alpha",
        .key_seed = 0x22U,
        .require_pin = true,
    });
    LanMdnsAdvertiser advertiser;
    LanMdnsSocketConfig adv_cfg{};
    adv_cfg.bind_address = "127.0.0.1";
    adv_cfg.bind_port = 0U;
    adv_cfg.target_address = "127.0.0.1";
    adv_cfg.target_port = scanner.bound_port();
    adv_cfg.enable_multicast = false;
    adv_cfg.advertise_addrs = {P2pDirectAddr::ipv4({192U, 168U, 50U, 10U}, 51820U)};

    must_void(advertiser.start(beacon, 51820U, 300U, adv_cfg), "advertiser start");
    require(advertiser.active() && advertiser.announcements_sent() == 1U,
            "advertiser must send initial announcement");

    // Verify move construction preserves live FD without spurious goodbye.
    LanMdnsAdvertiser moved_advertiser(std::move(advertiser));
    require(moved_advertiser.active(), "moved advertiser must stay active");

    // Pump scanner to receive initial announcement.
    for (int i = 0; i < 10 && scanner.lobbies().empty(); ++i) {
      must_void(scanner.pump_once(50U), "scanner pump initial");
    }
    const auto found = scanner.lobbies();
    require(found.size() == 1U, "scanner must discover 1 lobby");
    require(found[0].beacon == beacon, "discovered beacon must match");
    require(found[0].service_port == 51820U, "discovered port must match");
    require(found[0].addrs.size() == 1U &&
                found[0].addrs[0] ==
                    P2pDirectAddr::ipv4({192U, 168U, 50U, 10U}, 51820U),
            "discovered direct addr must match");

    // Mark peer joined so idle timeout will NOT expire while open.
    moved_advertiser.mark_peer_joined();
    const auto far_future =
        std::chrono::steady_clock::now() + std::chrono::seconds(3600);
    must_void(moved_advertiser.pump_once(0U, far_future),
              "advertiser pump after peer joined");
    require(moved_advertiser.active() && !moved_advertiser.expired(),
            "peer-joined advertiser must not idle-expire");
    require(moved_advertiser.announcements_sent() >= 2U,
            "30s refresh interval must trigger re-announcement");

    // Lock lobby: immediately sends TTL=0 goodbye and stops advertising!
    moved_advertiser.lock_lobby();
    require(!moved_advertiser.active() && moved_advertiser.locked(),
            "lock_lobby must stop advertiser");
    require(moved_advertiser.goodbyes_sent() == 1U,
            "lock_lobby must send TTL=0 goodbye");

    // Pump scanner to receive TTL=0 goodbye and remove lobby.
    for (int i = 0; i < 10 && !scanner.lobbies().empty(); ++i) {
      must_void(scanner.pump_once(50U), "scanner pump goodbye");
    }
    require(scanner.lobbies().empty(), "TTL=0 goodbye must remove lobby from scanner");

    // Idempotent stop.
    moved_advertiser.stop();
    scanner.stop();
    scanner.stop();
  }
  require(count_open_fds() == fds_before,
          "zero leaked FDs after push/goodbye/lock test");

  // 2. Pull PTR query -> advertiser response + deduplication + sorted snapshot.
  {
    LanMdnsAdvertiser adv1;
    LanMdnsSocketConfig adv1_cfg{};
    adv1_cfg.bind_address = "127.0.0.1";
    adv1_cfg.bind_port = 0U;
    adv1_cfg.target_address = "127.0.0.1";
    adv1_cfg.target_port = 0U;
    adv1_cfg.enable_multicast = false;
    adv1_cfg.advertise_addrs = {P2pDirectAddr::ipv4({10U, 0U, 0U, 5U}, 41000U)};
    const auto b1 = make_valid_beacon(BeaconSpec{
        .id = "aaaaaaaaaaaaaaaa",
        .lobby_name = "zulu-room",
        .host_name = "host1",
        .key_seed = 0x10U,
        .require_pin = false,
    });
    must_void(adv1.start(b1, 41000U, 300U, adv1_cfg), "adv1 start");

    // Unrelated PTR query (_http._tcp.local.) must be ignored by advertiser.
    const std::vector<std::uint8_t> unrelated_ptr = {
        0U,  0U,  0U,  0U,  0U,  1U,  0U, 0U,  0U,  0U,  0U,  0U,
        5U,  '_', 'h', 't', 't', 'p', 4U, '_', 't', 'c', 'p', 5U,
        'l', 'o', 'c', 'a', 'l', 0U,  0U, 12U, 0U,  1U,
    };
    send_raw_udp_to_loopback(adv1.bound_port(), unrelated_ptr);
    must_void(adv1.pump_once(50U), "adv1 ignores unrelated PTR query");
    require(adv1.queries_answered() == 0U,
            "advertiser must not answer unrelated service queries");

    LanMdnsScanner scanner;
    LanMdnsSocketConfig scan_cfg{};
    scan_cfg.bind_address = "127.0.0.1";
    scan_cfg.bind_port = 0U;
    scan_cfg.target_address = "127.0.0.1";
    scan_cfg.target_port = adv1.bound_port();
    scan_cfg.enable_multicast = false;
    must_void(scanner.start(15U, scan_cfg), "scanner start PTR pull");
    require(scanner.queries_sent() == 1U, "scanner must send initial PTR query");

    // Advertiser answers incoming PTR query.
    for (int i = 0; i < 10 && adv1.queries_answered() == 0U; ++i) {
      must_void(adv1.pump_once(50U), "adv1 pump query");
    }
    require(adv1.queries_answered() == 1U, "advertiser must answer incoming PTR query");

    // Send a duplicate query to confirm deduplication on scanner.
    must_void(scanner.send_query(), "scanner second query");
    for (int i = 0; i < 10 && adv1.queries_answered() < 2U; ++i) {
      must_void(adv1.pump_once(50U), "adv1 pump second query");
    }

    // Also start a second lobby pushing directly to scanner to verify sorting.
    LanMdnsAdvertiser adv2;
    LanMdnsSocketConfig adv2_cfg{};
    adv2_cfg.bind_address = "127.0.0.1";
    adv2_cfg.bind_port = 0U;
    adv2_cfg.target_address = "127.0.0.1";
    adv2_cfg.target_port = scanner.bound_port();
    adv2_cfg.enable_multicast = false;
    adv2_cfg.advertise_addrs = {P2pDirectAddr::ipv4({10U, 0U, 0U, 6U}, 42000U)};
    const auto b2 = make_valid_beacon(BeaconSpec{
        .id = "bbbbbbbbbbbbbbbb",
        .lobby_name = "alpha-room",
        .host_name = "host2",
        .key_seed = 0x20U,
        .require_pin = true,
    });
    must_void(adv2.start(b2, 42000U, 300U, adv2_cfg), "adv2 start");

    for (int i = 0; i < 15 && scanner.lobbies().size() < 2U; ++i) {
      must_void(scanner.pump_once(50U), "scanner collect both");
    }
    const auto sorted = scanner.lobbies();
    require(sorted.size() == 2U, "scanner must deduplicate to 2 lobbies");
    require(sorted[0].beacon.lobby_name == "alpha-room" &&
                sorted[1].beacon.lobby_name == "zulu-room",
            "lobbies() snapshot must be sorted");
  }
  require(count_open_fds() == fds_before,
          "zero leaked FDs after PTR query & dedup test");

  // 3. Idle-timeout auto-shutoff on advertiser (sends TTL=0 goodbye & closes FD).
  {
    LanMdnsScanner observer;
    LanMdnsSocketConfig obs_cfg{};
    obs_cfg.bind_address = "127.0.0.1";
    obs_cfg.bind_port = 0U;
    obs_cfg.target_address = "127.0.0.1";
    obs_cfg.target_port = 0U;
    obs_cfg.enable_multicast = false;
    must_void(observer.start(15U, obs_cfg), "observer start");

    const int fds_with_observer = count_open_fds();
    require(fds_with_observer == fds_before + 1, "observer must hold exactly 1 FD");

    LanMdnsAdvertiser adv;
    LanMdnsSocketConfig adv_cfg{};
    adv_cfg.bind_address = "127.0.0.1";
    adv_cfg.bind_port = 0U;
    adv_cfg.target_address = "127.0.0.1";
    adv_cfg.target_port = observer.bound_port();
    adv_cfg.enable_multicast = false;
    adv_cfg.advertise_addrs = {P2pDirectAddr::ipv4({192U, 168U, 1U, 7U}, 51820U)};
    must_void(adv.start(make_valid_beacon(), 51820U, 10U, adv_cfg),
              "adv start idle test");
    require(count_open_fds() == fds_with_observer + 1,
            "active advertiser must hold 1 FD");

    // Observer receives initial announcement.
    for (int i = 0; i < 10 && observer.lobbies().empty(); ++i) {
      must_void(observer.pump_once(50U), "observer receive initial");
    }
    require(observer.lobbies().size() == 1U, "observer must see initial lobby");

    // Advance clock past idle_timeout_sec (10s) with zero peers joined.
    const auto after_idle = std::chrono::steady_clock::now() + std::chrono::seconds(11);
    must_void(adv.pump_once(0U, after_idle), "adv idle timeout pump");
    require(!adv.active(), "advertiser must auto-stop on idle timeout");
    require(adv.expired(), "advertiser expired() must be true");
    require(adv.goodbyes_sent() == 1U, "idle timeout must emit TTL=0 goodbye");
    require(count_open_fds() == fds_with_observer,
            "advertiser must close its FD immediately on idle timeout");

    // Observer receives the idle-timeout goodbye and removes the lobby.
    for (int i = 0; i < 10 && !observer.lobbies().empty(); ++i) {
      must_void(observer.pump_once(50U), "observer receive idle goodbye");
    }
    require(observer.lobbies().empty(), "idle-timeout goodbye must remove lobby");

    // 4. Scan-timeout auto-shutoff on scanner (closes FD cleanly).
    const auto after_scan = std::chrono::steady_clock::now() + std::chrono::seconds(16);
    must_void(observer.pump_once(0U, after_scan), "observer scan timeout pump");
    require(!observer.active() && observer.expired(),
            "scanner must auto-stop and mark expired() on scan timeout");
    require(count_open_fds() == fds_before,
            "scanner must close its FD immediately on scan timeout");
  }
  require(count_open_fds() == fds_before,
          "zero leaked FDs after timeout auto-shutoff tests");
}

void test_direct_target_parser_and_formatter() {
  g_stage = "direct_target_parser_and_formatter";

  // Valid IPv4 targets (RFC 1918, CGNAT/Tailscale, loopback).
  {
    const auto a1 =
        must(parse_lan_direct_target("192.168.1.42:51820"), "parse RFC1918 IPv4");
    require(a1 == P2pDirectAddr::ipv4({192U, 168U, 1U, 42U}, 51820U),
            "parsed 192.168.1.42:51820 mismatch");
    require(must(format_lan_direct_target(a1), "format IPv4") == "192.168.1.42:51820",
            "formatted IPv4 mismatch");

    const auto a2 =
        must(parse_lan_direct_target("100.64.0.5:42000"), "parse CGNAT IPv4");
    require(a2 == P2pDirectAddr::ipv4({100U, 64U, 0U, 5U}, 42000U),
            "parsed 100.64.0.5:42000 mismatch");
    require(must(format_lan_direct_target(a2), "format CGNAT") == "100.64.0.5:42000",
            "formatted CGNAT mismatch");

    const auto a3 =
        must(parse_lan_direct_target("127.0.0.1:65535"), "parse loopback IPv4");
    require(a3 == P2pDirectAddr::ipv4({127U, 0U, 0U, 1U}, 65535U),
            "parsed loopback mismatch");
  }

  // Valid IPv6 targets ([ipv6]:port).
  {
    const auto v6 = must(parse_lan_direct_target("[fd00::1]:51820"), "parse ULA IPv6");
    require(v6 == P2pDirectAddr::ipv6({0xfdU, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
                                       0U, 0U, 0U, 0U, 1U},
                                      51820U),
            "parsed [fd00::1]:51820 mismatch");
    require(must(format_lan_direct_target(v6), "format IPv6") == "[fd00::1]:51820",
            "formatted [fd00::1]:51820 mismatch");

    const auto v6_lo = must(parse_lan_direct_target("[::1]:1"), "parse loopback IPv6");
    require(must(format_lan_direct_target(v6_lo), "format loopback IPv6") == "[::1]:1",
            "formatted [::1]:1 mismatch");
  }

  // Invalid / hostile targets must all fail closed.
  const std::array<std::string_view, 24> bad_targets = {
      "",
      "192.168.1.42",          // missing port
      "192.168.1.42:",         // empty port
      "192.168.1.42:0",        // port 0
      "192.168.1.42:65536",    // port overflow
      "192.168.1.42:080",      // leading zero port
      "192.168.1.42:-1",       // negative port
      "192.168.01.42:51820",   // leading zero octet
      "192.168.1.256:51820",   // octet > 255
      "192.168.1:51820",       // 3 octets
      "0.0.0.0:51820",         // unspecified IPv4
      "224.0.0.251:5353",      // multicast IPv4
      "255.255.255.255:51820", // broadcast IPv4
      "localhost:51820",       // hostname
      "myhost.local:51820",    // mDNS hostname
      " 192.168.1.42:51820",   // leading space
      "192.168.1.42:51820 ",   // trailing space
      "192.168.1.42:51820\n",  // control char
      "fd00::1:51820",         // unbracketed IPv6
      "[fd00::1]",             // IPv6 missing port
      "[fd00::1]:0",           // IPv6 port 0
      "[::]:51820",            // unspecified IPv6
      "[ff02::fb]:5353",       // multicast IPv6
      "[fe80::1%en0]:51820",   // zone ID rejected
  };
  for (const std::string_view bad : bad_targets) {
    const auto res = parse_lan_direct_target(bad);
    require(!res.has_value(), "invalid direct target must fail");
    require(lan_mdns_error_of(res.error()) == LanMdnsError::invalid_direct_target,
            "invalid direct target must report invalid_direct_target");
  }

  // Format rejects invalid P2pDirectAddr.
  require(!format_lan_direct_target(P2pDirectAddr{}).has_value(),
          "format must reject family 0 / port 0");
  require(!format_lan_direct_target(P2pDirectAddr::ipv4({192U, 168U, 1U, 1U}, 0U))
               .has_value(),
          "format must reject port 0");
  require(!format_lan_direct_target(P2pDirectAddr::ipv4({224U, 0U, 0U, 251U}, 5353U))
               .has_value(),
          "format must reject multicast IPv4");
}

void test_enumerate_lan_ipv4_addrs() {
  g_stage = "enumerate_lan_ipv4_addrs";

  // Reject port 0.
  require(!enumerate_lan_ipv4_addrs(0U).has_value(),
          "enumerate_lan_ipv4_addrs(0) must fail");

  // Port > 0 succeeds and returns only non-loopback valid IPv4 addresses.
  const auto addrs = must(enumerate_lan_ipv4_addrs(51820U), "enumerate local LAN IPv4");
  require(addrs.size() <= kP2pMaxDirectAddrs,
          "enumerated addrs must not exceed kP2pMaxDirectAddrs");
  for (const auto &addr : addrs) {
    require(addr.family == 4U, "enumerated addr must be IPv4");
    require(addr.port == 51820U, "enumerated addr port must match");
    require(addr.ip[0] != 127U && addr.ip[0] != 0U && (addr.ip[0] & 0xf0U) != 0xe0U,
            "enumerated addr must be non-loopback non-multicast");
  }
}

} // namespace

int main() {
  try {
    test_pubkey_base64url_and_txt_codec();
    test_dns_wire_codec_and_fuzz_guards();
    test_opt_in_and_timeout_bounds();
    test_loopback_discovery_query_goodbye_and_idle_timeout();
    test_direct_target_parser_and_formatter();
    test_enumerate_lan_ipv4_addrs();
    std::cout << "lan_mdns_test: all checks passed\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "lan_mdns_test FAILED: " << ex.what() << "\n";
    return 1;
  }
}
