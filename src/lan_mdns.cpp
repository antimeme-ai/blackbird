#include "blackbird/lan_mdns.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <bit>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <ifaddrs.h>
#include <limits>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>

namespace blackbird {
namespace {

constexpr std::size_t kDnsHeaderBytes = 12U;
constexpr std::size_t kMaxDatagramsPerPump = 64U;
constexpr std::size_t kMaxDirectTargetBytes = 64U;

template <typename T> Result<T> lan_fail(ErrorCode code, LanMdnsError detail) {
  return Result<T>::failure({code, static_cast<std::int64_t>(detail)});
}

Result<void> lan_fail_void(ErrorCode code, LanMdnsError detail) {
  return Result<void>::failure({code, static_cast<std::int64_t>(detail)});
}

constexpr std::uint16_t host_to_be16(std::uint16_t value) noexcept {
  if constexpr (std::endian::native == std::endian::little) {
    return std::byteswap(value);
  }
  return value;
}

constexpr std::uint16_t be16_to_host(std::uint16_t value) noexcept {
  return host_to_be16(value);
}

void append_be16(std::vector<std::uint8_t> &out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void append_be32(std::vector<std::uint8_t> &out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
  out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

std::uint16_t read_be16(std::span<const std::uint8_t> data,
                        std::size_t offset) noexcept {
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8U) |
                                    static_cast<std::uint16_t>(data[offset + 1U]));
}

std::uint32_t read_be32(std::span<const std::uint8_t> data,
                        std::size_t offset) noexcept {
  return (static_cast<std::uint32_t>(data[offset]) << 24U) |
         (static_cast<std::uint32_t>(data[offset + 1U]) << 16U) |
         (static_cast<std::uint32_t>(data[offset + 2U]) << 8U) |
         static_cast<std::uint32_t>(data[offset + 3U]);
}

constexpr char ascii_lower(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z') {
    return static_cast<char>(ch - 'A' + 'a');
  }
  return ch;
}

constexpr bool is_printable_ascii_byte(std::uint8_t byte) noexcept {
  return byte >= 0x20U && byte <= 0x7eU;
}

bool is_valid_display_text(std::string_view text) noexcept {
  if (text.size() < kLanMinDisplayTextLength ||
      text.size() > kLanMaxDisplayTextLength) {
    return false;
  }
  bool has_non_space = false;
  for (const char ch : text) {
    const auto byte = static_cast<std::uint8_t>(ch);
    if (!is_printable_ascii_byte(byte)) {
      return false;
    }
    if (byte != 0x20U) {
      has_non_space = true;
    }
  }
  return has_non_space;
}

bool is_valid_party_id_hex(std::string_view id) noexcept {
  if (id.size() != kLanPartyIdHexLength) {
    return false;
  }
  for (const char ch : id) {
    const bool is_digit = (ch >= '0' && ch <= '9');
    const bool is_lower_hex = (ch >= 'a' && ch <= 'f');
    if (!is_digit && !is_lower_hex) {
      return false;
    }
  }
  return true;
}

bool is_all_zero_pubkey(const P2pPubkey &pubkey) noexcept {
  for (const std::uint8_t byte : pubkey) {
    if (byte != 0U) {
      return false;
    }
  }
  return true;
}

std::optional<std::uint8_t> b64url_value(char ch) noexcept {
  if (ch >= 'A' && ch <= 'Z') {
    return static_cast<std::uint8_t>(ch - 'A');
  }
  if (ch >= 'a' && ch <= 'z') {
    return static_cast<std::uint8_t>(26 + (ch - 'a'));
  }
  if (ch >= '0' && ch <= '9') {
    return static_cast<std::uint8_t>(52 + (ch - '0'));
  }
  if (ch == '-') {
    return std::uint8_t{62U};
  }
  if (ch == '_') {
    return std::uint8_t{63U};
  }
  return std::nullopt;
}

bool is_allowed_ipv4_octets(std::array<std::uint8_t, 4> ip) noexcept {
  // Reject 0.0.0.0/8 (unspecified/this-network), 224.0.0.0/4 (multicast),
  // and 255.255.255.255 (limited broadcast).
  if (ip[0] == 0U) {
    return false;
  }
  if ((ip[0] & 0xf0U) == 0xe0U) {
    return false;
  }
  if (ip[0] == 255U && ip[1] == 255U && ip[2] == 255U && ip[3] == 255U) {
    return false;
  }
  return true;
}

bool is_allowed_ipv6_octets(const std::array<std::uint8_t, 16> &ip) noexcept {
  // Reject :: (unspecified) and ff00::/8 (multicast).
  if (ip[0] == 0xffU) {
    return false;
  }
  bool all_zero = true;
  for (const std::uint8_t byte : ip) {
    if (byte != 0U) {
      all_zero = false;
      break;
    }
  }
  return !all_zero;
}

bool is_allowed_direct_addr(const P2pDirectAddr &addr,
                            bool require_nonzero_port) noexcept {
  if (require_nonzero_port && addr.port == 0U) {
    return false;
  }
  if (addr.family == 4U) {
    const std::array<std::uint8_t, 4> octets = {addr.ip[0], addr.ip[1], addr.ip[2],
                                                addr.ip[3]};
    for (std::size_t i = 4U; i < 16U; ++i) {
      if (addr.ip[i] != 0U) {
        return false;
      }
    }
    return is_allowed_ipv4_octets(octets);
  }
  if (addr.family == 6U) {
    return is_allowed_ipv6_octets(addr.ip);
  }
  return false;
}

bool is_ipv4_multicast_be(std::uint32_t ipv4_be) noexcept {
  std::array<std::uint8_t, 4> octets{};
  std::memcpy(octets.data(), &ipv4_be, 4U);
  return (octets[0] & 0xf0U) == 0xe0U;
}

int lan_ipv4_priority(std::array<std::uint8_t, 4> ip) noexcept {
  // Prefer RFC 1918 private LAN and CGNAT (Tailscale/WireGuard) ahead of
  // link-local or public addresses.
  if (ip[0] == 192U && ip[1] == 168U) {
    return 0;
  }
  if (ip[0] == 10U) {
    return 1;
  }
  if (ip[0] == 172U && ip[1] >= 16U && ip[1] <= 31U) {
    return 2;
  }
  if (ip[0] == 100U && ip[1] >= 64U && ip[1] <= 127U) {
    return 3;
  }
  if (ip[0] == 169U && ip[1] == 254U) {
    return 5;
  }
  return 4;
}

Result<std::uint32_t> parse_strict_ipv4_be(std::string_view text) {
  if (text.empty() || text.size() > 15U) {
    return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  std::array<std::uint8_t, 4> octets{};
  std::size_t pos = 0U;
  for (std::size_t part = 0U; part < 4U; ++part) {
    if (pos >= text.size()) {
      return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    const std::size_t start = pos;
    std::uint32_t value = 0U;
    while (pos < text.size() && text[pos] != '.') {
      const char ch = text[pos];
      if (ch < '0' || ch > '9') {
        return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_direct_target);
      }
      value = (value * 10U) + static_cast<std::uint32_t>(ch - '0');
      if (value > 255U) {
        return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_direct_target);
      }
      ++pos;
    }
    const std::size_t digits = pos - start;
    if (digits == 0U || digits > 3U) {
      return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    // Reject leading zeros on multi-digit octets (prevents octal ambiguity).
    if (digits > 1U && text[start] == '0') {
      return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    octets[part] = static_cast<std::uint8_t>(value);
    if (part < 3U) {
      if (pos >= text.size() || text[pos] != '.') {
        return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_direct_target);
      }
      ++pos;
    }
  }
  if (pos != text.size()) {
    return lan_fail<std::uint32_t>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  std::uint32_t be = 0U;
  std::memcpy(&be, octets.data(), 4U);
  return Result<std::uint32_t>::success(be);
}

Result<std::uint16_t> parse_strict_port(std::string_view text) {
  if (text.empty() || text.size() > 5U) {
    return lan_fail<std::uint16_t>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  if (text.size() > 1U && text[0] == '0') {
    return lan_fail<std::uint16_t>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  std::uint32_t value = 0U;
  for (const char ch : text) {
    if (ch < '0' || ch > '9') {
      return lan_fail<std::uint16_t>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    value = (value * 10U) + static_cast<std::uint32_t>(ch - '0');
    if (value > 65535U) {
      return lan_fail<std::uint16_t>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
  }
  if (value == 0U) {
    return lan_fail<std::uint16_t>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  return Result<std::uint16_t>::success(static_cast<std::uint16_t>(value));
}

Result<void> encode_dns_name(std::string_view name, std::vector<std::uint8_t> &out) {
  if (name.empty() || name == ".") {
    out.push_back(0U);
    return Result<void>::success();
  }
  if (name.back() == '.') {
    name.remove_suffix(1U);
  }
  if (name.empty()) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::dns_invalid_record);
  }
  std::size_t wire_len = 0U;
  std::size_t pos = 0U;
  while (pos < name.size()) {
    const std::size_t dot = name.find('.', pos);
    const std::size_t end = (dot == std::string_view::npos) ? name.size() : dot;
    const std::size_t label_len = end - pos;
    if (label_len == 0U || label_len > kLanMdnsMaxLabelLength) {
      return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::dns_label_too_long);
    }
    wire_len += 1U + label_len;
    if (wire_len + 1U > kLanMdnsMaxNameLength) {
      return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::dns_name_too_long);
    }
    out.push_back(static_cast<std::uint8_t>(label_len));
    for (std::size_t i = pos; i < end; ++i) {
      const auto byte = static_cast<std::uint8_t>(name[i]);
      if (byte == 0U) {
        return lan_fail_void(ErrorCode::invalid_range,
                             LanMdnsError::dns_invalid_record);
      }
      out.push_back(byte);
    }
    if (dot == std::string_view::npos) {
      break;
    }
    pos = dot + 1U;
    if (pos == name.size()) {
      // Trailing double dot (empty label).
      return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::dns_invalid_record);
    }
  }
  out.push_back(0U);
  return Result<void>::success();
}

struct DecodedDnsName {
  std::string name;
  std::size_t next_offset = 0U;
};

Result<DecodedDnsName> decode_dns_name(std::span<const std::uint8_t> packet,
                                       std::size_t start_offset) {
  if (start_offset >= packet.size()) {
    return lan_fail<DecodedDnsName>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
  }

  std::string out;
  std::size_t pos = start_offset;
  std::size_t next_offset = 0U;
  bool jumped = false;
  std::size_t jumps = 0U;
  std::size_t wire_len = 0U;
  std::size_t label_steps = 0U;
  std::array<std::size_t, kLanMdnsMaxNameJumps> visited_ptr_positions{};

  while (true) {
    if (pos >= packet.size()) {
      return lan_fail<DecodedDnsName>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
    }
    if (++label_steps > 128U) {
      return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                      LanMdnsError::dns_pointer_loop);
    }

    const std::uint8_t tag = packet[pos];
    if (tag == 0U) {
      if (!jumped) {
        next_offset = pos + 1U;
      }
      if (out.empty()) {
        out = ".";
      }
      return Result<DecodedDnsName>::success(
          DecodedDnsName{std::move(out), next_offset});
    }

    const std::uint8_t prefix = tag & 0xc0U;
    if (prefix == 0xc0U) {
      if (pos + 1U >= packet.size()) {
        return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                        LanMdnsError::dns_truncated);
      }
      const std::size_t target = (static_cast<std::size_t>(tag & 0x3fU) << 8U) |
                                 static_cast<std::size_t>(packet[pos + 1U]);
      if (target >= packet.size()) {
        return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                        LanMdnsError::dns_pointer_oob);
      }
      if (target == pos) {
        return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                        LanMdnsError::dns_pointer_loop);
      }
      for (std::size_t i = 0U; i < jumps; ++i) {
        if (visited_ptr_positions[i] == pos || visited_ptr_positions[i] == target) {
          return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                          LanMdnsError::dns_pointer_loop);
        }
      }
      if (jumps >= kLanMdnsMaxNameJumps) {
        return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                        LanMdnsError::dns_pointer_loop);
      }
      visited_ptr_positions[jumps] = pos;
      ++jumps;
      if (!jumped) {
        next_offset = pos + 2U;
        jumped = true;
      }
      pos = target;
      continue;
    }

    if (prefix != 0U) {
      return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                      LanMdnsError::dns_invalid_record);
    }

    const std::size_t label_len = tag;
    if (label_len > kLanMdnsMaxLabelLength) {
      return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                      LanMdnsError::dns_label_too_long);
    }
    if (pos + 1U + label_len > packet.size()) {
      return lan_fail<DecodedDnsName>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
    }
    wire_len += 1U + label_len;
    if (wire_len + 1U > kLanMdnsMaxNameLength) {
      return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                      LanMdnsError::dns_name_too_long);
    }
    for (std::size_t i = 0U; i < label_len; ++i) {
      const std::uint8_t byte = packet[pos + 1U + i];
      if (byte == 0U) {
        return lan_fail<DecodedDnsName>(ErrorCode::corrupt,
                                        LanMdnsError::dns_invalid_record);
      }
      out.push_back(static_cast<char>(byte));
    }
    out.push_back('.');
    pos += 1U + label_len;
  }
}

std::optional<std::string>
extract_party_id_from_instance_name(std::string_view instance_name) {
  // Expected: <16-hex>._mp1-lan._udp.local.
  const std::size_t expected_len =
      kLanPartyIdHexLength + 1U + kLanMdnsServiceType.size();
  if (instance_name.size() != expected_len) {
    return std::nullopt;
  }
  if (instance_name[kLanPartyIdHexLength] != '.') {
    return std::nullopt;
  }
  if (!dns_names_equal_ci(instance_name.substr(kLanPartyIdHexLength + 1U),
                          kLanMdnsServiceType)) {
    return std::nullopt;
  }
  std::string lowered;
  lowered.reserve(kLanPartyIdHexLength);
  for (std::size_t i = 0U; i < kLanPartyIdHexLength; ++i) {
    lowered.push_back(ascii_lower(instance_name[i]));
  }
  if (!is_valid_party_id_hex(lowered)) {
    return std::nullopt;
  }
  return lowered;
}

class ScopedFd {
public:
  ScopedFd() noexcept = default;
  explicit ScopedFd(int fd) noexcept : fd_(fd) {}
  ScopedFd(const ScopedFd &) = delete;
  ScopedFd &operator=(const ScopedFd &) = delete;
  ~ScopedFd() noexcept { reset(); }

  int get() const noexcept { return fd_; }
  int release() noexcept { return std::exchange(fd_, -1); }
  void reset() noexcept {
    if (fd_ >= 0) {
      (void)::close(fd_);
      fd_ = -1;
    }
  }

private:
  int fd_ = -1;
};

struct OpenedUdpSocket {
  int fd = -1;
  std::uint16_t bound_port = 0U;
  std::uint32_t target_ipv4_be = 0U;
  std::uint16_t target_port = 0U;
  bool has_target = false;
  bool enable_multicast = true;
};

Result<OpenedUdpSocket> open_lan_mdns_socket(const LanMdnsSocketConfig &cfg) {
  std::uint32_t bind_ipv4_be = 0U;
  if (!cfg.bind_address.empty()) {
    const auto parsed_bind = parse_strict_ipv4_be(cfg.bind_address);
    if (!parsed_bind.has_value()) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_socket_config);
    }
    bind_ipv4_be = parsed_bind.value();
  }

  std::uint32_t target_ipv4_be = 0U;
  bool has_target = false;
  if (cfg.enable_multicast) {
    if (cfg.target_port == 0U || cfg.target_address.empty()) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_socket_config);
    }
    const auto parsed_target = parse_strict_ipv4_be(cfg.target_address);
    if (!parsed_target.has_value() || !is_ipv4_multicast_be(parsed_target.value())) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_socket_config);
    }
    target_ipv4_be = parsed_target.value();
    has_target = true;
  } else if (cfg.target_port > 0U) {
    if (cfg.target_address.empty()) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_socket_config);
    }
    const auto parsed_target = parse_strict_ipv4_be(cfg.target_address);
    if (!parsed_target.has_value()) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_socket_config);
    }
    target_ipv4_be = parsed_target.value();
    has_target = true;
  }

  ScopedFd sock(::socket(AF_INET, SOCK_DGRAM, 0));
  if (sock.get() < 0) {
    return lan_fail<OpenedUdpSocket>(ErrorCode::io, LanMdnsError::socket_open_failed);
  }

  const int fd_flags = ::fcntl(sock.get(), F_GETFD, 0);
  if (fd_flags < 0 || ::fcntl(sock.get(), F_SETFD, fd_flags | FD_CLOEXEC) < 0) {
    return lan_fail<OpenedUdpSocket>(ErrorCode::io, LanMdnsError::socket_config_failed);
  }

  const int fl_flags = ::fcntl(sock.get(), F_GETFL, 0);
  if (fl_flags < 0 || ::fcntl(sock.get(), F_SETFL, fl_flags | O_NONBLOCK) < 0) {
    return lan_fail<OpenedUdpSocket>(ErrorCode::io, LanMdnsError::socket_config_failed);
  }

  const int one = 1;
  if (::setsockopt(sock.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
    return lan_fail<OpenedUdpSocket>(ErrorCode::io, LanMdnsError::socket_config_failed);
  }

#ifdef SO_REUSEPORT
  if (cfg.enable_multicast) {
    if (::setsockopt(sock.get(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) != 0) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::io,
                                       LanMdnsError::socket_config_failed);
    }
  }
#endif

  sockaddr_in bind_sa{};
  bind_sa.sin_family = AF_INET;
  bind_sa.sin_addr.s_addr = static_cast<in_addr_t>(bind_ipv4_be);
  bind_sa.sin_port = static_cast<in_port_t>(host_to_be16(cfg.bind_port));

  if (::bind(sock.get(), reinterpret_cast<const sockaddr *>(&bind_sa),
             sizeof(bind_sa)) != 0) {
    return lan_fail<OpenedUdpSocket>(ErrorCode::io, LanMdnsError::socket_bind_failed);
  }

  sockaddr_in actual_sa{};
  socklen_t actual_len = sizeof(actual_sa);
  if (::getsockname(sock.get(), reinterpret_cast<sockaddr *>(&actual_sa),
                    &actual_len) != 0) {
    return lan_fail<OpenedUdpSocket>(ErrorCode::io, LanMdnsError::socket_config_failed);
  }
  const std::uint16_t bound_port =
      be16_to_host(static_cast<std::uint16_t>(actual_sa.sin_port));

  if (cfg.enable_multicast) {
    const unsigned char mcast_ttl = 255U;
    if (::setsockopt(sock.get(), IPPROTO_IP, IP_MULTICAST_TTL, &mcast_ttl,
                     sizeof(mcast_ttl)) != 0) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::io,
                                       LanMdnsError::socket_config_failed);
    }
    const unsigned char mcast_loop = 1U;
    if (::setsockopt(sock.get(), IPPROTO_IP, IP_MULTICAST_LOOP, &mcast_loop,
                     sizeof(mcast_loop)) != 0) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::io,
                                       LanMdnsError::socket_config_failed);
    }
    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = static_cast<in_addr_t>(target_ipv4_be);
    mreq.imr_interface.s_addr = static_cast<in_addr_t>(bind_ipv4_be);
    if (::setsockopt(sock.get(), IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) !=
        0) {
      return lan_fail<OpenedUdpSocket>(ErrorCode::io,
                                       LanMdnsError::socket_config_failed);
    }
  }

  return Result<OpenedUdpSocket>::success(OpenedUdpSocket{
      sock.release(),
      bound_port,
      target_ipv4_be,
      cfg.target_port,
      has_target,
      cfg.enable_multicast,
  });
}

struct Ipv4UdpEndpoint {
  std::uint32_t ipv4_be = 0U;
  std::uint16_t port = 0U;
};

bool send_udp_datagram_noexcept(int fd, Ipv4UdpEndpoint endpoint,
                                std::span<const std::uint8_t> payload) noexcept {
  if (fd < 0 || endpoint.port == 0U || payload.empty()) {
    return false;
  }
  sockaddr_in dest{};
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = static_cast<in_addr_t>(endpoint.ipv4_be);
  dest.sin_port = static_cast<in_port_t>(host_to_be16(endpoint.port));
  while (true) {
    const ssize_t sent =
        ::sendto(fd, payload.data(), payload.size(), 0,
                 reinterpret_cast<const sockaddr *>(&dest), sizeof(dest));
    if (sent >= 0 && static_cast<std::size_t>(sent) == payload.size()) {
      return true;
    }
    if (sent < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
}

void poll_socket_readable(int fd, std::chrono::milliseconds timeout) noexcept {
  if (fd < 0 || timeout.count() <= 0) {
    return;
  }
  const int capped_ms = timeout.count() > std::numeric_limits<int>::max()
                            ? std::numeric_limits<int>::max()
                            : static_cast<int>(timeout.count());
  pollfd pfd{};
  pfd.fd = fd;
  pfd.events = POLLIN;
  while (true) {
    const int rc = ::poll(&pfd, 1U, capped_ms);
    if (rc < 0 && errno == EINTR) {
      continue;
    }
    break;
  }
}

void deduplicate_addrs(std::vector<P2pDirectAddr> &addrs) {
  std::vector<P2pDirectAddr> unique;
  unique.reserve(std::min(addrs.size(), kP2pMaxDirectAddrs));
  for (const auto &addr : addrs) {
    if (unique.size() >= kP2pMaxDirectAddrs) {
      break;
    }
    if (std::find(unique.begin(), unique.end(), addr) == unique.end()) {
      unique.push_back(addr);
    }
  }
  addrs = std::move(unique);
}

} // namespace

// ---------------------------------------------------------------------------
// Error names
// ---------------------------------------------------------------------------

std::string_view lan_mdns_error_name(LanMdnsError detail) noexcept {
  switch (detail) {
  case LanMdnsError::none:
    return "none";
  case LanMdnsError::invalid_version:
    return "invalid_version";
  case LanMdnsError::invalid_party_id:
    return "invalid_party_id";
  case LanMdnsError::invalid_lobby_name:
    return "invalid_lobby_name";
  case LanMdnsError::invalid_host_name:
    return "invalid_host_name";
  case LanMdnsError::invalid_pubkey:
    return "invalid_pubkey";
  case LanMdnsError::invalid_pin_flag:
    return "invalid_pin_flag";
  case LanMdnsError::invalid_alpn:
    return "invalid_alpn";
  case LanMdnsError::txt_too_large:
    return "txt_too_large";
  case LanMdnsError::txt_malformed:
    return "txt_malformed";
  case LanMdnsError::txt_duplicate_key:
    return "txt_duplicate_key";
  case LanMdnsError::txt_missing_key:
    return "txt_missing_key";
  case LanMdnsError::txt_unknown_key:
    return "txt_unknown_key";
  case LanMdnsError::dns_truncated:
    return "dns_truncated";
  case LanMdnsError::dns_malformed_header:
    return "dns_malformed_header";
  case LanMdnsError::dns_name_too_long:
    return "dns_name_too_long";
  case LanMdnsError::dns_label_too_long:
    return "dns_label_too_long";
  case LanMdnsError::dns_pointer_loop:
    return "dns_pointer_loop";
  case LanMdnsError::dns_pointer_oob:
    return "dns_pointer_oob";
  case LanMdnsError::dns_invalid_record:
    return "dns_invalid_record";
  case LanMdnsError::dns_packet_too_large:
    return "dns_packet_too_large";
  case LanMdnsError::invalid_timeout:
    return "invalid_timeout";
  case LanMdnsError::invalid_port:
    return "invalid_port";
  case LanMdnsError::invalid_socket_config:
    return "invalid_socket_config";
  case LanMdnsError::socket_open_failed:
    return "socket_open_failed";
  case LanMdnsError::socket_config_failed:
    return "socket_config_failed";
  case LanMdnsError::socket_bind_failed:
    return "socket_bind_failed";
  case LanMdnsError::socket_io_failed:
    return "socket_io_failed";
  case LanMdnsError::already_running:
    return "already_running";
  case LanMdnsError::not_running:
    return "not_running";
  case LanMdnsError::invalid_direct_target:
    return "invalid_direct_target";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// 1. Strict LanBeaconRecord & TXT Codec
// ---------------------------------------------------------------------------

std::string encode_lan_pubkey_base64url(const P2pPubkey &pubkey) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(kLanPubkeyB64UrlLength);
  std::size_t i = 0U;
  while (i + 3U <= pubkey.size()) {
    const std::uint32_t triple = (static_cast<std::uint32_t>(pubkey[i]) << 16U) |
                                 (static_cast<std::uint32_t>(pubkey[i + 1U]) << 8U) |
                                 static_cast<std::uint32_t>(pubkey[i + 2U]);
    out.push_back(kAlphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 12U) & 0x3fU]);
    out.push_back(kAlphabet[(triple >> 6U) & 0x3fU]);
    out.push_back(kAlphabet[triple & 0x3fU]);
    i += 3U;
  }
  // 32 % 3 == 2 remaining bytes -> 3 base64url chars (18 bits; bottom 2 bits = 0).
  const std::uint32_t rem = (static_cast<std::uint32_t>(pubkey[30]) << 16U) |
                            (static_cast<std::uint32_t>(pubkey[31]) << 8U);
  out.push_back(kAlphabet[(rem >> 18U) & 0x3fU]);
  out.push_back(kAlphabet[(rem >> 12U) & 0x3fU]);
  out.push_back(kAlphabet[(rem >> 6U) & 0x3fU]);
  return out;
}

Result<P2pPubkey> decode_lan_pubkey_base64url(std::string_view encoded) {
  if (encoded.size() != kLanPubkeyB64UrlLength) {
    return lan_fail<P2pPubkey>(ErrorCode::invalid_range, LanMdnsError::invalid_pubkey);
  }
  P2pPubkey out{};
  std::size_t out_pos = 0U;
  for (std::size_t i = 0U; i < 40U; i += 4U) {
    const auto v0 = b64url_value(encoded[i]);
    const auto v1 = b64url_value(encoded[i + 1U]);
    const auto v2 = b64url_value(encoded[i + 2U]);
    const auto v3 = b64url_value(encoded[i + 3U]);
    if (!v0.has_value() || !v1.has_value() || !v2.has_value() || !v3.has_value()) {
      return lan_fail<P2pPubkey>(ErrorCode::invalid_range,
                                 LanMdnsError::invalid_pubkey);
    }
    const std::uint32_t triple = (static_cast<std::uint32_t>(*v0) << 18U) |
                                 (static_cast<std::uint32_t>(*v1) << 12U) |
                                 (static_cast<std::uint32_t>(*v2) << 6U) |
                                 static_cast<std::uint32_t>(*v3);
    out[out_pos++] = static_cast<std::uint8_t>((triple >> 16U) & 0xffU);
    out[out_pos++] = static_cast<std::uint8_t>((triple >> 8U) & 0xffU);
    out[out_pos++] = static_cast<std::uint8_t>(triple & 0xffU);
  }
  const auto r0 = b64url_value(encoded[40]);
  const auto r1 = b64url_value(encoded[41]);
  const auto r2 = b64url_value(encoded[42]);
  if (!r0.has_value() || !r1.has_value() || !r2.has_value()) {
    return lan_fail<P2pPubkey>(ErrorCode::invalid_range, LanMdnsError::invalid_pubkey);
  }
  // Canonical RFC 4648 check: trailing 2 unused bits must be zero.
  if ((*r2 & 0x03U) != 0U) {
    return lan_fail<P2pPubkey>(ErrorCode::invalid_range, LanMdnsError::invalid_pubkey);
  }
  const std::uint32_t tail = (static_cast<std::uint32_t>(*r0) << 12U) |
                             (static_cast<std::uint32_t>(*r1) << 6U) |
                             static_cast<std::uint32_t>(*r2);
  out[30] = static_cast<std::uint8_t>((tail >> 10U) & 0xffU);
  out[31] = static_cast<std::uint8_t>((tail >> 2U) & 0xffU);

  if (is_all_zero_pubkey(out)) {
    return lan_fail<P2pPubkey>(ErrorCode::invalid_range, LanMdnsError::invalid_pubkey);
  }
  return Result<P2pPubkey>::success(out);
}

Result<void> validate_lan_beacon_record(const LanBeaconRecord &beacon) {
  if (beacon.version != kLanBeaconVersion) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_version);
  }
  if (!is_valid_party_id_hex(beacon.lan_party_id)) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_party_id);
  }
  if (!is_valid_display_text(beacon.lobby_name)) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_lobby_name);
  }
  if (!is_valid_display_text(beacon.host_name)) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_host_name);
  }
  if (is_all_zero_pubkey(beacon.host_pubkey)) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_pubkey);
  }
  if (beacon.alpn != kP2pAlpn) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_alpn);
  }
  return Result<void>::success();
}

Result<std::vector<std::uint8_t>> encode_lan_txt_record(const LanBeaconRecord &beacon) {
  const auto valid = validate_lan_beacon_record(beacon);
  if (!valid.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(valid.error());
  }

  const std::array<std::string, 7> entries = {
      std::string{"v=1"},
      std::string{"id="} + beacon.lan_party_id,
      std::string{"name="} + beacon.lobby_name,
      std::string{"host="} + beacon.host_name,
      std::string{"pk="} + encode_lan_pubkey_base64url(beacon.host_pubkey),
      std::string{"pin="} + (beacon.require_pin ? "1" : "0"),
      std::string{"alpn="} + beacon.alpn,
  };

  std::vector<std::uint8_t> out;
  out.reserve(kLanMaxTxtBytes);
  for (const auto &entry : entries) {
    if (entry.empty() || entry.size() > 255U ||
        out.size() + 1U + entry.size() > kLanMaxTxtBytes) {
      return lan_fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                                 LanMdnsError::txt_too_large);
    }
    out.push_back(static_cast<std::uint8_t>(entry.size()));
    for (const char ch : entry) {
      out.push_back(static_cast<std::uint8_t>(ch));
    }
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

Result<LanBeaconRecord> decode_lan_txt_record(std::span<const std::uint8_t> wire) {
  if (wire.size() > kLanMaxTxtBytes) {
    return lan_fail<LanBeaconRecord>(ErrorCode::capacity, LanMdnsError::txt_too_large);
  }
  if (wire.empty()) {
    return lan_fail<LanBeaconRecord>(ErrorCode::corrupt, LanMdnsError::txt_malformed);
  }

  bool seen_v = false;
  bool seen_id = false;
  bool seen_name = false;
  bool seen_host = false;
  bool seen_pk = false;
  bool seen_pin = false;
  bool seen_alpn = false;

  LanBeaconRecord record{};
  record.version = 0U;
  record.alpn.clear();

  std::size_t offset = 0U;
  while (offset < wire.size()) {
    const std::size_t entry_len = wire[offset];
    ++offset;
    if (entry_len == 0U || offset + entry_len > wire.size()) {
      return lan_fail<LanBeaconRecord>(ErrorCode::corrupt, LanMdnsError::txt_malformed);
    }
    // Reject all control characters, ANSI escapes (0x1B/0x9B), DEL (0x7F),
    // and non-ASCII/BiDi bytes (>= 0x80) across the entire TXT entry.
    for (std::size_t i = 0U; i < entry_len; ++i) {
      if (!is_printable_ascii_byte(wire[offset + i])) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_malformed);
      }
    }
    const std::string_view entry(reinterpret_cast<const char *>(wire.data() + offset),
                                 entry_len);
    offset += entry_len;

    const std::size_t eq = entry.find('=');
    if (eq == std::string_view::npos || eq == 0U) {
      return lan_fail<LanBeaconRecord>(ErrorCode::corrupt, LanMdnsError::txt_malformed);
    }
    const std::string_view key = entry.substr(0U, eq);
    const std::string_view val = entry.substr(eq + 1U);

    if (key == "v") {
      if (seen_v) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      if (val != "1") {
        return lan_fail<LanBeaconRecord>(ErrorCode::invalid_range,
                                         LanMdnsError::invalid_version);
      }
      seen_v = true;
      record.version = kLanBeaconVersion;
    } else if (key == "id") {
      if (seen_id) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      if (!is_valid_party_id_hex(val)) {
        return lan_fail<LanBeaconRecord>(ErrorCode::invalid_range,
                                         LanMdnsError::invalid_party_id);
      }
      seen_id = true;
      record.lan_party_id.assign(val);
    } else if (key == "name") {
      if (seen_name) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      if (!is_valid_display_text(val)) {
        return lan_fail<LanBeaconRecord>(ErrorCode::invalid_range,
                                         LanMdnsError::invalid_lobby_name);
      }
      seen_name = true;
      record.lobby_name.assign(val);
    } else if (key == "host") {
      if (seen_host) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      if (!is_valid_display_text(val)) {
        return lan_fail<LanBeaconRecord>(ErrorCode::invalid_range,
                                         LanMdnsError::invalid_host_name);
      }
      seen_host = true;
      record.host_name.assign(val);
    } else if (key == "pk") {
      if (seen_pk) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      const auto decoded_pk = decode_lan_pubkey_base64url(val);
      if (!decoded_pk.has_value()) {
        return Result<LanBeaconRecord>::failure(decoded_pk.error());
      }
      seen_pk = true;
      record.host_pubkey = decoded_pk.value();
    } else if (key == "pin") {
      if (seen_pin) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      if (val == "0") {
        record.require_pin = false;
      } else if (val == "1") {
        record.require_pin = true;
      } else {
        return lan_fail<LanBeaconRecord>(ErrorCode::invalid_range,
                                         LanMdnsError::invalid_pin_flag);
      }
      seen_pin = true;
    } else if (key == "alpn") {
      if (seen_alpn) {
        return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                         LanMdnsError::txt_duplicate_key);
      }
      if (val != kP2pAlpn) {
        return lan_fail<LanBeaconRecord>(ErrorCode::invalid_range,
                                         LanMdnsError::invalid_alpn);
      }
      seen_alpn = true;
      record.alpn.assign(val);
    } else {
      // Fail closed on any unknown key (prevents secret/PIN leakage and
      // rejects unknown-critical extensions).
      return lan_fail<LanBeaconRecord>(ErrorCode::corrupt,
                                       LanMdnsError::txt_unknown_key);
    }
  }

  if (!seen_v || !seen_id || !seen_name || !seen_host || !seen_pk || !seen_pin ||
      !seen_alpn) {
    return lan_fail<LanBeaconRecord>(ErrorCode::corrupt, LanMdnsError::txt_missing_key);
  }
  return Result<LanBeaconRecord>::success(std::move(record));
}

// ---------------------------------------------------------------------------
// 2. Zero-Dep RFC 6762 / 6763 DNS/mDNS Wire Packet Codec
// ---------------------------------------------------------------------------

bool dns_names_equal_ci(std::string_view lhs, std::string_view rhs) noexcept {
  if (lhs.size() != rhs.size()) {
    return false;
  }
  for (std::size_t i = 0U; i < lhs.size(); ++i) {
    if (ascii_lower(lhs[i]) != ascii_lower(rhs[i])) {
      return false;
    }
  }
  return true;
}

Result<std::vector<std::uint8_t>> encode_lan_ptr_query(bool unicast_response) {
  std::vector<std::uint8_t> out;
  out.reserve(64U);
  // Header: ID=0, Flags=0 (standard query), QDCOUNT=1, AN/NS/AR=0.
  append_be16(out, 0U);
  append_be16(out, 0U);
  append_be16(out, 1U);
  append_be16(out, 0U);
  append_be16(out, 0U);
  append_be16(out, 0U);

  const auto name_res = encode_dns_name(kLanMdnsServiceType, out);
  if (!name_res.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(name_res.error());
  }
  append_be16(out, kDnsTypePtr);
  const std::uint16_t qclass =
      unicast_response
          ? static_cast<std::uint16_t>(kDnsClassIn | kDnsClassUnicastOrFlushBit)
          : kDnsClassIn;
  append_be16(out, qclass);
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

Result<std::vector<std::uint8_t>>
encode_lan_announcement(const LanMdnsAnnouncement &announcement) {
  if (announcement.service_port == 0U) {
    return lan_fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                               LanMdnsError::invalid_port);
  }
  if (announcement.addrs.size() > kP2pMaxDirectAddrs) {
    return lan_fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                               LanMdnsError::dns_invalid_record);
  }
  for (const auto &addr : announcement.addrs) {
    if (!is_allowed_direct_addr(addr, false)) {
      return lan_fail<std::vector<std::uint8_t>>(ErrorCode::invalid_range,
                                                 LanMdnsError::dns_invalid_record);
    }
  }

  const auto txt_res = encode_lan_txt_record(announcement.beacon);
  if (!txt_res.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(txt_res.error());
  }
  const auto &txt_wire = txt_res.value();

  const std::string instance_name =
      announcement.beacon.lan_party_id + "." + std::string{kLanMdnsServiceType};
  const std::string host_target =
      announcement.beacon.lan_party_id + std::string{kLanMdnsLocalDomain};

  std::vector<std::uint8_t> instance_wire;
  const auto inst_enc = encode_dns_name(instance_name, instance_wire);
  if (!inst_enc.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(inst_enc.error());
  }
  std::vector<std::uint8_t> target_wire;
  const auto tgt_enc = encode_dns_name(host_target, target_wire);
  if (!tgt_enc.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(tgt_enc.error());
  }

  const std::uint16_t arcount =
      static_cast<std::uint16_t>(2U + announcement.addrs.size());
  const std::uint16_t unique_class =
      static_cast<std::uint16_t>(kDnsClassIn | kDnsClassUnicastOrFlushBit);

  std::vector<std::uint8_t> out;
  out.reserve(512U);
  // Header: ID=0, Flags=0x8400 (QR=1, AA=1), QD=0, AN=1 (PTR), NS=0, AR=2+addrs.
  append_be16(out, 0U);
  append_be16(out, 0x8400U);
  append_be16(out, 0U);
  append_be16(out, 1U);
  append_be16(out, 0U);
  append_be16(out, arcount);

  // Answer 1: PTR _mp1-lan._udp.local. -> <id>._mp1-lan._udp.local. (shared)
  const auto svc_enc = encode_dns_name(kLanMdnsServiceType, out);
  if (!svc_enc.has_value()) {
    return Result<std::vector<std::uint8_t>>::failure(svc_enc.error());
  }
  append_be16(out, kDnsTypePtr);
  append_be16(out, kDnsClassIn);
  append_be32(out, announcement.ttl_sec);
  append_be16(out, static_cast<std::uint16_t>(instance_wire.size()));
  out.insert(out.end(), instance_wire.begin(), instance_wire.end());

  // Additional 1: SRV <id>._mp1-lan._udp.local. -> port, <id>.local.
  out.insert(out.end(), instance_wire.begin(), instance_wire.end());
  append_be16(out, kDnsTypeSrv);
  append_be16(out, unique_class);
  append_be32(out, announcement.ttl_sec);
  append_be16(out, static_cast<std::uint16_t>(6U + target_wire.size()));
  append_be16(out, 0U); // priority
  append_be16(out, 0U); // weight
  append_be16(out, announcement.service_port);
  out.insert(out.end(), target_wire.begin(), target_wire.end());

  // Additional 2: TXT <id>._mp1-lan._udp.local.
  out.insert(out.end(), instance_wire.begin(), instance_wire.end());
  append_be16(out, kDnsTypeTxt);
  append_be16(out, unique_class);
  append_be32(out, announcement.ttl_sec);
  append_be16(out, static_cast<std::uint16_t>(txt_wire.size()));
  out.insert(out.end(), txt_wire.begin(), txt_wire.end());

  // Additional 3+: A / AAAA <id>.local.
  for (const auto &addr : announcement.addrs) {
    out.insert(out.end(), target_wire.begin(), target_wire.end());
    if (addr.family == 4U) {
      append_be16(out, kDnsTypeA);
      append_be16(out, unique_class);
      append_be32(out, announcement.ttl_sec);
      append_be16(out, 4U);
      out.insert(out.end(), addr.ip.begin(), addr.ip.begin() + 4);
    } else {
      append_be16(out, kDnsTypeAaaa);
      append_be16(out, unique_class);
      append_be32(out, announcement.ttl_sec);
      append_be16(out, 16U);
      out.insert(out.end(), addr.ip.begin(), addr.ip.end());
    }
  }

  if (out.size() > kLanMdnsMaxPacketBytes) {
    return lan_fail<std::vector<std::uint8_t>>(ErrorCode::capacity,
                                               LanMdnsError::dns_packet_too_large);
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(out));
}

Result<std::vector<std::uint8_t>>
encode_lan_goodbye(const LanBeaconRecord &beacon, LanServicePort service_port,
                   std::span<const P2pDirectAddr> addrs) {
  LanMdnsAnnouncement goodbye{};
  goodbye.beacon = beacon;
  goodbye.service_port = service_port.value;
  goodbye.addrs.assign(addrs.begin(), addrs.end());
  goodbye.ttl_sec = 0U;
  return encode_lan_announcement(goodbye);
}

Result<LanMdnsPacket> decode_lan_mdns_packet(std::span<const std::uint8_t> packet) {
  if (packet.size() > kLanMdnsMaxPacketBytes) {
    return lan_fail<LanMdnsPacket>(ErrorCode::capacity,
                                   LanMdnsError::dns_packet_too_large);
  }
  if (packet.size() < kDnsHeaderBytes) {
    return lan_fail<LanMdnsPacket>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
  }

  const std::uint16_t tx_id = read_be16(packet, 0U);
  const std::uint16_t flags = read_be16(packet, 2U);
  const std::uint16_t qdcount = read_be16(packet, 4U);
  const std::uint16_t ancount = read_be16(packet, 6U);
  const std::uint16_t nscount = read_be16(packet, 8U);
  const std::uint16_t arcount = read_be16(packet, 10U);

  const bool is_response = (flags & 0x8000U) != 0U;
  const std::uint16_t opcode = static_cast<std::uint16_t>((flags >> 11U) & 0x0fU);
  const std::uint16_t rcode = static_cast<std::uint16_t>(flags & 0x0fU);
  if (opcode != 0U || rcode != 0U) {
    return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                   LanMdnsError::dns_malformed_header);
  }

  const std::size_t total_rr =
      static_cast<std::size_t>(qdcount) + static_cast<std::size_t>(ancount) +
      static_cast<std::size_t>(nscount) + static_cast<std::size_t>(arcount);
  if (total_rr > kLanMdnsMaxRecordsPerPacket) {
    return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                   LanMdnsError::dns_malformed_header);
  }

  LanMdnsPacket result{};
  result.transaction_id = tx_id;
  result.is_response = is_response;
  result.questions.reserve(qdcount);

  std::size_t offset = kDnsHeaderBytes;
  for (std::uint16_t i = 0U; i < qdcount; ++i) {
    const auto qname_res = decode_dns_name(packet, offset);
    if (!qname_res.has_value()) {
      return Result<LanMdnsPacket>::failure(qname_res.error());
    }
    offset = qname_res.value().next_offset;
    if (offset + 4U > packet.size()) {
      return lan_fail<LanMdnsPacket>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
    }
    const std::uint16_t qtype = read_be16(packet, offset);
    const std::uint16_t raw_qclass = read_be16(packet, offset + 2U);
    offset += 4U;

    LanMdnsQuestion q{};
    q.qname = qname_res.value().name;
    q.qtype = qtype;
    q.qclass = static_cast<std::uint16_t>(raw_qclass & kDnsClassMask);
    q.unicast_response = (raw_qclass & kDnsClassUnicastOrFlushBit) != 0U;
    result.questions.push_back(std::move(q));
  }

  struct RawPtr {
    std::string target;
    std::uint32_t ttl = 0U;
  };
  struct RawSrv {
    std::string owner;
    std::uint16_t port = 0U;
    std::string target;
    std::uint32_t ttl = 0U;
  };
  struct RawTxt {
    std::string owner;
    std::span<const std::uint8_t> rdata;
    std::uint32_t ttl = 0U;
  };
  struct RawAddr {
    std::string owner;
    P2pDirectAddr addr{};
    std::uint32_t ttl = 0U;
  };

  std::vector<RawPtr> ptrs;
  std::vector<RawSrv> srvs;
  std::vector<RawTxt> txts;
  std::vector<RawAddr> addrs;

  const std::size_t rr_count = static_cast<std::size_t>(ancount) +
                               static_cast<std::size_t>(nscount) +
                               static_cast<std::size_t>(arcount);
  for (std::size_t i = 0U; i < rr_count; ++i) {
    const auto owner_res = decode_dns_name(packet, offset);
    if (!owner_res.has_value()) {
      return Result<LanMdnsPacket>::failure(owner_res.error());
    }
    offset = owner_res.value().next_offset;
    if (offset + 10U > packet.size()) {
      return lan_fail<LanMdnsPacket>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
    }
    const std::uint16_t rtype = read_be16(packet, offset);
    const std::uint16_t raw_rclass = read_be16(packet, offset + 2U);
    const std::uint32_t ttl = read_be32(packet, offset + 4U);
    const std::uint16_t rdlength = read_be16(packet, offset + 8U);
    offset += 10U;

    if (offset + rdlength > packet.size()) {
      return lan_fail<LanMdnsPacket>(ErrorCode::corrupt, LanMdnsError::dns_truncated);
    }
    const std::size_t rdata_start = offset;
    const std::size_t rdata_end = offset + rdlength;
    const std::uint16_t rclass = static_cast<std::uint16_t>(raw_rclass & kDnsClassMask);

    if (rclass == kDnsClassIn) {
      if (rtype == kDnsTypePtr) {
        const auto ptr_name = decode_dns_name(packet, rdata_start);
        if (!ptr_name.has_value()) {
          return Result<LanMdnsPacket>::failure(ptr_name.error());
        }
        if (ptr_name.value().next_offset != rdata_end) {
          return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                         LanMdnsError::dns_invalid_record);
        }
        if (dns_names_equal_ci(owner_res.value().name, kLanMdnsServiceType)) {
          ptrs.push_back(RawPtr{ptr_name.value().name, ttl});
        }
      } else if (rtype == kDnsTypeSrv) {
        if (rdlength < 7U) {
          return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                         LanMdnsError::dns_invalid_record);
        }
        const std::uint16_t port = read_be16(packet, rdata_start + 4U);
        const auto target_res = decode_dns_name(packet, rdata_start + 6U);
        if (!target_res.has_value()) {
          return Result<LanMdnsPacket>::failure(target_res.error());
        }
        if (target_res.value().next_offset != rdata_end) {
          return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                         LanMdnsError::dns_invalid_record);
        }
        srvs.push_back(
            RawSrv{owner_res.value().name, port, target_res.value().name, ttl});
      } else if (rtype == kDnsTypeTxt) {
        txts.push_back(
            RawTxt{owner_res.value().name, packet.subspan(rdata_start, rdlength), ttl});
      } else if (rtype == kDnsTypeA) {
        if (rdlength != 4U) {
          return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                         LanMdnsError::dns_invalid_record);
        }
        const std::array<std::uint8_t, 4> ip = {
            packet[rdata_start], packet[rdata_start + 1U], packet[rdata_start + 2U],
            packet[rdata_start + 3U]};
        addrs.push_back(
            RawAddr{owner_res.value().name, P2pDirectAddr::ipv4(ip, 0U), ttl});
      } else if (rtype == kDnsTypeAaaa) {
        if (rdlength != 16U) {
          return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                         LanMdnsError::dns_invalid_record);
        }
        std::array<std::uint8_t, 16> ip{};
        std::memcpy(ip.data(), packet.data() + rdata_start, 16U);
        addrs.push_back(
            RawAddr{owner_res.value().name, P2pDirectAddr::ipv6(ip, 0U), ttl});
      }
    }

    offset = rdata_end;
  }

  if (offset != packet.size()) {
    return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                   LanMdnsError::dns_malformed_header);
  }

  if (!is_response) {
    return Result<LanMdnsPacket>::success(std::move(result));
  }

  for (const auto &ptr : ptrs) {
    const auto parsed_id = extract_party_id_from_instance_name(ptr.target);
    if (!parsed_id.has_value()) {
      continue;
    }

    const RawTxt *matched_txt = nullptr;
    for (const auto &txt : txts) {
      if (dns_names_equal_ci(txt.owner, ptr.target)) {
        matched_txt = &txt;
        break;
      }
    }

    const RawSrv *matched_srv = nullptr;
    for (const auto &srv : srvs) {
      if (dns_names_equal_ci(srv.owner, ptr.target)) {
        matched_srv = &srv;
        break;
      }
    }

    if (matched_txt == nullptr) {
      if (ptr.ttl == 0U) {
        result.goodbye_party_ids.push_back(*parsed_id);
      }
      continue;
    }

    const auto decoded_beacon = decode_lan_txt_record(matched_txt->rdata);
    if (!decoded_beacon.has_value()) {
      return Result<LanMdnsPacket>::failure(decoded_beacon.error());
    }
    if (decoded_beacon.value().lan_party_id != *parsed_id) {
      return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                     LanMdnsError::invalid_party_id);
    }

    if (matched_srv == nullptr) {
      if (ptr.ttl == 0U || matched_txt->ttl == 0U) {
        LanMdnsAnnouncement ann{};
        ann.beacon = decoded_beacon.value();
        ann.ttl_sec = 0U;
        result.announcement = std::move(ann);
        break;
      }
      return lan_fail<LanMdnsPacket>(ErrorCode::corrupt,
                                     LanMdnsError::dns_invalid_record);
    }

    const std::uint32_t effective_ttl =
        std::min({ptr.ttl, matched_srv->ttl, matched_txt->ttl});
    if (effective_ttl > 0U && matched_srv->port == 0U) {
      return lan_fail<LanMdnsPacket>(ErrorCode::corrupt, LanMdnsError::invalid_port);
    }

    LanMdnsAnnouncement ann{};
    ann.beacon = decoded_beacon.value();
    ann.service_port = matched_srv->port;
    ann.ttl_sec = effective_ttl;
    for (const auto &addr_rr : addrs) {
      if (!dns_names_equal_ci(addr_rr.owner, matched_srv->target)) {
        continue;
      }
      if (effective_ttl > 0U && addr_rr.ttl == 0U) {
        continue;
      }
      P2pDirectAddr candidate = addr_rr.addr;
      candidate.port = matched_srv->port;
      if (is_allowed_direct_addr(candidate, effective_ttl > 0U)) {
        ann.addrs.push_back(candidate);
      }
    }
    deduplicate_addrs(ann.addrs);
    result.announcement = std::move(ann);
    break;
  }

  return Result<LanMdnsPacket>::success(std::move(result));
}

// ---------------------------------------------------------------------------
// 3. Local LAN IPv4 Enumeration, LanMdnsAdvertiser, LanMdnsScanner
// ---------------------------------------------------------------------------

Result<std::vector<P2pDirectAddr>>
enumerate_lan_ipv4_addrs(LanServicePort service_port) {
  if (service_port.value == 0U) {
    return lan_fail<std::vector<P2pDirectAddr>>(ErrorCode::invalid_range,
                                                LanMdnsError::invalid_port);
  }
  ifaddrs *raw_list = nullptr;
  if (::getifaddrs(&raw_list) != 0) {
    return lan_fail<std::vector<P2pDirectAddr>>(ErrorCode::io,
                                                LanMdnsError::socket_io_failed);
  }
  struct IfAddrsGuard {
    ifaddrs *list = nullptr;
    ~IfAddrsGuard() noexcept {
      if (list != nullptr) {
        ::freeifaddrs(list);
      }
    }
  } guard{raw_list};

  std::vector<std::array<std::uint8_t, 4>> ips;
  for (const ifaddrs *ifa = raw_list; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }
    if ((ifa->ifa_flags & IFF_UP) == 0U || (ifa->ifa_flags & IFF_LOOPBACK) != 0U) {
      continue;
    }
    const auto *sin = reinterpret_cast<const sockaddr_in *>(ifa->ifa_addr);
    std::array<std::uint8_t, 4> octets{};
    std::memcpy(octets.data(), &sin->sin_addr.s_addr, 4U);
    if (octets[0] == 127U || !is_allowed_ipv4_octets(octets)) {
      continue;
    }
    if (std::find(ips.begin(), ips.end(), octets) == ips.end()) {
      ips.push_back(octets);
    }
  }

  std::sort(ips.begin(), ips.end(),
            [](const std::array<std::uint8_t, 4> &lhs,
               const std::array<std::uint8_t, 4> &rhs) {
              const int pl = lan_ipv4_priority(lhs);
              const int pr = lan_ipv4_priority(rhs);
              if (pl != pr) {
                return pl < pr;
              }
              return lhs < rhs;
            });

  std::vector<P2pDirectAddr> out;
  out.reserve(std::min(ips.size(), kP2pMaxDirectAddrs));
  for (const auto &ip : ips) {
    if (out.size() >= kP2pMaxDirectAddrs) {
      break;
    }
    out.push_back(P2pDirectAddr::ipv4(ip, service_port.value));
  }
  return Result<std::vector<P2pDirectAddr>>::success(std::move(out));
}

// --- LanMdnsAdvertiser ---

LanMdnsAdvertiser::LanMdnsAdvertiser(LanMdnsAdvertiser &&other) noexcept
    : fd_(std::exchange(other.fd_, -1)), running_(std::exchange(other.running_, false)),
      expired_(std::exchange(other.expired_, false)),
      locked_(std::exchange(other.locked_, false)),
      has_peer_joined_(std::exchange(other.has_peer_joined_, false)),
      enable_multicast_(other.enable_multicast_),
      has_target_(std::exchange(other.has_target_, false)),
      has_last_unicast_peer_(std::exchange(other.has_last_unicast_peer_, false)),
      bound_port_(std::exchange(other.bound_port_, 0U)),
      target_ipv4_be_(other.target_ipv4_be_), target_port_(other.target_port_),
      last_unicast_peer_ipv4_be_(other.last_unicast_peer_ipv4_be_),
      last_unicast_peer_port_(other.last_unicast_peer_port_),
      idle_timeout_sec_(other.idle_timeout_sec_), started_at_(other.started_at_),
      last_announce_at_(other.last_announce_at_),
      announce_packet_(std::move(other.announce_packet_)),
      goodbye_packet_(std::move(other.goodbye_packet_)),
      announcements_sent_(other.announcements_sent_),
      queries_answered_(other.queries_answered_), goodbyes_sent_(other.goodbyes_sent_) {
}

LanMdnsAdvertiser &LanMdnsAdvertiser::operator=(LanMdnsAdvertiser &&other) noexcept {
  if (this != &other) {
    stop();
    fd_ = std::exchange(other.fd_, -1);
    running_ = std::exchange(other.running_, false);
    expired_ = std::exchange(other.expired_, false);
    locked_ = std::exchange(other.locked_, false);
    has_peer_joined_ = std::exchange(other.has_peer_joined_, false);
    enable_multicast_ = other.enable_multicast_;
    has_target_ = std::exchange(other.has_target_, false);
    has_last_unicast_peer_ = std::exchange(other.has_last_unicast_peer_, false);
    bound_port_ = std::exchange(other.bound_port_, 0U);
    target_ipv4_be_ = other.target_ipv4_be_;
    target_port_ = other.target_port_;
    last_unicast_peer_ipv4_be_ = other.last_unicast_peer_ipv4_be_;
    last_unicast_peer_port_ = other.last_unicast_peer_port_;
    idle_timeout_sec_ = other.idle_timeout_sec_;
    started_at_ = other.started_at_;
    last_announce_at_ = other.last_announce_at_;
    announce_packet_ = std::move(other.announce_packet_);
    goodbye_packet_ = std::move(other.goodbye_packet_);
    announcements_sent_ = other.announcements_sent_;
    queries_answered_ = other.queries_answered_;
    goodbyes_sent_ = other.goodbyes_sent_;
  }
  return *this;
}

LanMdnsAdvertiser::~LanMdnsAdvertiser() noexcept { stop(); }

Result<void> LanMdnsAdvertiser::start(const LanBeaconRecord &beacon,
                                      LanServicePort service_port,
                                      LanIdleTimeoutSec idle_timeout_sec,
                                      const LanMdnsSocketConfig &socket_cfg) {
  if (running_) {
    return lan_fail_void(ErrorCode::busy, LanMdnsError::already_running);
  }
  if (service_port.value == 0U) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_port);
  }
  if (idle_timeout_sec.value < kLanMinIdleTimeoutSec ||
      idle_timeout_sec.value > kLanMaxIdleTimeoutSec) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_timeout);
  }
  const auto valid_beacon = validate_lan_beacon_record(beacon);
  if (!valid_beacon.has_value()) {
    return valid_beacon;
  }

  std::vector<P2pDirectAddr> advertise_addrs;
  if (!socket_cfg.advertise_addrs.empty()) {
    if (socket_cfg.advertise_addrs.size() > kP2pMaxDirectAddrs) {
      return lan_fail_void(ErrorCode::capacity, LanMdnsError::invalid_socket_config);
    }
    advertise_addrs.reserve(socket_cfg.advertise_addrs.size());
    for (P2pDirectAddr addr : socket_cfg.advertise_addrs) {
      addr.port = service_port.value;
      if (!is_allowed_direct_addr(addr, true)) {
        return lan_fail_void(ErrorCode::invalid_range,
                             LanMdnsError::invalid_socket_config);
      }
      advertise_addrs.push_back(addr);
    }
    deduplicate_addrs(advertise_addrs);
  } else {
    auto enumerated = enumerate_lan_ipv4_addrs(service_port);
    if (!enumerated.has_value()) {
      return Result<void>::failure(enumerated.error());
    }
    advertise_addrs = std::move(enumerated).value();
  }

  LanMdnsAnnouncement ann{};
  ann.beacon = beacon;
  ann.service_port = service_port.value;
  ann.addrs = advertise_addrs;
  ann.ttl_sec = kLanMdnsDefaultTtlSec;
  auto ann_pkt = encode_lan_announcement(ann);
  if (!ann_pkt.has_value()) {
    return Result<void>::failure(ann_pkt.error());
  }

  auto bye_pkt = encode_lan_goodbye(beacon, service_port, advertise_addrs);
  if (!bye_pkt.has_value()) {
    return Result<void>::failure(bye_pkt.error());
  }

  auto opened = open_lan_mdns_socket(socket_cfg);
  if (!opened.has_value()) {
    return Result<void>::failure(opened.error());
  }

  const auto now = std::chrono::steady_clock::now();
  fd_ = opened.value().fd;
  running_ = true;
  expired_ = false;
  locked_ = false;
  has_peer_joined_ = false;
  enable_multicast_ = opened.value().enable_multicast;
  has_target_ = opened.value().has_target;
  has_last_unicast_peer_ = false;
  bound_port_ = opened.value().bound_port;
  target_ipv4_be_ = opened.value().target_ipv4_be;
  target_port_ = opened.value().target_port;
  last_unicast_peer_ipv4_be_ = 0U;
  last_unicast_peer_port_ = 0U;
  idle_timeout_sec_ = idle_timeout_sec.value;
  started_at_ = now;
  last_announce_at_ = now;
  announce_packet_ = std::move(ann_pkt).value();
  goodbye_packet_ = std::move(bye_pkt).value();
  announcements_sent_ = 0U;
  queries_answered_ = 0U;
  goodbyes_sent_ = 0U;

  if (has_target_) {
    if (send_udp_datagram_noexcept(fd_, {target_ipv4_be_, target_port_},
                                   announce_packet_)) {
      ++announcements_sent_;
    }
  }
  return Result<void>::success();
}

Result<void> LanMdnsAdvertiser::pump_once(
    std::uint32_t timeout_ms,
    std::optional<std::chrono::steady_clock::time_point> now_override) {
  if (!running_) {
    return lan_fail_void(ErrorCode::stale_handle, LanMdnsError::not_running);
  }

  const auto current_now = [&]() {
    return now_override.value_or(std::chrono::steady_clock::now());
  };

  const auto deadline = started_at_ + std::chrono::seconds(idle_timeout_sec_);
  const auto check_idle_expired = [&](std::chrono::steady_clock::time_point now) {
    if (!has_peer_joined_ && now >= deadline) {
      expired_ = true;
      stop();
      return true;
    }
    return false;
  };

  if (check_idle_expired(current_now())) {
    return Result<void>::success();
  }

  std::uint32_t effective_poll_ms = timeout_ms;
  if (!now_override.has_value() && !has_peer_joined_ && effective_poll_ms > 0U) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      expired_ = true;
      stop();
      return Result<void>::success();
    }
    const auto rem_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    if (rem_ms <= 0) {
      effective_poll_ms = 0U;
    } else if (static_cast<std::uint64_t>(rem_ms) < effective_poll_ms) {
      effective_poll_ms = static_cast<std::uint32_t>(rem_ms);
    }
  }

  poll_socket_readable(fd_, std::chrono::milliseconds(effective_poll_ms));

  std::array<std::uint8_t, kLanMdnsMaxPacketBytes> buf{};
  for (std::size_t i = 0U; i < kMaxDatagramsPerPump && running_; ++i) {
    sockaddr_in sender{};
    socklen_t sender_len = sizeof(sender);
    const ssize_t n = ::recvfrom(fd_, buf.data(), buf.size(), 0,
                                 reinterpret_cast<sockaddr *>(&sender), &sender_len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (n == 0) {
      continue;
    }

    const auto decoded = decode_lan_mdns_packet(
        std::span<const std::uint8_t>(buf.data(), static_cast<std::size_t>(n)));
    if (!decoded.has_value() || decoded.value().is_response) {
      continue;
    }

    for (const auto &q : decoded.value().questions) {
      if (q.qtype == kDnsTypePtr && q.qclass == kDnsClassIn &&
          dns_names_equal_ci(q.qname, kLanMdnsServiceType)) {
        const std::uint32_t sender_ip =
            static_cast<std::uint32_t>(sender.sin_addr.s_addr);
        const std::uint16_t sender_port =
            be16_to_host(static_cast<std::uint16_t>(sender.sin_port));

        bool sent = false;
        if (!enable_multicast_) {
          if (sender_port > 0U) {
            last_unicast_peer_ipv4_be_ = sender_ip;
            last_unicast_peer_port_ = sender_port;
            has_last_unicast_peer_ = true;
            sent = send_udp_datagram_noexcept(fd_, {sender_ip, sender_port},
                                              announce_packet_);
          }
        } else if (q.unicast_response && sender_port > 0U) {
          sent = send_udp_datagram_noexcept(fd_, {sender_ip, sender_port},
                                            announce_packet_);
        } else if (has_target_) {
          sent = send_udp_datagram_noexcept(fd_, {target_ipv4_be_, target_port_},
                                            announce_packet_);
        }
        if (sent) {
          ++announcements_sent_;
          ++queries_answered_;
        }
        break;
      }
    }
  }

  const auto after_now = current_now();
  if (check_idle_expired(after_now)) {
    return Result<void>::success();
  }

  if (running_ && has_target_ &&
      after_now >=
          last_announce_at_ + std::chrono::seconds(kLanAnnounceRefreshIntervalSec)) {
    if (send_udp_datagram_noexcept(fd_, {target_ipv4_be_, target_port_},
                                   announce_packet_)) {
      ++announcements_sent_;
    }
    last_announce_at_ = after_now;
  }

  return Result<void>::success();
}

void LanMdnsAdvertiser::mark_peer_joined() noexcept { has_peer_joined_ = true; }

void LanMdnsAdvertiser::lock_lobby() noexcept {
  locked_ = true;
  stop();
}

void LanMdnsAdvertiser::stop() noexcept {
  if (fd_ >= 0) {
    send_goodbye_best_effort();
    close_socket_noexcept();
  }
  running_ = false;
  bound_port_ = 0U;
}

void LanMdnsAdvertiser::send_goodbye_best_effort() noexcept {
  if (fd_ < 0 || goodbye_packet_.empty()) {
    return;
  }
  bool sent = false;
  if (has_target_) {
    sent = send_udp_datagram_noexcept(fd_, {target_ipv4_be_, target_port_},
                                      goodbye_packet_);
  }
  if (!enable_multicast_ && has_last_unicast_peer_) {
    const bool same_as_target = has_target_ &&
                                last_unicast_peer_ipv4_be_ == target_ipv4_be_ &&
                                last_unicast_peer_port_ == target_port_;
    if (!same_as_target) {
      sent = send_udp_datagram_noexcept(
                 fd_, {last_unicast_peer_ipv4_be_, last_unicast_peer_port_},
                 goodbye_packet_) ||
             sent;
    }
  }
  if (sent) {
    ++goodbyes_sent_;
  }
}

void LanMdnsAdvertiser::close_socket_noexcept() noexcept {
  if (fd_ >= 0) {
    (void)::close(fd_);
    fd_ = -1;
  }
}

// --- LanMdnsScanner ---

LanMdnsScanner::LanMdnsScanner(LanMdnsScanner &&other) noexcept
    : fd_(std::exchange(other.fd_, -1)), running_(std::exchange(other.running_, false)),
      expired_(std::exchange(other.expired_, false)),
      enable_multicast_(other.enable_multicast_),
      has_target_(std::exchange(other.has_target_, false)),
      bound_port_(std::exchange(other.bound_port_, 0U)),
      target_ipv4_be_(other.target_ipv4_be_), target_port_(other.target_port_),
      scan_timeout_sec_(other.scan_timeout_sec_), started_at_(other.started_at_),
      query_packet_(std::move(other.query_packet_)),
      lobbies_(std::move(other.lobbies_)), queries_sent_(other.queries_sent_) {}

LanMdnsScanner &LanMdnsScanner::operator=(LanMdnsScanner &&other) noexcept {
  if (this != &other) {
    stop();
    fd_ = std::exchange(other.fd_, -1);
    running_ = std::exchange(other.running_, false);
    expired_ = std::exchange(other.expired_, false);
    enable_multicast_ = other.enable_multicast_;
    has_target_ = std::exchange(other.has_target_, false);
    bound_port_ = std::exchange(other.bound_port_, 0U);
    target_ipv4_be_ = other.target_ipv4_be_;
    target_port_ = other.target_port_;
    scan_timeout_sec_ = other.scan_timeout_sec_;
    started_at_ = other.started_at_;
    query_packet_ = std::move(other.query_packet_);
    lobbies_ = std::move(other.lobbies_);
    queries_sent_ = other.queries_sent_;
  }
  return *this;
}

LanMdnsScanner::~LanMdnsScanner() noexcept { stop(); }

Result<void> LanMdnsScanner::start(std::uint32_t scan_timeout_sec,
                                   const LanMdnsSocketConfig &socket_cfg) {
  if (running_) {
    return lan_fail_void(ErrorCode::busy, LanMdnsError::already_running);
  }
  if (scan_timeout_sec < kLanMinScanTimeoutSec ||
      scan_timeout_sec > kLanMaxScanTimeoutSec) {
    return lan_fail_void(ErrorCode::invalid_range, LanMdnsError::invalid_timeout);
  }

  auto query_pkt = encode_lan_ptr_query(!socket_cfg.enable_multicast);
  if (!query_pkt.has_value()) {
    return Result<void>::failure(query_pkt.error());
  }

  auto opened = open_lan_mdns_socket(socket_cfg);
  if (!opened.has_value()) {
    return Result<void>::failure(opened.error());
  }

  fd_ = opened.value().fd;
  running_ = true;
  expired_ = false;
  enable_multicast_ = opened.value().enable_multicast;
  has_target_ = opened.value().has_target;
  bound_port_ = opened.value().bound_port;
  target_ipv4_be_ = opened.value().target_ipv4_be;
  target_port_ = opened.value().target_port;
  scan_timeout_sec_ = scan_timeout_sec;
  started_at_ = std::chrono::steady_clock::now();
  query_packet_ = std::move(query_pkt).value();
  lobbies_.clear();
  queries_sent_ = 0U;

  if (has_target_) {
    if (send_udp_datagram_noexcept(fd_, {target_ipv4_be_, target_port_},
                                   query_packet_)) {
      ++queries_sent_;
    }
  }
  return Result<void>::success();
}

Result<void> LanMdnsScanner::send_query() {
  if (!running_) {
    return lan_fail_void(ErrorCode::stale_handle, LanMdnsError::not_running);
  }
  if (!has_target_) {
    return Result<void>::success();
  }
  if (!send_udp_datagram_noexcept(fd_, {target_ipv4_be_, target_port_},
                                  query_packet_)) {
    return lan_fail_void(ErrorCode::io, LanMdnsError::socket_io_failed);
  }
  ++queries_sent_;
  return Result<void>::success();
}

Result<void> LanMdnsScanner::pump_once(
    std::uint32_t timeout_ms,
    std::optional<std::chrono::steady_clock::time_point> now_override) {
  if (!running_) {
    return lan_fail_void(ErrorCode::stale_handle, LanMdnsError::not_running);
  }

  const auto current_now = [&]() {
    return now_override.value_or(std::chrono::steady_clock::now());
  };
  const auto deadline = started_at_ + std::chrono::seconds(scan_timeout_sec_);

  if (current_now() >= deadline) {
    expired_ = true;
    stop();
    return Result<void>::success();
  }

  std::uint32_t effective_poll_ms = timeout_ms;
  if (!now_override.has_value() && effective_poll_ms > 0U) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      expired_ = true;
      stop();
      return Result<void>::success();
    }
    const auto rem_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    if (rem_ms <= 0) {
      effective_poll_ms = 0U;
    } else if (static_cast<std::uint64_t>(rem_ms) < effective_poll_ms) {
      effective_poll_ms = static_cast<std::uint32_t>(rem_ms);
    }
  }

  poll_socket_readable(fd_, std::chrono::milliseconds(effective_poll_ms));

  std::array<std::uint8_t, kLanMdnsMaxPacketBytes> buf{};
  for (std::size_t i = 0U; i < kMaxDatagramsPerPump && running_; ++i) {
    sockaddr_in sender{};
    socklen_t sender_len = sizeof(sender);
    const ssize_t n = ::recvfrom(fd_, buf.data(), buf.size(), 0,
                                 reinterpret_cast<sockaddr *>(&sender), &sender_len);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    if (n == 0) {
      continue;
    }

    const auto decoded = decode_lan_mdns_packet(
        std::span<const std::uint8_t>(buf.data(), static_cast<std::size_t>(n)));
    if (!decoded.has_value() || !decoded.value().is_response) {
      continue;
    }

    const auto &pkt = decoded.value();
    if (pkt.announcement.has_value()) {
      const auto &ann = *pkt.announcement;
      if (ann.is_goodbye()) {
        std::erase_if(lobbies_, [&](const DiscoveredLanLobby &entry) {
          return entry.beacon.lan_party_id == ann.beacon.lan_party_id &&
                 entry.beacon.host_pubkey == ann.beacon.host_pubkey;
        });
        continue;
      }

      std::vector<P2pDirectAddr> resolved_addrs = ann.addrs;
      if (resolved_addrs.empty() && ann.service_port > 0U) {
        std::array<std::uint8_t, 4> sender_ip{};
        std::memcpy(sender_ip.data(), &sender.sin_addr.s_addr, 4U);
        if (is_allowed_ipv4_octets(sender_ip)) {
          resolved_addrs.push_back(P2pDirectAddr::ipv4(sender_ip, ann.service_port));
        }
      }

      const auto seen_at = current_now();
      auto existing = std::find_if(
          lobbies_.begin(), lobbies_.end(), [&](const DiscoveredLanLobby &entry) {
            return entry.beacon.lan_party_id == ann.beacon.lan_party_id &&
                   entry.beacon.host_pubkey == ann.beacon.host_pubkey;
          });
      if (existing != lobbies_.end()) {
        existing->beacon = ann.beacon;
        existing->service_port = ann.service_port;
        existing->addrs = std::move(resolved_addrs);
        existing->ttl_sec = ann.ttl_sec;
        existing->last_seen = seen_at;
      } else if (lobbies_.size() < kLanMaxDiscoveredLobbies) {
        lobbies_.push_back(DiscoveredLanLobby{
            ann.beacon,
            ann.service_port,
            std::move(resolved_addrs),
            ann.ttl_sec,
            seen_at,
        });
      }
    } else if (!pkt.goodbye_party_ids.empty()) {
      for (const auto &party_id : pkt.goodbye_party_ids) {
        std::erase_if(lobbies_, [&](const DiscoveredLanLobby &entry) {
          return entry.beacon.lan_party_id == party_id;
        });
      }
    }
  }

  if (current_now() >= deadline) {
    expired_ = true;
    stop();
  }
  return Result<void>::success();
}

void LanMdnsScanner::stop() noexcept {
  close_socket_noexcept();
  running_ = false;
  bound_port_ = 0U;
}

void LanMdnsScanner::close_socket_noexcept() noexcept {
  if (fd_ >= 0) {
    (void)::close(fd_);
    fd_ = -1;
  }
}

std::vector<DiscoveredLanLobby> LanMdnsScanner::lobbies() const {
  std::vector<DiscoveredLanLobby> snapshot = lobbies_;
  std::sort(snapshot.begin(), snapshot.end(),
            [](const DiscoveredLanLobby &lhs, const DiscoveredLanLobby &rhs) {
              if (lhs.beacon.lobby_name != rhs.beacon.lobby_name) {
                return lhs.beacon.lobby_name < rhs.beacon.lobby_name;
              }
              if (lhs.beacon.lan_party_id != rhs.beacon.lan_party_id) {
                return lhs.beacon.lan_party_id < rhs.beacon.lan_party_id;
              }
              return lhs.beacon.host_pubkey < rhs.beacon.host_pubkey;
            });
  return snapshot;
}

// ---------------------------------------------------------------------------
// 4. Quake-Style Direct Target Parser & Formatter
// ---------------------------------------------------------------------------

Result<P2pDirectAddr> parse_lan_direct_target(std::string_view input) {
  if (input.empty() || input.size() > kMaxDirectTargetBytes) {
    return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  for (const char ch : input) {
    const auto byte = static_cast<std::uint8_t>(ch);
    // Reject whitespace (<= 0x20), control chars, DEL, and non-ASCII.
    if (byte <= 0x20U || byte >= 0x7fU) {
      return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
  }

  if (input.front() == '[') {
    const std::size_t close_bracket = input.find(']');
    if (close_bracket == std::string_view::npos || close_bracket <= 1U ||
        close_bracket + 2U >= input.size() || input[close_bracket + 1U] != ':') {
      return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    const std::string_view ip_text = input.substr(1U, close_bracket - 1U);
    const std::string_view port_text = input.substr(close_bracket + 2U);

    // Strictly allow IPv6 literal characters only (no zone IDs '%', no brackets).
    bool has_colon = false;
    for (const char ch : ip_text) {
      const bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                      (ch >= 'A' && ch <= 'F') || ch == ':' || ch == '.';
      if (!ok) {
        return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                       LanMdnsError::invalid_direct_target);
      }
      if (ch == ':') {
        has_colon = true;
      }
    }
    if (!has_colon) {
      return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }

    const auto port_res = parse_strict_port(port_text);
    if (!port_res.has_value()) {
      return Result<P2pDirectAddr>::failure(port_res.error());
    }

    const std::string ip_nul(ip_text);
    in6_addr in6{};
    if (::inet_pton(AF_INET6, ip_nul.c_str(), &in6) != 1) {
      return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    std::array<std::uint8_t, 16> octets{};
    std::memcpy(octets.data(), &in6, 16U);
    if (!is_allowed_ipv6_octets(octets)) {
      return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                     LanMdnsError::invalid_direct_target);
    }
    return Result<P2pDirectAddr>::success(
        P2pDirectAddr::ipv6(octets, port_res.value()));
  }

  // IPv4 form: must contain exactly one ':'.
  const std::size_t colon = input.find(':');
  if (colon == std::string_view::npos || colon == 0U || colon + 1U >= input.size() ||
      input.find(':', colon + 1U) != std::string_view::npos) {
    return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  const std::string_view ip_text = input.substr(0U, colon);
  const std::string_view port_text = input.substr(colon + 1U);

  const auto ipv4_be = parse_strict_ipv4_be(ip_text);
  if (!ipv4_be.has_value()) {
    return Result<P2pDirectAddr>::failure(ipv4_be.error());
  }
  const auto port_res = parse_strict_port(port_text);
  if (!port_res.has_value()) {
    return Result<P2pDirectAddr>::failure(port_res.error());
  }

  std::array<std::uint8_t, 4> octets{};
  std::memcpy(octets.data(), &ipv4_be.value(), 4U);
  if (!is_allowed_ipv4_octets(octets)) {
    return lan_fail<P2pDirectAddr>(ErrorCode::invalid_range,
                                   LanMdnsError::invalid_direct_target);
  }
  return Result<P2pDirectAddr>::success(P2pDirectAddr::ipv4(octets, port_res.value()));
}

Result<std::string> format_lan_direct_target(const P2pDirectAddr &addr) {
  if (!is_allowed_direct_addr(addr, true)) {
    return lan_fail<std::string>(ErrorCode::invalid_range,
                                 LanMdnsError::invalid_direct_target);
  }
  if (addr.family == 4U) {
    return Result<std::string>::success(
        std::to_string(addr.ip[0]) + "." + std::to_string(addr.ip[1]) + "." +
        std::to_string(addr.ip[2]) + "." + std::to_string(addr.ip[3]) + ":" +
        std::to_string(addr.port));
  }
  in6_addr in6{};
  std::memcpy(&in6, addr.ip.data(), 16U);
  std::array<char, INET6_ADDRSTRLEN> text{};
  if (::inet_ntop(AF_INET6, &in6, text.data(), static_cast<socklen_t>(text.size())) ==
      nullptr) {
    return lan_fail<std::string>(ErrorCode::invalid_range,
                                 LanMdnsError::invalid_direct_target);
  }
  return Result<std::string>::success(std::string{"["} + text.data() +
                                      "]:" + std::to_string(addr.port));
}

} // namespace blackbird
