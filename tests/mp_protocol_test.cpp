#include "blackbird/mp_protocol.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace blackbird;
using namespace blackbird::mp;

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
                             mp_error_name(mp_error_of(result.error())) + ")");
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: " + error_name(result.error().code) + " (" +
                             mp_error_name(mp_error_of(result.error())) + ")");
  }
}

template <typename T>
const T &must_opt(const std::optional<T> &opt, const char *context) {
  if (!opt.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: expected optional value");
  }
  return *opt;
}

template <typename T>
void expect_err(const Result<T> &result, MpError expected, const char *context) {
  if (result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: expected error " + mp_error_name(expected) +
                             ", got success");
  }
  const MpError actual = mp_error_of(result.error());
  if (actual != expected) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: expected error " + mp_error_name(expected) + ", got " +
                             mp_error_name(actual));
  }
}

Ed25519SigningKey test_signing_key(std::uint8_t seed_byte) {
  Ed25519Seed seed{};
  seed.fill(seed_byte);
  return must(Ed25519SigningKey::from_seed(seed), "test_signing_key");
}

std::vector<std::uint8_t> to_bytes(std::string_view text) {
  std::vector<std::uint8_t> out;
  out.reserve(text.size());
  for (const char ch : text) {
    out.push_back(static_cast<std::uint8_t>(ch));
  }
  return out;
}

std::vector<std::uint8_t> from_hex(std::string_view hex) {
  require((hex.size() % 2U) == 0U, "from_hex even length");
  const auto nibble = [](char ch) -> std::uint8_t {
    if (ch >= '0' && ch <= '9') {
      return static_cast<std::uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
      return static_cast<std::uint8_t>(10 + (ch - 'a'));
    }
    if (ch >= 'A' && ch <= 'F') {
      return static_cast<std::uint8_t>(10 + (ch - 'A'));
    }
    require(false, "from_hex invalid hex digit");
    return 0U;
  };
  std::vector<std::uint8_t> out;
  out.reserve(hex.size() / 2U);
  for (std::size_t i = 0U; i < hex.size(); i += 2U) {
    const auto hi = nibble(hex[i]);
    const auto lo = nibble(hex[i + 1U]);
    out.push_back(static_cast<std::uint8_t>((hi << 4U) | lo));
  }
  return out;
}

std::string encode_base64(std::span<const std::uint8_t> bytes, bool url_safe_nopad) {
  static constexpr char kStdAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  static constexpr char kUrlAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const char *alphabet = url_safe_nopad ? kUrlAlphabet : kStdAlphabet;
  std::string out;
  out.reserve(((bytes.size() + 2U) / 3U) * 4U);
  for (std::size_t i = 0U; i < bytes.size(); i += 3U) {
    const std::uint32_t b0 = bytes[i];
    const bool has_b1 = (i + 1U) < bytes.size();
    const bool has_b2 = (i + 2U) < bytes.size();
    const std::uint32_t b1 = has_b1 ? bytes[i + 1U] : 0U;
    const std::uint32_t b2 = has_b2 ? bytes[i + 2U] : 0U;
    const std::uint32_t triple = (b0 << 16U) | (b1 << 8U) | b2;
    out.push_back(alphabet[(triple >> 18U) & 0x3fU]);
    out.push_back(alphabet[(triple >> 12U) & 0x3fU]);
    if (has_b1) {
      out.push_back(alphabet[(triple >> 6U) & 0x3fU]);
    } else if (!url_safe_nopad) {
      out.push_back('=');
    }
    if (has_b2) {
      out.push_back(alphabet[triple & 0x3fU]);
    } else if (!url_safe_nopad) {
      out.push_back('=');
    }
  }
  return out;
}

void test_safe_ids_and_handles() {
  g_stage = "safe_ids_and_handles";

  expect_err(AccountId::create(0U), MpError::id_zero, "account zero");
  expect_err(DeviceId::create(0U), MpError::id_zero, "device zero");
  expect_err(PartyId::create(0U), MpError::id_zero, "party zero");
  expect_err(InviteId::create(0U), MpError::id_zero, "invite zero");
  expect_err(SessionId::create(0U), MpError::id_zero, "session zero");

  const auto min_id = must(AccountId::create(1U), "min id");
  require(min_id.value() == 1U, "min id value");
  const auto max_id = must(AccountId::create(kMaxSafeId), "max safe id");
  require(max_id.value() == 9007199254740991ULL, "max safe id exact");
  expect_err(AccountId::create(kMaxSafeId + 1U), MpError::id_exceeds_safe_int,
             "2^53 rejected");
  expect_err(PartyId::create(std::numeric_limits<std::uint64_t>::max()),
             MpError::id_exceeds_safe_int, "u64 max rejected");

  const auto le = max_id.to_le_bytes();
  require(le[0] == 0xffU && le[6] == 0x1fU && le[7] == 0x00U, "max safe id LE bytes");
  const auto roundtrip = must(AccountId::from_le_bytes(le), "from_le_bytes");
  require(roundtrip == max_id, "id le roundtrip");

  require(must(AccountId::parse_decimal("1"), "parse 1").value() == 1U, "decimal 1");
  require(must(AccountId::parse_decimal("9007199254740991"), "parse max").value() ==
              kMaxSafeId,
          "decimal max");
  expect_err(AccountId::parse_decimal(""), MpError::id_invalid_decimal,
             "empty decimal");
  expect_err(AccountId::parse_decimal("0"), MpError::id_invalid_decimal,
             "zero decimal");
  expect_err(AccountId::parse_decimal("01"), MpError::id_invalid_decimal,
             "leading zero");
  expect_err(AccountId::parse_decimal("-5"), MpError::id_invalid_decimal, "negative");
  expect_err(AccountId::parse_decimal("12a"), MpError::id_invalid_decimal, "non-digit");
  expect_err(AccountId::parse_decimal("9007199254740992"), MpError::id_exceeds_safe_int,
             "decimal 2^53");
  expect_err(AccountId::parse_decimal("12345678901234567"), MpError::id_invalid_decimal,
             "decimal >16 digits");

  for (int i = 0; i < 16; ++i) {
    const auto gid = must(generate_random_global_id(), "random global id");
    require(gid >= 1U && gid <= kMaxRandomGlobalId, "random global id 52-bit range");
  }

  const auto handle = must(AccountHandle::parse("Patrick_1"), "valid handle");
  require(handle.display() == "Patrick_1", "handle display");
  require(handle.normalized() == "patrick_1", "handle normalized");
  expect_err(AccountHandle::parse("admin"), MpError::reserved_handle, "reserved admin");
  expect_err(AccountHandle::parse("Blackbird"), MpError::reserved_handle,
             "reserved blackbird");
  expect_err(AccountHandle::parse("ab"), MpError::invalid_handle, "too short");
  expect_err(AccountHandle::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
             MpError::invalid_handle, "too long");
  expect_err(AccountHandle::parse("a__b"), MpError::invalid_handle,
             "double underscore");
  expect_err(AccountHandle::parse("a_-b"), MpError::invalid_handle, "adjacent sep");
  expect_err(AccountHandle::parse("_abc"), MpError::invalid_handle, "leading sep");
  expect_err(AccountHandle::parse("abc-"), MpError::invalid_handle, "trailing sep");
}

void test_ed25519_rfc8032_and_strict_rejections() {
  g_stage = "ed25519_rfc8032";

  // RFC 8032 Section 7.1 TEST 1 (empty message)
  const Ed25519Seed sk_bytes = {
      0x9dU, 0x61U, 0xb1U, 0x9dU, 0xefU, 0xfdU, 0x5aU, 0x60U, 0xbaU, 0x84U, 0x4aU,
      0xf4U, 0x92U, 0xecU, 0x2cU, 0xc4U, 0x44U, 0x49U, 0xc5U, 0x69U, 0x7bU, 0x32U,
      0x69U, 0x19U, 0x70U, 0x3bU, 0xacU, 0x03U, 0x1cU, 0xaeU, 0x7fU, 0x60U,
  };
  const Ed25519PubKey expected_pk = {
      0xd7U, 0x5aU, 0x98U, 0x01U, 0x82U, 0xb1U, 0x0aU, 0xb7U, 0xd5U, 0x4bU, 0xfeU,
      0xd3U, 0xc9U, 0x64U, 0x07U, 0x3aU, 0x0eU, 0xe1U, 0x72U, 0xf3U, 0xdaU, 0xa6U,
      0x23U, 0x25U, 0xafU, 0x02U, 0x1aU, 0x68U, 0xf7U, 0x07U, 0x51U, 0x1aU,
  };
  const Ed25519Sig expected_sig = {
      0xe5U, 0x56U, 0x43U, 0x00U, 0xc3U, 0x60U, 0xacU, 0x72U, 0x90U, 0x86U, 0xe2U,
      0xccU, 0x80U, 0x6eU, 0x82U, 0x8aU, 0x84U, 0x87U, 0x7fU, 0x1eU, 0xb8U, 0xe5U,
      0xd9U, 0x74U, 0xd8U, 0x73U, 0xe0U, 0x65U, 0x22U, 0x49U, 0x01U, 0x55U, 0x5fU,
      0xb8U, 0x82U, 0x15U, 0x90U, 0xa3U, 0x3bU, 0xacU, 0xc6U, 0x1eU, 0x39U, 0x70U,
      0x1cU, 0xf9U, 0xb4U, 0x6bU, 0xd2U, 0x5bU, 0xf5U, 0xf0U, 0x59U, 0x5bU, 0xbeU,
      0x24U, 0x65U, 0x51U, 0x41U, 0x43U, 0x8eU, 0x7aU, 0x10U, 0x0bU,
  };

  const auto key = must(Ed25519SigningKey::from_seed(sk_bytes), "from_seed");
  require(key.public_key() == expected_pk, "RFC 8032 pubkey match");
  const auto sig = must(key.sign({}), "RFC 8032 sign empty");
  require(sig == expected_sig, "RFC 8032 signature match");
  must_void(verify_ed25519_strict({expected_pk, {}, expected_sig}),
            "RFC 8032 verify empty");

  // Single-bit flip in message or signature rejected.
  const std::array<std::uint8_t, 1> one_byte = {0x00U};
  expect_err(verify_ed25519_strict({expected_pk, one_byte, expected_sig}),
             MpError::invalid_signature, "wrong message");
  auto flipped_sig = expected_sig;
  flipped_sig[63] ^= 0x01U;
  expect_err(verify_ed25519_strict({expected_pk, {}, flipped_sig}),
             MpError::invalid_signature, "flipped sig");

  // Small-order torsion public keys (Chalkias et al. "Taming the many EdDSAs"):
  Ed25519PubKey id_pt{};
  id_pt[0] = 0x01U;
  expect_err(validate_ed25519_pubkey_strict(id_pt), MpError::weak_public_key,
             "order-1 identity point");

  Ed25519PubKey ord2{};
  ord2.fill(0xffU);
  ord2[0] = 0xecU;
  ord2[31] = 0x7fU;
  expect_err(validate_ed25519_pubkey_strict(ord2), MpError::weak_public_key,
             "order-2 point");

  Ed25519PubKey ord4_a{};
  expect_err(validate_ed25519_pubkey_strict(ord4_a), MpError::weak_public_key,
             "order-4 point A");
  Ed25519PubKey ord4_b{};
  ord4_b[31] = 0x80U;
  expect_err(validate_ed25519_pubkey_strict(ord4_b), MpError::weak_public_key,
             "order-4 point B");

  const Ed25519PubKey ord8_a = {
      0x26U, 0xe8U, 0x95U, 0x8fU, 0xc2U, 0xb2U, 0x27U, 0xb0U, 0x45U, 0xc3U, 0xf4U,
      0x89U, 0xf2U, 0xefU, 0x98U, 0xf0U, 0xd5U, 0xdfU, 0xacU, 0x05U, 0xd3U, 0xc6U,
      0x33U, 0x39U, 0xb1U, 0x38U, 0x02U, 0x88U, 0x6dU, 0x53U, 0xfcU, 0x85U,
  };
  expect_err(validate_ed25519_pubkey_strict(ord8_a), MpError::weak_public_key,
             "order-8 point A");

  // Non-canonical Y = p = 2^255 - 19
  Ed25519PubKey non_canon_p{};
  non_canon_p.fill(0xffU);
  non_canon_p[0] = 0xedU;
  non_canon_p[31] = 0x7fU;
  expect_err(validate_ed25519_pubkey_strict(non_canon_p), MpError::invalid_public_key,
             "non-canonical Y = p");

  // Non-canonical R in signature rejected
  auto bad_r_sig = expected_sig;
  std::memcpy(bad_r_sig.data(), non_canon_p.data(), 32U);
  expect_err(verify_ed25519_strict({expected_pk, {}, bad_r_sig}),
             MpError::invalid_signature, "non-canonical R");

  // Malleable S' = S + L (mod 2^256) rejected
  const std::array<std::uint8_t, 32> l_le = {
      0xedU, 0xd3U, 0xf5U, 0x5cU, 0x1aU, 0x63U, 0x12U, 0x58U, 0xd6U, 0x9cU, 0xf7U,
      0xa2U, 0xdeU, 0xf9U, 0xdeU, 0x14U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U,
      0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x10U,
  };
  auto s_plus_l = expected_sig;
  std::uint16_t carry = 0U;
  for (std::size_t i = 0U; i < 32U; ++i) {
    const auto sum = static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(s_plus_l[32U + i]) + l_le[i] + carry);
    s_plus_l[32U + i] = static_cast<std::uint8_t>(sum & 0xffU);
    carry = static_cast<std::uint16_t>(sum >> 8U);
  }
  expect_err(verify_ed25519_strict({expected_pk, {}, s_plus_l}),
             MpError::invalid_signature, "malleable S + L");

  // Non-canonical sign bit on x == 0: (0, 1) with sign bit 1 -> invalid_public_key
  Ed25519PubKey non_canon_neg0{};
  non_canon_neg0[0] = 0x01U;
  non_canon_neg0[31] = 0x80U;
  expect_err(validate_ed25519_pubkey_strict(non_canon_neg0),
             MpError::invalid_public_key, "non-canonical -0 sign bit");

  // Off-curve & mixed-order public keys across y = 2..26 (parity with
  // mp-protocol/tests/protocol_oracles.rs:135-160):
  // y=2..25 has 9 off-curve + 15 mixed-order points; y=26 is the first prime-order
  // torsion-free point.
  Ed25519PubKey off_curve_y2{};
  off_curve_y2[0] = 2U;
  expect_err(validate_ed25519_pubkey_strict(off_curve_y2), MpError::invalid_public_key,
             "y=2 off-curve rejected");
  Ed25519PubKey mixed_order_y3{};
  mixed_order_y3[0] = 3U;
  expect_err(validate_ed25519_pubkey_strict(mixed_order_y3), MpError::weak_public_key,
             "y=3 mixed-order rejected");
  Ed25519PubKey prime_order_y26{};
  prime_order_y26[0] = 26U;
  must_void(validate_ed25519_pubkey_strict(prime_order_y26),
            "y=26 prime-order accepted");

  int off_curve_rejected = 0;
  int mixed_order_rejected = 0;
  int prime_order_accepted = 0;
  for (std::uint8_t k = 2U; k <= 26U; ++k) {
    Ed25519PubKey probe{};
    probe[0] = k;
    const auto res = validate_ed25519_pubkey_strict(probe);
    if (res.has_value()) {
      ++prime_order_accepted;
    } else if (mp_error_of(res.error()) == MpError::invalid_public_key) {
      ++off_curve_rejected;
    } else if (mp_error_of(res.error()) == MpError::weak_public_key) {
      ++mixed_order_rejected;
    } else {
      require(false, "unexpected error code on y=2..26 probe");
    }
  }
  require(off_curve_rejected == 9, "exact 9 off-curve pubkeys rejected in y=2..26");
  require(mixed_order_rejected == 15,
          "exact 15 mixed-order pubkeys rejected in y=2..26");
  require(prime_order_accepted == 1, "exact 1 prime-order pubkey accepted in y=2..26");

  // Also verify encode_device_cwt rejects off-curve & mixed-order device_pubkey
  expect_err(encode_device_cwt(key, DeviceCwtMintRequest{off_curve_y2, 1000, 2000}),
             MpError::invalid_public_key, "CWT mint rejects off-curve device_pubkey");
  expect_err(encode_device_cwt(key, DeviceCwtMintRequest{mixed_order_y3, 1000, 2000}),
             MpError::weak_public_key, "CWT mint rejects mixed-order device_pubkey");

  // Key generation + sign/verify round-trip + moved-from key fails closed
  auto generated = must(Ed25519SigningKey::generate(), "generate key");
  require(generated.valid(), "generated key is valid");
  const auto msg = to_bytes("blackbird-mp1-openssl3");
  const auto gen_sig = must(generated.sign(msg), "sign generated");
  must_void(verify_ed25519_strict({generated.public_key(), msg, gen_sig}),
            "verify generated");

  const auto move_out = [](Ed25519SigningKey &src) -> Ed25519SigningKey {
    return std::move(src);
  };
  const Ed25519SigningKey moved_dest = move_out(generated);
  require(moved_dest.valid(), "moved destination key valid");
  require(!generated.valid(), "moved-from key marked invalid");
  const auto moved_from_sig = generated.sign(msg);
  require(!moved_from_sig.has_value() &&
              moved_from_sig.error().code == ErrorCode::stale_handle,
          "moved-from Ed25519SigningKey::sign fails closed");
  const auto dest_sig = must(moved_dest.sign(msg), "moved destination still signs");
  must_void(verify_ed25519_strict({moved_dest.public_key(), msg, dest_sig}),
            "moved destination sig verifies");

  std::array<std::uint8_t, 32> secret{};
  secret.fill(0x42U);
  const auto acct_inv_hash = must(hash_account_invite_secret(secret), "acct inv hash");
  const auto party_inv_hash =
      must(hash_party_invite_secret(must(PartyId::create(99U), "pid"), secret),
           "party inv hash");
  require(acct_inv_hash != party_inv_hash, "domain-separated invite hashes differ");
}

void test_endpoint_descriptor_codec_and_policies() {
  g_stage = "endpoint_descriptor";

  // Exact 256B max descriptor: 1 + 2 + 100 + 1 + 8*19 = 256 bytes
  const std::string relay_100 = "https://" + std::string(34U, 'a') + "." +
                                std::string(34U, 'b') + ".relay.multiplayer.tech";
  require(relay_100.size() == 100U, "relay_100 exact length");
  std::vector<DirectAddr> max_addrs(
      kMaxDirectAddrs,
      DirectAddrV6{{0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1U},
                   8788U});
  const EndpointDescriptor max_ep{TransportKind::iroh_quic, relay_100, max_addrs};
  const auto enc = must(max_ep.encode(), "encode 256B max endpoint");
  require(enc.size() == kMaxEndpointDescriptorBytes, "exact 256 bytes");
  require(enc[0] == 1U, "transport_kind byte");
  require(enc[1] == 100U && enc[2] == 0U, "relay_url_len LE");
  require(enc[103] == 8U, "direct_count byte");
  require(enc[104] == 6U, "addr family IPv6");
  // port 8788 = 0x2254 -> LE 0x54, 0x22
  require(enc[121] == 0x54U && enc[122] == 0x22U, "port LE");
  const auto dec = must(EndpointDescriptor::decode(enc), "decode 256B max endpoint");
  require(dec == max_ep, "256B endpoint roundtrip");

  // Mixed V4 + V6 round-trip
  const EndpointDescriptor mixed_ep{
      TransportKind::iroh_quic,
      "https://relay.multiplayer.tech:8443",
      {
          DirectAddrV4{{198U, 51U, 100U, 7U}, 4433U},
          DirectAddrV6{
              {0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9U}, 9001U},
      },
  };
  const auto mixed_enc = must(mixed_ep.encode(), "encode mixed");
  require(must(EndpointDescriptor::decode(mixed_enc), "decode mixed") == mixed_ep,
          "mixed roundtrip");

  // Relay URL SSRF / grammar rejections
  const std::array<std::string_view, 15> bad_urls = {
      "http://relay.multiplayer.tech",
      "https://127.0.0.1",
      "https://2130706433",
      "https://0x7f.1",
      "https://localhost:9222",
      "https://169.254.169.254",
      "https://a.-b.c",
      "https://relay.multiplayer.tech:443",
      "https://relay.multiplayer.tech/path",
      "https://relay.multiplayer.tech?q=1",
      "https://relay.multiplayer.tech#frag",
      "https://user@relay.multiplayer.tech",
      "https://RELAY.multiplayer.tech",
      "https://relay.multiplayer.tech:0",
      "https://relay.multiplayer.tech:08443",
  };
  for (const std::string_view bad : bad_urls) {
    expect_err(validate_relay_url(bad), MpError::invalid_relay_url, "bad relay url");
  }
  const std::string relay_101 = relay_100 + "x";
  expect_err(validate_relay_url(relay_101), MpError::invalid_relay_url,
             "101B relay url");

  // DirectAddr filtering
  const EndpointDescriptor loopback_ep{
      TransportKind::direct_quic,
      "",
      {DirectAddrV4{{127U, 0U, 0U, 1U}, 53U}},
  };
  expect_err(loopback_ep.validate(), MpError::disallowed_direct_addr, "loopback v4");
  const EndpointDescriptor v4_mapped_ep{
      TransportKind::direct_quic,
      "",
      {DirectAddrV6{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xffU, 0xffU, 1U, 2U, 3U, 4U},
                    8788U}},
  };
  expect_err(v4_mapped_ep.validate(), MpError::disallowed_direct_addr, "v4-mapped v6");

  const EndpointDescriptor lan_ep{
      TransportKind::direct_quic,
      "",
      {DirectAddrV4{{10U, 0U, 0U, 5U}, 8788U}},
  };
  must_void(lan_ep.validate_against_policy(RelayPolicy::no_relays, ""),
            "LAN allowed under no_relays");
  expect_err(lan_ep.validate_against_policy(RelayPolicy::allow_relays, ""),
             MpError::disallowed_direct_addr, "LAN rejected under allow_relays");

  // force_relays enforcement
  expect_err(max_ep.validate_against_policy(RelayPolicy::force_relays, relay_100),
             MpError::force_relays_violation, "force_relays rejects direct_count > 0");
  const EndpointDescriptor relay_only{
      TransportKind::iroh_quic,
      "https://relay.multiplayer.tech",
      {},
  };
  must_void(relay_only.validate_against_policy(RelayPolicy::force_relays,
                                               "https://relay.multiplayer.tech"),
            "force_relays accepts matching relay_only");
  expect_err(relay_only.validate_against_policy(RelayPolicy::force_relays,
                                                "https://other.multiplayer.tech"),
             MpError::force_relays_violation, "force_relays rejects mismatched relay");
  expect_err(relay_only.validate_against_policy(RelayPolicy::no_relays, ""),
             MpError::no_relays_violation, "no_relays rejects relay_url");

  // Malformed binary decode rejections
  std::vector<std::uint8_t> oversize(kMaxEndpointDescriptorBytes + 1U, 0U);
  expect_err(EndpointDescriptor::decode(oversize), MpError::endpoint_too_large,
             ">256B endpoint");
  auto with_trail = mixed_enc;
  with_trail.push_back(0x00U);
  expect_err(EndpointDescriptor::decode(with_trail), MpError::endpoint_trailing_bytes,
             "trailing byte endpoint");
  auto truncated = mixed_enc;
  truncated.pop_back();
  expect_err(EndpointDescriptor::decode(truncated), MpError::endpoint_truncated,
             "truncated endpoint");
  auto bad_kind = mixed_enc;
  bad_kind[0] = 9U;
  expect_err(EndpointDescriptor::decode(bad_kind), MpError::invalid_transport_kind,
             "bad transport kind");
  const std::array<std::uint8_t, 5> bad_count = {1U, 0U, 0U, 9U, 0U};
  expect_err(EndpointDescriptor::decode(bad_count), MpError::too_many_direct_addrs,
             "direct_count > 8");
}

void test_mp1_all_opcodes_and_limits() {
  g_stage = "mp1_all_opcodes";

  const auto acct1 = must(AccountId::create(1001U), "acct1");
  const auto acct2 = must(AccountId::create(1002U), "acct2");
  const auto dev1 = must(DeviceId::create(2001U), "dev1");
  const auto dev2 = must(DeviceId::create(2002U), "dev2");
  const auto party1 = must(PartyId::create(3001U), "party1");
  const auto pinv1 = must(PartyInviteId::create(4001U), "pinv1");
  const auto sess1 = must(SessionId::create(5001U), "sess1");
  const auto req1 = must(RequestId::create(6001U), "req1");

  const EndpointDescriptor ep{
      TransportKind::iroh_quic,
      "https://relay.multiplayer.tech",
      {DirectAddrV4{{198U, 51U, 100U, 42U}, 4433U}},
  };

  Ed25519PubKey root_pk{};
  root_pk.fill(0x11U);
  Ed25519PubKey dev_pk{};
  dev_pk.fill(0x22U);
  const PartyMemberRecord member1{dev1, acct1, root_pk, dev_pk, {0xd2U, 0x84U, 0x43U},
                                  ep,   1U,    true};
  // Multi-device same-account party member (08ad6c1): same acct1, distinct dev2!
  const PartyMemberRecord member2{dev2, acct1, root_pk, dev_pk, {0xd2U, 0x84U, 0x43U},
                                  ep,   2U,    false};

  const std::vector<Mp1Message> all_messages = {
      HelloAckMessage{sess1, 1795430000123ULL, 20000U},
      ErrorMessage{77U, 4003U, 1500U},
      PresenceSetMessage{PresenceVisibility::busy, true},
      PresenceSnapshotMessage{{
          PresenceEntry{acct1, PresenceVisibility::online, party1, 1795430000100ULL},
          PresenceEntry{acct2, PresenceVisibility::idle, std::nullopt,
                        1795430000200ULL},
      }},
      PresenceDeltaMessage{PresenceEntry{acct2, PresenceVisibility::invisible,
                                         std::nullopt, 1795430000300ULL}},
      SocialEventMessage{SocialEventKind::friend_accepted, acct2},
      PartyInviteNotifyMessage{pinv1, party1, acct2, 1795430600000ULL},
      PartySnapshotMessage{
          party1,
          5U,
          acct1,
          dev1,
          PartyVisibility::friends,
          PartyJoinMode::approval_required,
          RelayPolicy::allow_relays,
          4U,
          "https://relay.multiplayer.tech",
          {member1, member2},
      },
      PartyMemberJoinedMessage{6U, member2},
      PartyEndpointUpdateMessage{ep},
      PartyMemberUpdatedMessage{7U, dev2, true, {0xaaU, 0xbbU, 0xccU}, ep},
      PartyMemberLeftMessage{8U, dev2, acct1, MemberLeaveReason::device_revoked},
      PartyLeaderChangedMessage{9U, acct2, dev2,
                                PartyLeaderChangeReason::auto_migrated},
      PartyJoinRequestEventMessage{req1, acct2, dev2, root_pk, dev_pk},
      PartyDisbandedMessage{10U, PartyDisbandReason::empty_timeout},
  };

  require(all_messages.size() == 15U, "all 15 MP1 opcodes tested");
  std::uint32_t seq = 100U;
  for (const auto &msg : all_messages) {
    const auto wire = must(encode_frame(seq, msg), "encode_frame");
    require(wire.size() >= kMp1HeaderBytes && wire.size() <= kMaxMp1FrameBytes,
            "frame size bounds");
    require(wire[0] == kMp1Version, "header version");
    require(wire[1] == 0U, "header flags == 0");
    require(wire[4] == 0U && wire[5] == 0U && wire[6] == 0U && wire[7] == 0U,
            "header reserved == 0");
    const auto decoded = must(decode_frame(wire), "decode_frame");
    require(decoded.header.opcode == opcode_of(msg), "header opcode match");
    require(decoded.header.seq == seq, "header seq match");
    require(decoded.header.payload_len == wire.size() - kMp1HeaderBytes,
            "header payload_len exact");
    require(decoded.message == msg, "message roundtrip equality");
    ++seq;
  }

  // Exact worst-case 12-member PartySnapshot = 7415 bytes (parity with
  // protocol_oracles.rs:596!)
  const std::string relay_100 = "https://" + std::string(34U, 'r') + "." +
                                std::string(34U, 's') + ".relay.multiplayer.tech";
  require(relay_100.size() == 100U, "relay_100 size");
  const EndpointDescriptor max_ep{
      TransportKind::iroh_quic,
      relay_100,
      std::vector<DirectAddr>(kMaxDirectAddrs,
                              DirectAddrV6{{0x20U, 0x01U, 0x0dU, 0xb8U, 0, 0, 0, 0, 0,
                                            0, 0, 0, 0, 0, 0, 1U},
                                           9000U}),
  };
  std::vector<PartyMemberRecord> max_members;
  max_members.reserve(kMaxPartyMembers);
  for (std::uint64_t i = 1U; i <= kMaxPartyMembers; ++i) {
    Ed25519PubKey rpk{};
    rpk.fill(static_cast<std::uint8_t>(i));
    Ed25519PubKey dpk{};
    dpk.fill(static_cast<std::uint8_t>(i + 100U));
    max_members.push_back(PartyMemberRecord{
        must(DeviceId::create(1000U + i), "max dev"),
        must(AccountId::create(2000U + i), "max acct"),
        rpk,
        dpk,
        std::vector<std::uint8_t>(kMaxCwtBytes, 0xaaU),
        max_ep,
        i,
        true,
    });
  }
  const Mp1Message max_snap = PartySnapshotMessage{
      must(PartyId::create(999999U), "max party"),
      42U,
      must(AccountId::create(2001U), "leader acct"),
      must(DeviceId::create(1001U), "leader dev"),
      PartyVisibility::private_party,
      PartyJoinMode::invite_only,
      RelayPolicy::allow_relays,
      12U,
      relay_100,
      max_members,
  };
  const auto max_snap_wire = must(encode_frame(7U, max_snap), "encode worst-case snap");
  require(max_snap_wire.size() == 7415U, "worst-case 12-member snapshot == 7415 bytes");
  const auto max_snap_dec = must(decode_frame(max_snap_wire), "decode worst-case snap");
  require(max_snap_dec.header.seq == 7U && max_snap_dec.message == max_snap,
          "worst-case snapshot roundtrip");

  // 256-entry PresenceSnapshot fits strictly under 8192B
  std::vector<PresenceEntry> max_pres;
  max_pres.reserve(kMaxPresenceEntries);
  for (std::uint64_t i = 1U; i <= kMaxPresenceEntries; ++i) {
    max_pres.push_back(PresenceEntry{
        must(AccountId::create(i), "pres acct"),
        PresenceVisibility::online,
        must(PartyId::create(5000U + i), "pres party"),
        1795430000000ULL,
    });
  }
  const Mp1Message pres_msg = PresenceSnapshotMessage{max_pres};
  const auto pres_wire = must(encode_frame(1U, pres_msg), "encode 256 presence");
  require(pres_wire.size() <= kMaxMp1FrameBytes, "256 presence <= 8192B");
  require(must(decode_frame(pres_wire), "decode 256 presence").message == pres_msg,
          "256 presence roundtrip");

  // Header & framing negative tests
  std::vector<std::uint8_t> oversize(kMaxMp1FrameBytes + 1U, 0U);
  expect_err(decode_frame(oversize), MpError::mp1_frame_too_large, ">8192 frame");
  std::vector<std::uint8_t> short_hdr(15U, 0U);
  expect_err(decode_frame(short_hdr), MpError::mp1_truncated, "<16B header");

  const auto err_wire = must(encode_frame(5U, ErrorMessage{1U, 2U, 3U}), "err wire");
  auto bad_ver = err_wire;
  bad_ver[0] = 2U;
  expect_err(decode_frame(bad_ver), MpError::mp1_unsupported_version, "bad version");
  auto bad_flags = err_wire;
  bad_flags[1] = 1U;
  expect_err(decode_frame(bad_flags), MpError::mp1_non_zero_flags, "non-zero flags");
  auto bad_res = err_wire;
  bad_res[4] = 1U;
  expect_err(decode_frame(bad_res), MpError::mp1_non_zero_reserved,
             "non-zero reserved");
  auto bad_op = err_wire;
  bad_op[2] = 0x99U;
  bad_op[3] = 0x99U;
  expect_err(decode_frame(bad_op), MpError::mp1_unknown_opcode, "unknown opcode");
  auto trailing_outside_len = err_wire;
  trailing_outside_len.push_back(0U);
  expect_err(decode_frame(trailing_outside_len), MpError::mp1_length_mismatch,
             "trailing byte length mismatch");
  auto trailing_inside_len = err_wire;
  trailing_inside_len.push_back(0U);
  trailing_inside_len[12] = static_cast<std::uint8_t>(trailing_inside_len[12] + 1U);
  expect_err(decode_frame(trailing_inside_len), MpError::mp1_trailing_bytes,
             "trailing byte inside payload_len");

  // Duplicate device_id in PartySnapshot rejected; members > max_members rejected
  const Mp1Message dup_dev_snap = PartySnapshotMessage{
      party1,
      1U,
      acct1,
      dev1,
      PartyVisibility::private_party,
      PartyJoinMode::invite_only,
      RelayPolicy::allow_relays,
      4U,
      "",
      {member1, member1},
  };
  expect_err(encode_frame(1U, dup_dev_snap), MpError::mp1_invalid_count,
             "duplicate device_id rejected");

  const Mp1Message over_max_snap = PartySnapshotMessage{
      party1,
      1U,
      acct1,
      dev1,
      PartyVisibility::private_party,
      PartyJoinMode::invite_only,
      RelayPolicy::allow_relays,
      2U,
      relay_100,
      std::vector<PartyMemberRecord>(max_members.begin(), max_members.begin() + 3),
  };
  expect_err(encode_frame(1U, over_max_snap), MpError::mp1_invalid_count,
             "members > max_members rejected");

  // Out-of-range IDs in wire frame rejected (0 and 2^53)
  auto social_wire =
      must(encode_frame(1U, SocialEventMessage{SocialEventKind::friend_request, acct1}),
           "social wire");
  for (std::size_t i = 0U; i < 8U; ++i) {
    social_wire[kMp1HeaderBytes + 1U + i] = 0U;
  }
  expect_err(decode_frame(social_wire), MpError::id_zero, "wire ID 0 rejected");
  social_wire[kMp1HeaderBytes + 1U + 6U] = 0x20U; // 2^53 = 1 << 53
  expect_err(decode_frame(social_wire), MpError::mp1_safe_int_exceeded,
             "wire ID 2^53 rejected");

  // Client-role opcode allowlist
  require(opcode_allowed_from_client(Opcode::presence_set, SocketRole::account),
          "account client allows presence_set");
  require(!opcode_allowed_from_client(Opcode::presence_delta, SocketRole::account),
          "account client forbids server opcode");
  require(opcode_allowed_from_client(Opcode::party_endpoint_update, SocketRole::party),
          "party client allows endpoint_update");
  require(!opcode_allowed_from_client(Opcode::presence_set, SocketRole::party),
          "party client forbids account opcode");
}

void test_rfc9421_and_rfc9530() {
  g_stage = "rfc9421_rfc9530";

  const auto sk = test_signing_key(13U);
  const Ed25519PubKey pk = sk.public_key();
  const std::int64_t now = 1795430000;
  const std::string_view nonce = "AbCdEfGhIjKlMnOpQrStUvWx";

  const auto acct = must(AccountId::create(1001U), "acct");
  const auto dev = must(DeviceId::create(2002U), "dev");
  const KeyId dev_keyid = DeviceKeyId{acct, dev};

  // 1. POST with JSON body + RFC 9530 Content-Digest
  const auto body =
      to_bytes(R"({"visibility":0,"join_mode":0,"relay_policy":1,"max_members":8})");
  const auto signed_post = must(sign_rfc9421_request(sk,
                                                     Rfc9421SignRequest{
                                                         HttpMethod::post,
                                                         "api.multiplayer.tech",
                                                         "/v1/parties",
                                                         "?",
                                                         "application/json",
                                                         body,
                                                         dev_keyid,
                                                         now - 5,
                                                         now + 55,
                                                         nonce,
                                                     }),
                                "sign POST");
  const std::string &post_cd = must_opt(signed_post.content_digest, "POST digest");
  require(post_cd.starts_with("sha-256=:"), "RFC 9530 digest format");

  const Rfc9421Request post_req{
      HttpMethod::post,
      "api.multiplayer.tech",
      "/v1/parties",
      "?",
      "application/json",
      post_cd,
      false,
      body,
      signed_post.signature_input,
      signed_post.signature,
  };
  const auto verified =
      must(verify_rfc9421_request({post_req, "api.multiplayer.tech", pk, now}),
           "verify POST");
  require(verified.keyid == dev_keyid, "verified keyid");
  require(verified.nonce == nonce, "verified nonce");
  require(verified.retain_until_ms == (now + 55) * 1000 + 5000,
          "exact retain_until_ms");

  // Mutate single byte of body -> ContentDigestMismatch
  auto bad_body = body;
  bad_body[2] ^= 0x01U;
  auto bad_body_req = post_req;
  bad_body_req.body = bad_body;
  expect_err(verify_rfc9421_request({bad_body_req, "api.multiplayer.tech", pk, now}),
             MpError::rfc9421_content_digest_mismatch, "tampered body");

  // Non-JSON Content-Type rejected -> rfc9421_missing_content_type
  auto non_json_req = post_req;
  non_json_req.content_type = "text/plain";
  expect_err(verify_rfc9421_request({non_json_req, "api.multiplayer.tech", pk, now}),
             MpError::rfc9421_missing_content_type, "non-JSON content-type rejected");
  expect_err(sign_rfc9421_request(sk,
                                  Rfc9421SignRequest{
                                      HttpMethod::post,
                                      "api.multiplayer.tech",
                                      "/v1/parties",
                                      "?",
                                      "text/plain",
                                      body,
                                      dev_keyid,
                                      now - 5,
                                      now + 55,
                                      nonce,
                                  }),
             MpError::rfc9421_missing_content_type, "signer rejects non-JSON");

  // Tampered JSON Content-Type parameter -> invalid_signature
  auto tampered_ct_req = post_req;
  tampered_ct_req.content_type = "application/json; charset=utf-8";
  expect_err(verify_rfc9421_request({tampered_ct_req, "api.multiplayer.tech", pk, now}),
             MpError::invalid_signature, "tampered content-type parameter");

  // Validly signed APPLICATION/JSON; charset=utf-8 accepted (case-insensitive media
  // type)
  const auto json_param_signed =
      must(sign_rfc9421_request(sk,
                                Rfc9421SignRequest{
                                    HttpMethod::post,
                                    "api.multiplayer.tech",
                                    "/v1/parties",
                                    "?",
                                    "APPLICATION/JSON; charset=utf-8",
                                    body,
                                    dev_keyid,
                                    now - 5,
                                    now + 55,
                                    nonce,
                                }),
           "sign JSON charset");
  const Rfc9421Request json_param_req{
      HttpMethod::post,
      "api.multiplayer.tech",
      "/v1/parties",
      "?",
      "APPLICATION/JSON; charset=utf-8",
      must_opt(json_param_signed.content_digest, "json charset digest"),
      false,
      body,
      json_param_signed.signature_input,
      json_param_signed.signature,
  };
  must(verify_rfc9421_request({json_param_req, "api.multiplayer.tech", pk, now}),
       "verify APPLICATION/JSON; charset=utf-8");

  // Content-Encoding forbidden
  auto ce_req = post_req;
  ce_req.has_content_encoding = true;
  expect_err(verify_rfc9421_request({ce_req, "api.multiplayer.tech", pk, now}),
             MpError::rfc9421_content_encoding_forbidden, "Content-Encoding rejected");

  // Wrong authority rejected
  expect_err(verify_rfc9421_request({post_req, "evil.example.com", pk, now}),
             MpError::rfc9421_invalid_authority, "wrong authority");

  // 2. GET WebSocket upgrade (bodyless, 4 covered components, auto-generated CSPRNG
  // nonce)
  const auto signed_ws = must(sign_rfc9421_request(sk,
                                                   Rfc9421SignRequest{
                                                       HttpMethod::get,
                                                       "api.multiplayer.tech",
                                                       "/v1/ws",
                                                       "?",
                                                       std::nullopt,
                                                       {},
                                                       RootKeyId{acct},
                                                       now,
                                                       now + 60,
                                                       "",
                                                   }),
                              "sign GET WS");
  require(!signed_ws.content_digest.has_value(), "GET has no content_digest");
  require(signed_ws.nonce.size() == 32U, "auto CSPRNG nonce 32 base64url chars");
  const Rfc9421Request ws_req{
      HttpMethod::get,
      "api.multiplayer.tech",
      "/v1/ws",
      "?",
      std::nullopt,
      std::nullopt,
      false,
      {},
      signed_ws.signature_input,
      signed_ws.signature,
  };
  const auto verified_ws =
      must(verify_rfc9421_request({ws_req, "api.multiplayer.tech", pk, now}),
           "verify GET WS");
  require(verified_ws.keyid == KeyId{RootKeyId{acct}}, "root keyid verified");

  // 3. Registration keyid binds cryptographically to sha256(pubkey)[..16]
  const auto reg_kid = must(registration_key_id_for_pubkey(pk), "reg keyid");
  const auto signed_reg = must(sign_rfc9421_request(sk,
                                                    Rfc9421SignRequest{
                                                        HttpMethod::post,
                                                        "api.multiplayer.tech",
                                                        "/v1/accounts/register",
                                                        "?",
                                                        "application/json",
                                                        body,
                                                        reg_kid,
                                                        now,
                                                        now + 60,
                                                        nonce,
                                                    }),
                               "sign register");
  const Rfc9421Request reg_req{
      HttpMethod::post,
      "api.multiplayer.tech",
      "/v1/accounts/register",
      "?",
      "application/json",
      must_opt(signed_reg.content_digest, "reg digest"),
      false,
      body,
      signed_reg.signature_input,
      signed_reg.signature,
  };
  must(verify_rfc9421_request({reg_req, "api.multiplayer.tech", pk, now}),
       "verify register");
  const auto other_pk = test_signing_key(99U).public_key();
  expect_err(verify_rfc9421_request({reg_req, "api.multiplayer.tech", other_pk, now}),
             MpError::rfc9421_invalid_key_id, "reg keyid mismatch rejected");

  // 4. Expired short window vs clock skew
  const auto exp_signed = must(sign_rfc9421_request(sk,
                                                    Rfc9421SignRequest{
                                                        HttpMethod::post,
                                                        "api.multiplayer.tech",
                                                        "/v1/parties",
                                                        "?",
                                                        "application/json",
                                                        body,
                                                        dev_keyid,
                                                        now - 10,
                                                        now - 9,
                                                        nonce,
                                                    }),
                               "sign expired");
  const Rfc9421Request exp_req{
      HttpMethod::post,
      "api.multiplayer.tech",
      "/v1/parties",
      "?",
      "application/json",
      must_opt(exp_signed.content_digest, "exp digest"),
      false,
      body,
      exp_signed.signature_input,
      exp_signed.signature,
  };
  expect_err(verify_rfc9421_request({exp_req, "api.multiplayer.tech", pk, now}),
             MpError::rfc9421_expired, "short expired window -> expired");
  expect_err(verify_rfc9421_request({post_req, "api.multiplayer.tech", pk, now - 66}),
             MpError::rfc9421_clock_skew, "created > now + 60 -> clock_skew");
  expect_err(verify_rfc9421_request({post_req, "api.multiplayer.tech", pk, now + 66}),
             MpError::rfc9421_clock_skew, "created < now - 60 & expired -> clock_skew");

  // Unauthenticated forged signature + drifted/expired timestamp MUST fail with
  // invalid_signature (never leaking clock_skew/expired as an existence oracle)!
  expect_err(
      verify_rfc9421_request({post_req, "api.multiplayer.tech", other_pk, now - 66}),
      MpError::invalid_signature, "forged sig + future created -> invalid_signature");
  expect_err(
      verify_rfc9421_request({post_req, "api.multiplayer.tech", other_pk, now + 66}),
      MpError::invalid_signature, "forged sig + past created -> invalid_signature");
  expect_err(verify_rfc9421_request({exp_req, "api.multiplayer.tech", other_pk, now}),
             MpError::invalid_signature, "forged sig + expired -> invalid_signature");

  // 5. Query signing & path hygiene
  const auto q_signed = must(sign_rfc9421_request(sk,
                                                  Rfc9421SignRequest{
                                                      HttpMethod::get,
                                                      "api.multiplayer.tech",
                                                      "/v1/accounts/resolve",
                                                      "?handle=alice",
                                                      std::nullopt,
                                                      {},
                                                      dev_keyid,
                                                      now,
                                                      now + 60,
                                                      nonce,
                                                  }),
                             "sign resolve");
  Rfc9421Request q_req{
      HttpMethod::get,
      "api.multiplayer.tech",
      "/v1/accounts/resolve",
      "?handle=alice",
      std::nullopt,
      std::nullopt,
      false,
      {},
      q_signed.signature_input,
      q_signed.signature,
  };
  must(verify_rfc9421_request({q_req, "api.multiplayer.tech", pk, now}),
       "verify resolve");
  q_req.query = "?handle=bob";
  expect_err(verify_rfc9421_request({q_req, "api.multiplayer.tech", pk, now}),
             MpError::invalid_signature, "tampered query rejected");

  expect_err(validate_path_and_query({HttpMethod::get, "/v1/ws", "?token=secret"}),
             MpError::rfc9421_query_not_allowed, "query on /v1/ws rejected");
  expect_err(validate_path_and_query({HttpMethod::get, "/v1/../admin", "?"}),
             MpError::rfc9421_invalid_path, "dotdot path");
  expect_err(validate_path_and_query({HttpMethod::get, "/v1//parties", "?"}),
             MpError::rfc9421_invalid_path, "double slash");
  expect_err(validate_path_and_query({HttpMethod::get, "/v1/parties/1%2f2", "?"}),
             MpError::rfc9421_invalid_path, "percent in path");
  must_void(validate_path_and_query(
                {HttpMethod::get, "/v1/parties/42/requests", "?cursor=1"}),
            "requests cursor allowed on GET");
  expect_err(validate_path_and_query(
                 {HttpMethod::post, "/v1/parties/42/requests", "?cursor=1"}),
             MpError::rfc9421_query_not_allowed, "requests cursor forbidden on POST");

  // 6. Independent RFC 8941 canonicalization oracle (extra SP & leading-zero int)
  const std::string canon_params =
      "(\"@method\" \"@authority\" \"@path\" \"@query\");created=" +
      std::to_string(now - 10) + ";expires=" + std::to_string(now + 110) + ";nonce=\"" +
      std::string{nonce} + "\";keyid=\"1001.2002\";alg=\"ed25519\";tag=\"mp1\"";
  const std::string indep_base = "\"@method\": GET\n"
                                 "\"@authority\": api.multiplayer.tech\n"
                                 "\"@path\": /v1/accounts/resolve\n"
                                 "\"@query\": ?handle=al%69ce\n"
                                 "\"@signature-params\": " +
                                 canon_params;
  const auto indep_base_bytes = to_bytes(indep_base);
  const auto indep_sig_raw = must(sk.sign(indep_base_bytes), "sign indep");
  // Encode signature using sign_rfc9421_request's header format verification via
  // parse_signature_header round-trip.
  const auto canon_signed = must(sign_rfc9421_request(sk,
                                                      Rfc9421SignRequest{
                                                          HttpMethod::get,
                                                          "api.multiplayer.tech",
                                                          "/v1/accounts/resolve",
                                                          "?handle=al%69ce",
                                                          std::nullopt,
                                                          {},
                                                          dev_keyid,
                                                          now - 10,
                                                          now + 110,
                                                          nonce,
                                                      }),
                                 "sign canonical oracle");
  require(canon_signed.signature_base == indep_base_bytes,
          "exact RFC 9421 canonical signature base byte parity");
  require(must(parse_signature_header(canon_signed.signature), "parse sig hdr") ==
              indep_sig_raw,
          "signature header exact parity");

  const std::string two_space_in =
      "mp1=(\"@method\"  \"@authority\" \"@path\" \"@query\");created=" +
      std::to_string(now - 10) + ";expires=" + std::to_string(now + 110) + ";nonce=\"" +
      std::string{nonce} + "\";keyid=\"1001.2002\";alg=\"ed25519\";tag=\"mp1\"";
  const std::string lead_zero_in =
      "mp1=(\"@method\" \"@authority\" \"@path\" \"@query\");created=0" +
      std::to_string(now - 10) + ";expires=" + std::to_string(now + 110) + ";nonce=\"" +
      std::string{nonce} + "\";keyid=\"1001.2002\";alg=\"ed25519\";tag=\"mp1\"";
  for (const std::string_view variant :
       {std::string_view{two_space_in}, std::string_view{lead_zero_in}}) {
    const Rfc9421Request v_req{
        HttpMethod::get,
        "api.multiplayer.tech",
        "/v1/accounts/resolve",
        "?handle=al%69ce",
        std::nullopt,
        std::nullopt,
        false,
        {},
        variant,
        canon_signed.signature,
    };
    must(verify_rfc9421_request({v_req, "api.multiplayer.tech", pk, now}),
         "canonical variant verifies");
  }
}

void test_cbor_cose_sign1_and_device_cwt() {
  g_stage = "cose_sign1_cwt";

  const auto root_sk = test_signing_key(7U);
  const Ed25519PubKey root_pk = root_sk.public_key();
  const auto dev_sk = test_signing_key(42U);
  const Ed25519PubKey dev_pk = dev_sk.public_key();
  const auto other_sk = test_signing_key(99U);
  const Ed25519PubKey other_pk = other_sk.public_key();

  const std::int64_t now = 1795430000;
  const std::int64_t exp = now + kMaxCwtTtlSecs;

  const auto cwt =
      must(encode_device_cwt(root_sk, DeviceCwtMintRequest{dev_pk, now, exp}),
           "encode_device_cwt");
  require(cwt.size() <= kMaxCwtBytes, "CWT size <= 256B");
  // Exact Tag 18 + array(4) + h'A10132' + {} prefix
  const std::array<std::uint8_t, 7> expected_prefix = {0xd2U, 0x84U, 0x43U, 0xa1U,
                                                       0x01U, 0x32U, 0xa0U};
  require(cwt.size() > expected_prefix.size() &&
              std::memcmp(cwt.data(), expected_prefix.data(), expected_prefix.size()) ==
                  0,
          "exact COSE_Sign1 Ed25519 (-19) prefix");

  // Verify CWT claims & zero-RTT verify_party_member_cwt helper
  const auto claims =
      must(verify_device_cwt(DeviceCwtVerifyRequest{cwt, root_pk, dev_pk, now + 10}),
           "verify_device_cwt");
  require(claims.device_pubkey == dev_pk, "claims device_pubkey");
  require(claims.iat == now, "claims iat");
  require(claims.exp == exp, "claims exp");
  require(claims.iss == hex_lower(must(sha256(root_pk), "root sha256")), "claims iss");

  const PartyMemberRecord member{
      must(DeviceId::create(55U), "member dev"),
      must(AccountId::create(11U), "member acct"),
      root_pk,
      dev_pk,
      cwt,
      EndpointDescriptor{
          TransportKind::iroh_quic, "https://relay.multiplayer.tech", {}},
      1U,
      true,
  };
  const auto peer_claims =
      must(verify_party_member_cwt(member, now + 10), "verify_party_member_cwt");
  require(peer_claims == claims, "zero-RTT peer helper claims match");

  // Wrong root key rejected
  expect_err(verify_device_cwt(DeviceCwtVerifyRequest{cwt, other_pk, dev_pk, now + 10}),
             MpError::invalid_signature, "wrong root key");

  // Wrong expected device key rejected
  expect_err(
      verify_device_cwt(DeviceCwtVerifyRequest{cwt, root_pk, other_pk, now + 10}),
      MpError::cwt_device_key_mismatch, "device key mismatch");

  // Expired at exact exp rejected (now < exp required)
  expect_err(verify_device_cwt(DeviceCwtVerifyRequest{cwt, root_pk, dev_pk, exp}),
             MpError::cwt_expired, "expired at exp");

  // Future iat > now + 60s rejected
  expect_err(verify_device_cwt(DeviceCwtVerifyRequest{cwt, root_pk, dev_pk, now - 61}),
             MpError::cwt_future_issued_at, "future iat");

  // Tampered payload claim byte rejected (fails Ed25519 signature!)
  auto tampered = cwt;
  tampered[20] ^= 0x01U;
  expect_err(verify_device_cwt(DeviceCwtVerifyRequest{tampered, root_pk, dev_pk, now}),
             MpError::invalid_signature, "tampered claim byte");

  // Trailing byte rejected
  auto with_trail = cwt;
  with_trail.push_back(0x00U);
  expect_err(
      verify_device_cwt(DeviceCwtVerifyRequest{with_trail, root_pk, dev_pk, now + 10}),
      MpError::cwt_invalid_cbor, "trailing byte");

  // TTL > 30d and INT64_MIN overflow rejected on encode
  expect_err(encode_device_cwt(root_sk, DeviceCwtMintRequest{dev_pk, now, exp + 1}),
             MpError::cwt_ttl_exceeded, "TTL > 30d");
  expect_err(
      encode_device_cwt(
          root_sk,
          DeviceCwtMintRequest{dev_pk, std::numeric_limits<std::int64_t>::min(), 0}),
      MpError::cwt_invalid_claims, "iat INT64_MIN");

  // Stripped Tag 18 (untagged COSE_Sign1) rejected
  const std::span<const std::uint8_t> untagged{cwt.data() + 1U, cwt.size() - 1U};
  expect_err(verify_device_cwt(DeviceCwtVerifyRequest{untagged, root_pk, dev_pk, now}),
             MpError::cwt_invalid_envelope_shape, "untagged COSE_Sign1");

  // Deprecated polymorphic EdDSA (-8) protected header h'A10127' MUST be rejected!
  auto legacy_eddsa = cwt;
  legacy_eddsa[5] = 0x27U; // {1: -8} instead of {1: -19} (0x32)
  expect_err(verify_device_cwt(
                 DeviceCwtVerifyRequest{legacy_eddsa, root_pk, std::nullopt, now}),
             MpError::cwt_invalid_protected_header, "deprecated EdDSA (-8) rejected");

  // Non-empty unprotected header rejected
  std::vector<std::uint8_t> non_empty_unprot = {0xd2U, 0x84U, 0x43U, 0xa1U,
                                                0x01U, 0x32U, 0xa1U, 0x04U,
                                                0x41U, 0x01U, 0x40U, 0x40U};
  expect_err(verify_device_cwt(
                 DeviceCwtVerifyRequest{non_empty_unprot, root_pk, std::nullopt, now}),
             MpError::cwt_non_empty_unprotected_header, "non-empty unprotected header");
}

void test_rust_mp_protocol_bit_exact_parity() {
  g_stage = "rust_mp_protocol_bit_exact_parity";

  // Exact golden vectors emitted by ../multiplayer_site/crates/mp-protocol (commit
  // 08ad6c1) for deterministic seeds, timestamps, EndpointDescriptor, PartySnapshot,
  // COSE_Sign1 (-19) CWT, and RFC 9421 + RFC 9530 signatures.
  const auto root_sk = test_signing_key(7U);
  const auto dev_sk = test_signing_key(42U);
  const std::int64_t now = 1795430000;
  const std::int64_t exp = now + kMaxCwtTtlSecs;

  const auto cwt = must(
      encode_device_cwt(root_sk, DeviceCwtMintRequest{dev_sk.public_key(), now, exp}),
      "parity cwt");
  static constexpr std::string_view kRustCwtHex =
      "d28443a10132a0587da4017840666538313263313266336162346365366163356462363961633335"
      "32663930366362316231316566343366623333653235326566376666353532323633383839041a6b"
      "2ba370061a6b04167008a101a4010103322006215820197f6b23e16c8532c6abc838facd5ea789be"
      "0c76b2920334039bfa8b3d368d615840bfc85932d013d37bbfbdec8c15afbeaf2055a46f185920a9"
      "0dab323e666944582507bbb00c88f5662ce881e950e5c122cc4a2b43b0885e8e9bf8faff0eef0c0"
      "7";
  require(hex_lower(cwt) == kRustCwtHex, "CWT COSE_Sign1 (-19) bit-exact Rust parity");

  const EndpointDescriptor ep{
      TransportKind::iroh_quic,
      "https://relay.multiplayer.tech",
      {DirectAddrV4{{198U, 51U, 100U, 42U}, 4433U}},
  };
  const auto ep_bytes = must(ep.encode(), "parity ep");
  static constexpr std::string_view kRustEpHex =
      "011e0068747470733a2f2f72656c61792e6d756c7469706c617965722e746563680104c633642a51"
      "11";
  require(hex_lower(ep_bytes) == kRustEpHex,
          "EndpointDescriptor bit-exact Rust parity");

  const Mp1Message snap = PartySnapshotMessage{
      must(PartyId::create(3001U), "pid"),
      5U,
      must(AccountId::create(1001U), "aid"),
      must(DeviceId::create(2001U), "did"),
      PartyVisibility::friends,
      PartyJoinMode::approval_required,
      RelayPolicy::allow_relays,
      4U,
      "https://relay.multiplayer.tech",
      {PartyMemberRecord{
          must(DeviceId::create(2001U), "mdid"),
          must(AccountId::create(1001U), "maid"),
          root_sk.public_key(),
          dev_sk.public_key(),
          cwt,
          ep,
          1U,
          true,
      }},
  };
  const auto snap_frame = must(encode_frame(77U, snap), "parity snap");
  static constexpr std::string_view kRustSnapHex =
      "01000102000000004d00000093010000b90b0000000000000500000000000000e903000000000000"
      "d107000000000000010100041e0068747470733a2f2f72656c61792e6d756c7469706c617965722e"
      "7465636801d107000000000000e903000000000000ea4a6c63e29c520abef5507b132ec5f9954776"
      "aebebe7b92421eea691446d22c197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa"
      "8b3d368d61c800d28443a10132a0587da40178406665383132633132663361623463653661633564"
      "62363961633335326639303663623162313165663433666233336532353265663766663535323236"
      "33383839041a6b2ba370061a6b04167008a101a4010103322006215820197f6b23e16c8532c6abc8"
      "38facd5ea789be0c76b2920334039bfa8b3d368d615840bfc85932d013d37bbfbdec8c15afbeaf20"
      "55a46f185920a90dab323e666944582507bbb00c88f5662ce881e950e5c122cc4a2b43b0885e8e9b"
      "f8faff0eef0c072900011e0068747470733a2f2f72656c61792e6d756c7469706c617965722e7465"
      "63680104c633642a5111010000000000000001";
  require(hex_lower(snap_frame) == kRustSnapHex,
          "MP1 PartySnapshot frame bit-exact Rust parity");

  const auto sk = test_signing_key(13U);
  const auto body =
      to_bytes(R"({"visibility":0,"join_mode":0,"relay_policy":1,"max_members":8})");
  const auto signed_post =
      must(sign_rfc9421_request(sk,
                                Rfc9421SignRequest{
                                    HttpMethod::post,
                                    "api.multiplayer.tech",
                                    "/v1/parties",
                                    "?",
                                    "application/json",
                                    body,
                                    DeviceKeyId{must(AccountId::create(1001U), "a"),
                                                must(DeviceId::create(2002U), "d")},
                                    now - 5,
                                    now + 55,
                                    "AbCdEfGhIjKlMnOpQrStUvWx",
                                }),
           "parity rfc9421");
  require(must_opt(signed_post.content_digest, "parity cd") ==
              "sha-256=:IarzQYCJWBDZgjjVa8X7JiRGjYGVs9C9ZnMuk7oDdH4=:",
          "RFC 9530 Content-Digest bit-exact Rust parity");
  const auto sig_raw =
      must(parse_signature_header(signed_post.signature), "parity sig");
  static constexpr std::string_view kRustSigHex =
      "dd507ccb0e3d78398d5fbcf5f7a41782e9e78dfb5e357e07b2c8c09f25a50b2ffba6044a81e6c53b"
      "c7104b38e5b3baad08da83202cde00f9ee1f7400a050410b";
  require(hex_lower(sig_raw) == kRustSigHex,
          "RFC 9421 Ed25519 signature bit-exact Rust parity");
}

void test_official_multiplayer_site_test_vectors() {
  g_stage = "official_multiplayer_site_test_vectors";

  // Bit-exact verification of EVERY field in
  // ../multiplayer_site/docs/TEST_VECTORS.json
  // (schema: "multiplayer.tech/mp1-interop-vectors/v1").

  // -------------------------------------------------------------------------
  // 1. keys
  // -------------------------------------------------------------------------
  static constexpr std::string_view kRootSeedHex =
      "1111111111111111111111111111111111111111111111111111111111111111";
  static constexpr std::string_view kRootPubkeyHex =
      "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
  static constexpr std::string_view kRootPubkeyB64 =
      "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";
  static constexpr std::string_view kRootPubkeySha256Hex =
      "10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d";
  static constexpr std::string_view kDeviceSeedHex =
      "2222222222222222222222222222222222222222222222222222222222222222";
  static constexpr std::string_view kDevicePubkeyHex =
      "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
  static constexpr std::string_view kDevicePubkeyB64 =
      "oJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/5ODRVpPA=";

  const auto root_seed_vec = from_hex(kRootSeedHex);
  require(root_seed_vec.size() == 32U, "root_seed_hex 32 bytes");
  Ed25519Seed root_seed{};
  std::memcpy(root_seed.data(), root_seed_vec.data(), root_seed.size());
  const auto root_sk = must(Ed25519SigningKey::from_seed(root_seed), "vector root_sk");
  const Ed25519PubKey root_pk = root_sk.public_key();
  require(hex_lower(root_pk) == kRootPubkeyHex, "root_pubkey_hex bit-exact");
  require(encode_base64(root_pk, false) == kRootPubkeyB64, "root_pubkey_b64 bit-exact");
  const auto root_pk_sha = must(sha256(root_pk), "root_pubkey sha256");
  require(hex_lower(root_pk_sha) == kRootPubkeySha256Hex,
          "root_pubkey_sha256_hex bit-exact");

  const auto dev_seed_vec = from_hex(kDeviceSeedHex);
  require(dev_seed_vec.size() == 32U, "device_seed_hex 32 bytes");
  Ed25519Seed dev_seed{};
  std::memcpy(dev_seed.data(), dev_seed_vec.data(), dev_seed.size());
  const auto dev_sk = must(Ed25519SigningKey::from_seed(dev_seed), "vector dev_sk");
  const Ed25519PubKey dev_pk = dev_sk.public_key();
  require(hex_lower(dev_pk) == kDevicePubkeyHex, "device_pubkey_hex bit-exact");
  require(encode_base64(dev_pk, false) == kDevicePubkeyB64,
          "device_pubkey_b64 bit-exact");

  // -------------------------------------------------------------------------
  // 2. cwt_rfc8392_8747_9052_9864
  // -------------------------------------------------------------------------
  static constexpr std::string_view kProtectedHeaderHex = "a10132";
  static constexpr std::int64_t kCwtIat = 1795430000;
  static constexpr std::int64_t kCwtExp = 1795516400;
  static constexpr std::string_view kCwtHex =
      "d28443a10132a0587da4017840313062613638326338616431333531333937316538623536383831"
      "61616238626437303262623830373739366563613831393332633733356139346436653664041a6b"
      "0567f0061a6b04167008a101a4010103322006215820a09aa5f47a6759802ff955f8dc2d2a14a5c9"
      "9d23be97f864127ff9383455a4f05840b20a888785f9231d828f91f597aa97bca878133b3c39940e"
      "cf5b99ec925c4b39625b5c6387042a957f9d963ca64fa87675a79276e6eeecda917435fbc470130"
      "a";
  static constexpr std::string_view kCwtB64 =
      "0oRDoQEyoFh9pAF4QDEwYmE2ODJjOGFkMTM1MTM5NzFlOGI1Njg4MWFhYjhiZDcwMmJiODA3Nzk2ZWNh"
      "ODE5MzJjNzM1YTk0ZDZlNmQEGmsFZ/"
      "AGGmsEFnAIoQGkAQEDMiAGIVggoJql9HpnWYAv+VX43C0qFKXJnSO+l/hkEn/"
      "5ODRVpPBYQLIKiIeF+SMdgo+R9Zeql7yoeBM7PDmUDs9bmeySXEs5YltcY4cEKpV/"
      "nZY8pk+odnWnknbm7uzakXQ1+8RwEwo=";

  require(hex_lower(kProtectedHeaderEd25519) == kProtectedHeaderHex,
          "CWT protected_header_hex bit-exact");
  const auto cwt =
      must(encode_device_cwt(root_sk, DeviceCwtMintRequest{dev_pk, kCwtIat, kCwtExp}),
           "vector encode_device_cwt");
  require(hex_lower(cwt) == kCwtHex, "cwt_hex bit-exact");
  require(encode_base64(cwt, false) == kCwtB64, "cwt_b64 bit-exact");

  const auto cwt_from_vector = from_hex(kCwtHex);
  const auto cwt_claims = must(verify_device_cwt(DeviceCwtVerifyRequest{
                                   cwt_from_vector, root_pk, dev_pk, kCwtIat + 10}),
                               "verify_device_cwt succeeds at iat + 10");
  require(cwt_claims.iss == kRootPubkeySha256Hex, "cwt_claims.iss exact");
  require(cwt_claims.iat == kCwtIat, "cwt_claims.iat exact");
  require(cwt_claims.exp == kCwtExp, "cwt_claims.exp exact");
  require(cwt_claims.device_pubkey == dev_pk, "cwt_claims.device_pubkey exact");

  expect_err(verify_device_cwt(
                 DeviceCwtVerifyRequest{cwt_from_vector, root_pk, dev_pk, kCwtExp}),
             MpError::cwt_expired, "verify_device_cwt fails at exact exp");

  // -------------------------------------------------------------------------
  // 3. rfc9421_post
  // -------------------------------------------------------------------------
  const auto acct_1001 = must(AccountId::create(1001U), "acct 1001");
  const auto dev_2002 = must(DeviceId::create(2002U), "dev 2002");
  const KeyId vec_keyid = DeviceKeyId{acct_1001, dev_2002};
  static constexpr std::string_view kVecNonce = "TestVectorNonce_0123456789";
  static constexpr std::int64_t kSigCreated = 1795430000;
  static constexpr std::int64_t kSigExpires = 1795430060;

  static constexpr std::string_view kPostBodyUtf8 =
      R"({"visibility":1,"join_mode":0,"relay_policy":1,"max_members":4})";
  static constexpr std::string_view kPostContentDigest =
      "sha-256=:CTtRXZLZ2jZoHv2drxk62oLpXDmmq2jn8kkFuvucCy4=:";
  static constexpr std::string_view kPostSigInput =
      R"(mp1=("@method" "@authority" "@path" "@query" "content-type" "content-digest");created=1795430000;expires=1795430060;nonce="TestVectorNonce_0123456789";keyid="1001.2002";alg="ed25519";tag="mp1")";
  static constexpr std::string_view kPostSigBaseUtf8 =
      "\"@method\": POST\n"
      "\"@authority\": api.multiplayer.tech\n"
      "\"@path\": /v1/parties\n"
      "\"@query\": ?\n"
      "\"content-type\": application/json\n"
      "\"content-digest\": sha-256=:CTtRXZLZ2jZoHv2drxk62oLpXDmmq2jn8kkFuvucCy4=:\n"
      "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" \"@query\" "
      "\"content-type\" "
      "\"content-digest\");created=1795430000;expires=1795430060;nonce="
      "\"TestVectorNonce_0123456789\";keyid=\"1001.2002\";alg=\"ed25519\";tag=\"mp1\"";
  static constexpr std::string_view kPostSignature =
      "mp1=:"
      "obnKgHzwjYrBahN4ajTDHCChV+TrAafRv30dGlAe3yrMBDBclS2yQFA7ZlIkFy1KRjJ2hsBxGGoN3SUs"
      "ZN6nDw==:";

  const auto post_body = to_bytes(kPostBodyUtf8);
  const auto signed_post = must(sign_rfc9421_request(dev_sk,
                                                     Rfc9421SignRequest{
                                                         HttpMethod::post,
                                                         "api.multiplayer.tech",
                                                         "/v1/parties",
                                                         "?",
                                                         "application/json",
                                                         post_body,
                                                         vec_keyid,
                                                         kSigCreated,
                                                         kSigExpires,
                                                         kVecNonce,
                                                     }),
                                "vector sign rfc9421_post");
  require(must_opt(signed_post.content_digest, "post content_digest") ==
              kPostContentDigest,
          "rfc9421_post content_digest bit-exact");
  require(signed_post.signature_input == kPostSigInput,
          "rfc9421_post signature_input bit-exact");
  require(signed_post.signature_base == to_bytes(kPostSigBaseUtf8),
          "rfc9421_post signature_base_utf8 bit-exact");
  require(signed_post.signature == kPostSignature, "rfc9421_post signature bit-exact");

  const Rfc9421Request post_req{
      HttpMethod::post,   "api.multiplayer.tech", "/v1/parties", "?",
      "application/json", kPostContentDigest,     false,         post_body,
      kPostSigInput,      kPostSignature,
  };
  const auto verified_post =
      must(verify_rfc9421_request(
               {post_req, "api.multiplayer.tech", dev_pk, kSigCreated + 10}),
           "vector verify rfc9421_post");
  require(verified_post.keyid == vec_keyid, "verified_post keyid");
  require(verified_post.nonce == kVecNonce, "verified_post nonce");
  require(verified_post.created == kSigCreated, "verified_post created");
  require(verified_post.expires == kSigExpires, "verified_post expires");

  // -------------------------------------------------------------------------
  // 4. rfc9421_get_query
  // -------------------------------------------------------------------------
  static constexpr std::string_view kGetSigInput =
      R"(mp1=("@method" "@authority" "@path" "@query");created=1795430000;expires=1795430060;nonce="TestVectorNonce_0123456789";keyid="1001.2002";alg="ed25519";tag="mp1")";
  static constexpr std::string_view kGetSigBaseUtf8 =
      "\"@method\": GET\n"
      "\"@authority\": api.multiplayer.tech\n"
      "\"@path\": /v1/accounts/resolve\n"
      "\"@query\": ?handle=patrick\n"
      "\"@signature-params\": (\"@method\" \"@authority\" \"@path\" "
      "\"@query\");created=1795430000;expires=1795430060;nonce="
      "\"TestVectorNonce_0123456789\";keyid=\"1001.2002\";alg=\"ed25519\";tag=\"mp1\"";
  static constexpr std::string_view kGetSignature =
      "mp1=:"
      "ECNkruW957tQidzvYxPzgZra6s5J97WrI+UawuBOiLU4Qj9zlyaf2BPsKdAwk8Kb3+FGesXMd1qLHQbC"
      "U0ytDA==:";

  const auto signed_get = must(sign_rfc9421_request(dev_sk,
                                                    Rfc9421SignRequest{
                                                        HttpMethod::get,
                                                        "api.multiplayer.tech",
                                                        "/v1/accounts/resolve",
                                                        "?handle=patrick",
                                                        std::nullopt,
                                                        {},
                                                        vec_keyid,
                                                        kSigCreated,
                                                        kSigExpires,
                                                        kVecNonce,
                                                    }),
                               "vector sign rfc9421_get_query");
  require(!signed_get.content_digest.has_value(),
          "rfc9421_get_query has no content_digest");
  require(signed_get.signature_input == kGetSigInput,
          "rfc9421_get_query signature_input bit-exact");
  require(signed_get.signature_base == to_bytes(kGetSigBaseUtf8),
          "rfc9421_get_query signature_base_utf8 bit-exact");
  require(signed_get.signature == kGetSignature,
          "rfc9421_get_query signature bit-exact");

  const Rfc9421Request get_req{
      HttpMethod::get,
      "api.multiplayer.tech",
      "/v1/accounts/resolve",
      "?handle=patrick",
      std::nullopt,
      std::nullopt,
      false,
      {},
      kGetSigInput,
      kGetSignature,
  };
  const auto verified_get =
      must(verify_rfc9421_request(
               {get_req, "api.multiplayer.tech", dev_pk, kSigCreated + 10}),
           "vector verify rfc9421_get_query");
  require(verified_get.keyid == vec_keyid, "verified_get keyid");
  require(verified_get.nonce == kVecNonce, "verified_get nonce");

  // -------------------------------------------------------------------------
  // 5. endpoint_descriptors
  // -------------------------------------------------------------------------
  static constexpr std::string_view kEpForceRelaysIrohHex =
      "011e0068747470733a2f2f72656c61792e6d756c7469706c617965722e7465636800";
  static constexpr std::string_view kEpNoRelaysLanV4Hex = "02000001040a00002a5422";

  const EndpointDescriptor ep_force{
      TransportKind::iroh_quic,
      "https://relay.multiplayer.tech",
      {},
  };
  const auto ep_force_enc = must(ep_force.encode(), "encode force_relays_iroh");
  require(hex_lower(ep_force_enc) == kEpForceRelaysIrohHex,
          "force_relays_iroh_hex encode bit-exact");
  const auto ep_force_dec =
      must(EndpointDescriptor::decode(from_hex(kEpForceRelaysIrohHex)),
           "decode force_relays_iroh");
  require(ep_force_dec == ep_force, "force_relays_iroh_hex decode exact");
  must_void(ep_force_dec.validate_against_policy(RelayPolicy::force_relays,
                                                 "https://relay.multiplayer.tech"),
            "force_relays_iroh policy valid");

  const EndpointDescriptor ep_lan{
      TransportKind::direct_quic,
      "",
      {DirectAddrV4{{10U, 0U, 0U, 42U}, 8788U}},
  };
  const auto ep_lan_enc = must(ep_lan.encode(), "encode no_relays_lan_v4");
  require(hex_lower(ep_lan_enc) == kEpNoRelaysLanV4Hex,
          "no_relays_lan_v4_hex encode bit-exact");
  const auto ep_lan_dec =
      must(EndpointDescriptor::decode(from_hex(kEpNoRelaysLanV4Hex)),
           "decode no_relays_lan_v4");
  require(ep_lan_dec == ep_lan, "no_relays_lan_v4_hex decode exact");
  must_void(ep_lan_dec.validate_against_policy(RelayPolicy::no_relays, ""),
            "no_relays_lan_v4 policy valid");

  // -------------------------------------------------------------------------
  // 6. mp1_frames
  // -------------------------------------------------------------------------
  static constexpr std::string_view kHelloAckHex =
      "010001000000000000000000140000000903000000000000fba5f707a2010000204e0000";
  static constexpr std::string_view kPresenceSetHex =
      "010001010000000001000000020000000101";
  static constexpr std::string_view kPartyEndpointUpdateHex =
      "01000302000000000200000022000000011e0068747470733a2f2f72656c61792e6d756c7469706c"
      "617965722e7465636800";
  static constexpr std::string_view kPartySnapshot1MemberHex =
      "0100010200000000000000008c01000089130000000000000100000000000000e903000000000000"
      "d207000000000000010101041e0068747470733a2f2f72656c61792e6d756c7469706c617965722e"
      "7465636801d207000000000000e903000000000000d04ab232742bb4ab3a1368bd4615e4e6d0224a"
      "b71a016baf8520a332c9778737a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9"
      "383455a4f0c800d28443a10132a0587da40178403130626136383263386164313335313339373165"
      "38623536383831616162386264373032626238303737393665636138313933326337333561393464"
      "36653664041a6b0567f0061a6b04167008a101a4010103322006215820a09aa5f47a6759802ff955"
      "f8dc2d2a14a5c99d23be97f864127ff9383455a4f05840b20a888785f9231d828f91f597aa97bca8"
      "78133b3c39940ecf5b99ec925c4b39625b5c6387042a957f9d963ca64fa87675a79276e6eeecda91"
      "7435fbc470130a2200011e0068747470733a2f2f72656c61792e6d756c7469706c617965722e7465"
      "636800010000000000000001";

  // 6a. HELLO_ACK
  const Mp1Message hello_msg = HelloAckMessage{
      must(SessionId::create(777U), "sess 777"), 1795430000123ULL, 20000U};
  const auto hello_enc = must(encode_frame(0U, hello_msg), "encode hello_ack");
  require(hex_lower(hello_enc) == kHelloAckHex, "hello_ack_hex encode bit-exact");
  const auto hello_dec = must(decode_frame(from_hex(kHelloAckHex)), "decode hello_ack");
  require(hello_dec.header.opcode == Opcode::hello_ack && hello_dec.header.seq == 0U &&
              hello_dec.message == hello_msg,
          "hello_ack_hex decode exact");

  // 6b. PRESENCE_SET
  const Mp1Message pres_msg = PresenceSetMessage{PresenceVisibility::online, true};
  const auto pres_enc = must(encode_frame(1U, pres_msg), "encode presence_set");
  require(hex_lower(pres_enc) == kPresenceSetHex, "presence_set_hex encode bit-exact");
  const auto pres_dec =
      must(decode_frame(from_hex(kPresenceSetHex)), "decode presence_set");
  require(pres_dec.header.opcode == Opcode::presence_set && pres_dec.header.seq == 1U &&
              pres_dec.message == pres_msg,
          "presence_set_hex decode exact");

  // 6c. PARTY_ENDPOINT_UPDATE
  const Mp1Message ep_upd_msg = PartyEndpointUpdateMessage{ep_force};
  const auto ep_upd_enc =
      must(encode_frame(2U, ep_upd_msg), "encode party_endpoint_update");
  require(hex_lower(ep_upd_enc) == kPartyEndpointUpdateHex,
          "party_endpoint_update_hex encode bit-exact");
  const auto ep_upd_dec = must(decode_frame(from_hex(kPartyEndpointUpdateHex)),
                               "decode party_endpoint_update");
  require(ep_upd_dec.header.opcode == Opcode::party_endpoint_update &&
              ep_upd_dec.header.seq == 2U && ep_upd_dec.message == ep_upd_msg,
          "party_endpoint_update_hex decode exact");

  // 6d. PARTY_SNAPSHOT (1 member)
  const auto party_5001 = must(PartyId::create(5001U), "party 5001");
  const PartyMemberRecord vec_member{
      dev_2002, acct_1001, root_pk, dev_pk, cwt, ep_force, 1U, true,
  };
  const Mp1Message snap_msg = PartySnapshotMessage{
      party_5001,
      1U,
      acct_1001,
      dev_2002,
      PartyVisibility::friends,
      PartyJoinMode::approval_required,
      RelayPolicy::force_relays,
      4U,
      "https://relay.multiplayer.tech",
      {vec_member},
  };
  const auto snap_enc =
      must(encode_frame(0U, snap_msg), "encode party_snapshot_1member");
  require(hex_lower(snap_enc) == kPartySnapshot1MemberHex,
          "party_snapshot_1member_hex encode bit-exact");
  const auto snap_dec = must(decode_frame(from_hex(kPartySnapshot1MemberHex)),
                             "decode party_snapshot_1member");
  require(snap_dec.header.opcode == Opcode::party_snapshot &&
              snap_dec.header.seq == 0U && snap_dec.message == snap_msg,
          "party_snapshot_1member_hex decode exact");
  const auto *decoded_snap = std::get_if<PartySnapshotMessage>(&snap_dec.message);
  require(decoded_snap != nullptr && decoded_snap->members.size() == 1U,
          "decoded party_snapshot has 1 member");
  must(verify_party_member_cwt(decoded_snap->members[0], kCwtIat + 10),
       "decoded snapshot member CWT verifies");

  // -------------------------------------------------------------------------
  // 7. invite_hashes
  // -------------------------------------------------------------------------
  static constexpr std::string_view kRawSecretHex =
      "3333333333333333333333333333333333333333333333333333333333333333";
  static constexpr std::string_view kAccountInviteToken =
      "mpinv1_MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
  static constexpr std::string_view kAccountInviteSha256Hex =
      "32a3f48e3d5130d7c813b5032809943bd29ac3fa1dd9ac0b02d1e49f8ca4db12";
  static constexpr std::string_view kPartyInviteLink =
      "mppi1_5001_MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM";
  static constexpr std::string_view kPartyInviteSha256Hex =
      "bf3dff455be4a5ae1a611a037d6e62dcf3d3a83bbb132b430dfa898e511ca34d";

  const auto raw_secret_vec = from_hex(kRawSecretHex);
  require(raw_secret_vec.size() == 32U, "raw_secret_hex 32 bytes");
  std::array<std::uint8_t, 32> raw_secret{};
  std::memcpy(raw_secret.data(), raw_secret_vec.data(), raw_secret.size());

  const std::string raw_secret_b64url = encode_base64(raw_secret, true);
  require(("mpinv1_" + raw_secret_b64url) == kAccountInviteToken,
          "account_invite_token bit-exact");
  require(("mppi1_5001_" + raw_secret_b64url) == kPartyInviteLink,
          "party_invite_link bit-exact");

  const auto acct_inv_hash =
      must(hash_account_invite_secret(raw_secret), "vector hash_account_invite_secret");
  require(hex_lower(acct_inv_hash) == kAccountInviteSha256Hex,
          "account_invite_sha256_hex bit-exact");

  const auto party_inv_hash = must(hash_party_invite_secret(party_5001, raw_secret),
                                   "vector hash_party_invite_secret");
  require(hex_lower(party_inv_hash) == kPartyInviteSha256Hex,
          "party_invite_sha256_hex bit-exact");
}

} // namespace

int main() {
  try {
    test_safe_ids_and_handles();
    test_ed25519_rfc8032_and_strict_rejections();
    test_endpoint_descriptor_codec_and_policies();
    test_mp1_all_opcodes_and_limits();
    test_rfc9421_and_rfc9530();
    test_cbor_cose_sign1_and_device_cwt();
    test_rust_mp_protocol_bit_exact_parity();
    test_official_multiplayer_site_test_vectors();
    std::cout << "mp_protocol_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "mp_protocol_test FAILED: " << ex.what() << "\n";
    return 1;
  }
}
