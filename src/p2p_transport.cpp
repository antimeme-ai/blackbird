#include "blackbird/p2p_transport.hpp"

#include <cstring>
#include <new>
#include <utility>

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
#include "blackbird_p2p_abi.h"

extern "C" {
BbP2pStatus bb_p2p_set_lan_open_admission(BbP2pEndpoint *handle, uint8_t enabled);
BbP2pStatus bb_p2p_allow_peer(BbP2pEndpoint *handle,
                              const uint8_t pubkey_32b[BB_P2P_PUBKEY_LEN]);
}
#endif

namespace blackbird {

bool p2p_iroh_compiled_in() noexcept {
#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH
  return true;
#else
  return false;
#endif
}

std::size_t p2p_lane_max_frame_bytes(P2pLane lane) noexcept {
  switch (lane) {
  case P2pLane::control:
    return kP2pMaxControlFrameBytes;
  case P2pLane::causal:
    return kP2pMaxCausalFrameBytes;
  case P2pLane::ephemeral:
    return kP2pMaxEphemeralFrameBytes;
  }
  return 0;
}

std::string_view p2p_relay_policy_name(P2pRelayPolicy policy) noexcept {
  switch (policy) {
  case P2pRelayPolicy::allow_relays:
    return "allow_relays";
  case P2pRelayPolicy::force_relays:
    return "force_relays";
  case P2pRelayPolicy::no_relays:
    return "no_relays";
  }
  return "unknown";
}

std::string_view p2p_lane_name(P2pLane lane) noexcept {
  switch (lane) {
  case P2pLane::control:
    return "control";
  case P2pLane::causal:
    return "causal";
  case P2pLane::ephemeral:
    return "ephemeral";
  }
  return "unknown";
}

#if defined(BLACKBIRD_HAS_IROH) && BLACKBIRD_HAS_IROH

namespace {

Error map_status(BbP2pStatus status) noexcept {
  const auto detail = static_cast<std::int64_t>(status);
  switch (status) {
  case BB_P2P_OK:
    return {ErrorCode::external_unknown, 0};
  case BB_P2P_ERR_NULL_POINTER:
  case BB_P2P_ERR_INVALID_ARG:
    return {ErrorCode::invalid_range, detail};
  case BB_P2P_ERR_POLICY_VIOLATION:
    return {ErrorCode::conflict, detail};
  case BB_P2P_ERR_NOT_ALLOWED:
    return {ErrorCode::invalid_identity, detail};
  case BB_P2P_ERR_NOT_CONNECTED:
  case BB_P2P_ERR_TRANSPORT:
    return {ErrorCode::io, detail};
  case BB_P2P_ERR_FRAME_TOO_LARGE:
  case BB_P2P_ERR_CAPACITY:
    return {ErrorCode::capacity, detail};
  case BB_P2P_ERR_TIMEOUT:
    return {ErrorCode::busy, detail};
  case BB_P2P_ERR_CLOSED:
    return {ErrorCode::stale_handle, detail};
  case BB_P2P_ERR_PANIC:
    return {ErrorCode::external_unknown, detail};
  case BB_P2P_ERR_UNSUPPORTED:
    return {ErrorCode::unsupported, detail};
  }
  return {ErrorCode::external_unknown, detail};
}

BbP2pDirectAddr to_abi_addr(const P2pDirectAddr &addr) noexcept {
  BbP2pDirectAddr out{};
  out.family = addr.family;
  std::memcpy(out.ip, addr.ip.data(), addr.ip.size());
  out.port = addr.port;
  return out;
}

P2pDirectAddr from_abi_addr(const BbP2pDirectAddr &addr) noexcept {
  P2pDirectAddr out{};
  out.family = addr.family;
  std::memcpy(out.ip.data(), addr.ip, out.ip.size());
  out.port = addr.port;
  return out;
}

struct AbiBytesGuard {
  std::uint8_t *ptr = nullptr;
  std::size_t len = 0;

  ~AbiBytesGuard() {
    if (ptr != nullptr && len > 0) {
      bb_p2p_free_bytes(ptr, len);
    }
  }
};

} // namespace

P2pEndpoint::P2pEndpoint(BbP2pEndpoint *handle, P2pRelayPolicy relay_policy) noexcept
    : handle_(handle), relay_policy_(relay_policy) {}

P2pEndpoint::P2pEndpoint(P2pEndpoint &&other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)),
      relay_policy_(other.relay_policy_) {}

P2pEndpoint &P2pEndpoint::operator=(P2pEndpoint &&other) noexcept {
  if (this != &other) {
    close();
    handle_ = std::exchange(other.handle_, nullptr);
    relay_policy_ = other.relay_policy_;
  }
  return *this;
}

P2pEndpoint::~P2pEndpoint() { close(); }

void P2pEndpoint::close() noexcept {
  if (handle_ != nullptr) {
    BbP2pEndpoint *h = std::exchange(handle_, nullptr);
    bb_p2p_destroy(h);
  }
}

Result<P2pEndpoint> P2pEndpoint::create(const P2pEndpointConfig &config) {
  if (config.relay_url.size() > kP2pMaxRelayUrlBytes) {
    return Result<P2pEndpoint>::failure({ErrorCode::invalid_range});
  }

  BbP2pCreateConfig abi_cfg{};
  abi_cfg.abi_version = BB_P2P_ABI_VERSION;
  abi_cfg.relay_policy = static_cast<std::uint32_t>(config.relay_policy);
  abi_cfg.secret_key =
      config.secret_key.has_value() ? config.secret_key->data() : nullptr;
  abi_cfg.relay_url = config.relay_url.empty() ? nullptr : config.relay_url.data();
  abi_cfg.relay_url_len = config.relay_url.size();

  BbP2pEndpoint *raw_handle = nullptr;
  const BbP2pStatus status = bb_p2p_create(&abi_cfg, &raw_handle);
  if (status != BB_P2P_OK || raw_handle == nullptr) {
    return Result<P2pEndpoint>::failure(map_status(status));
  }
  return Result<P2pEndpoint>::success(P2pEndpoint{raw_handle, config.relay_policy});
}

Result<P2pPubkey> P2pEndpoint::local_pubkey() const {
  if (handle_ == nullptr) {
    return Result<P2pPubkey>::failure({ErrorCode::stale_handle});
  }
  P2pPubkey out{};
  const BbP2pStatus status = bb_p2p_local_pubkey(handle_, out.data());
  if (status != BB_P2P_OK) {
    return Result<P2pPubkey>::failure(map_status(status));
  }
  return Result<P2pPubkey>::success(out);
}

Result<std::vector<P2pDirectAddr>> P2pEndpoint::local_direct_addrs() const {
  if (handle_ == nullptr) {
    return Result<std::vector<P2pDirectAddr>>::failure({ErrorCode::stale_handle});
  }
  std::array<BbP2pDirectAddr, kP2pMaxDirectAddrs> buf{};
  std::size_t count = 0;
  const BbP2pStatus status =
      bb_p2p_local_direct_addrs(handle_, buf.data(), buf.size(), &count);
  if (status != BB_P2P_OK) {
    return Result<std::vector<P2pDirectAddr>>::failure(map_status(status));
  }
  const std::size_t copy_count = count < buf.size() ? count : buf.size();
  try {
    std::vector<P2pDirectAddr> out;
    out.reserve(copy_count);
    for (std::size_t i = 0; i < copy_count; ++i) {
      out.push_back(from_abi_addr(buf[i]));
    }
    return Result<std::vector<P2pDirectAddr>>::success(std::move(out));
  } catch (const std::bad_alloc &) {
    return Result<std::vector<P2pDirectAddr>>::failure({ErrorCode::allocation});
  }
}

Result<void> P2pEndpoint::set_allowed_peers(std::span<const P2pPubkey> peers) {
  if (handle_ == nullptr) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }
  if (peers.size() > kP2pMaxAllowedPeers) {
    return Result<void>::failure({ErrorCode::capacity});
  }
  static_assert(sizeof(P2pPubkey) == BB_P2P_PUBKEY_LEN);
  const std::uint8_t *flat_ptr =
      peers.empty() ? nullptr : reinterpret_cast<const std::uint8_t *>(peers.data());
  const BbP2pStatus status = bb_p2p_set_allowed_peers(handle_, flat_ptr, peers.size());
  if (status != BB_P2P_OK) {
    return Result<void>::failure(map_status(status));
  }
  return Result<void>::success();
}

Result<void> P2pEndpoint::allow_peer(const P2pPubkey &peer_pubkey) {
  if (handle_ == nullptr) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }
  const BbP2pStatus status = bb_p2p_allow_peer(handle_, peer_pubkey.data());
  if (status != BB_P2P_OK) {
    return Result<void>::failure(map_status(status));
  }
  return Result<void>::success();
}

Result<void> P2pEndpoint::set_lan_open_admission(bool enabled) {
  if (handle_ == nullptr) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }
  const BbP2pStatus status = bb_p2p_set_lan_open_admission(handle_, enabled ? 1U : 0U);
  if (status != BB_P2P_OK) {
    return Result<void>::failure(map_status(status));
  }
  return Result<void>::success();
}

Result<void> P2pEndpoint::revoke_peer(const P2pPubkey &peer_pubkey) {
  if (handle_ == nullptr) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }
  const BbP2pStatus status = bb_p2p_revoke_peer(handle_, peer_pubkey.data());
  if (status != BB_P2P_OK) {
    return Result<void>::failure(map_status(status));
  }
  return Result<void>::success();
}

Result<void> P2pEndpoint::connect_peer(const P2pPeerTarget &target) {
  if (handle_ == nullptr) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }
  if (!relay_policy_compatible(relay_policy_, target.remote_relay_policy)) {
    return Result<void>::failure(
        {ErrorCode::conflict, static_cast<std::int64_t>(BB_P2P_ERR_POLICY_VIOLATION)});
  }
  if (target.direct_addrs.size() > kP2pMaxDirectAddrs ||
      target.relay_url.size() > kP2pMaxRelayUrlBytes) {
    return Result<void>::failure({ErrorCode::invalid_range});
  }

  std::array<BbP2pDirectAddr, kP2pMaxDirectAddrs> abi_addrs{};
  for (std::size_t i = 0; i < target.direct_addrs.size(); ++i) {
    abi_addrs[i] = to_abi_addr(target.direct_addrs[i]);
  }

  BbP2pPeerTarget abi_target{};
  std::memcpy(abi_target.pubkey, target.pubkey.data(), target.pubkey.size());
  abi_target.remote_relay_policy =
      static_cast<std::uint32_t>(target.remote_relay_policy);
  abi_target.relay_url = target.relay_url.empty() ? nullptr : target.relay_url.data();
  abi_target.relay_url_len = target.relay_url.size();
  abi_target.direct_addrs = target.direct_addrs.empty() ? nullptr : abi_addrs.data();
  abi_target.direct_addrs_count = target.direct_addrs.size();
  abi_target.connect_timeout_ms = target.connect_timeout_ms;

  const BbP2pStatus status = bb_p2p_connect_peer(handle_, &abi_target);
  if (status != BB_P2P_OK) {
    return Result<void>::failure(map_status(status));
  }
  return Result<void>::success();
}

Result<void> P2pEndpoint::send_frame(const P2pPubkey &peer_pubkey, P2pLane lane,
                                     std::span<const std::uint8_t> payload) {
  if (handle_ == nullptr) {
    return Result<void>::failure({ErrorCode::stale_handle});
  }
  if (payload.size() > p2p_lane_max_frame_bytes(lane)) {
    return Result<void>::failure(
        {ErrorCode::capacity, static_cast<std::int64_t>(BB_P2P_ERR_FRAME_TOO_LARGE)});
  }
  const std::uint8_t *data_ptr = payload.empty() ? nullptr : payload.data();
  const BbP2pStatus status =
      bb_p2p_send_frame(handle_, peer_pubkey.data(), static_cast<std::uint32_t>(lane),
                        data_ptr, payload.size());
  if (status != BB_P2P_OK) {
    return Result<void>::failure(map_status(status));
  }
  return Result<void>::success();
}

Result<void> P2pEndpoint::send_frame(const P2pPubkey &peer_pubkey, P2pLane lane,
                                     std::string_view payload) {
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(payload.data());
  return send_frame(peer_pubkey, lane,
                    std::span<const std::uint8_t>{bytes, payload.size()});
}

Result<std::optional<P2pEvent>> P2pEndpoint::poll_event(std::uint32_t timeout_ms) {
  if (handle_ == nullptr) {
    return Result<std::optional<P2pEvent>>::failure({ErrorCode::stale_handle});
  }
  BbP2pEvent raw{};
  const BbP2pStatus status = bb_p2p_poll_event(handle_, timeout_ms, &raw);
  AbiBytesGuard guard{raw.data, raw.data_len};

  if (status == BB_P2P_ERR_TIMEOUT) {
    return Result<std::optional<P2pEvent>>::success(std::nullopt);
  }
  if (status != BB_P2P_OK) {
    return Result<std::optional<P2pEvent>>::failure(map_status(status));
  }

  P2pEvent ev{};
  switch (raw.kind) {
  case BB_P2P_EVENT_NONE:
    return Result<std::optional<P2pEvent>>::success(std::nullopt);
  case BB_P2P_EVENT_PEER_CONNECTED:
    ev.kind = P2pEventKind::peer_connected;
    break;
  case BB_P2P_EVENT_PEER_DISCONNECTED:
    ev.kind = P2pEventKind::peer_disconnected;
    break;
  case BB_P2P_EVENT_FRAME_RECEIVED:
    ev.kind = P2pEventKind::frame_received;
    break;
  default:
    return Result<std::optional<P2pEvent>>::failure({ErrorCode::corrupt});
  }

  switch (raw.lane) {
  case BB_P2P_LANE_CONTROL:
    ev.lane = P2pLane::control;
    break;
  case BB_P2P_LANE_CAUSAL:
    ev.lane = P2pLane::causal;
    break;
  case BB_P2P_LANE_EPHEMERAL:
    ev.lane = P2pLane::ephemeral;
    break;
  default:
    return Result<std::optional<P2pEvent>>::failure({ErrorCode::corrupt});
  }

  std::memcpy(ev.peer_pubkey.data(), raw.peer_pubkey, ev.peer_pubkey.size());
  ev.reason_code = raw.reason_code;

  if (raw.data_len > 0) {
    if (raw.data == nullptr) {
      return Result<std::optional<P2pEvent>>::failure({ErrorCode::corrupt});
    }
    try {
      ev.payload.assign(raw.data, raw.data + raw.data_len);
    } catch (const std::bad_alloc &) {
      return Result<std::optional<P2pEvent>>::failure({ErrorCode::allocation});
    }
  }

  return Result<std::optional<P2pEvent>>::success(std::move(ev));
}

#else

P2pEndpoint::P2pEndpoint(BbP2pEndpoint *handle, P2pRelayPolicy relay_policy) noexcept
    : handle_(handle), relay_policy_(relay_policy) {}

P2pEndpoint::P2pEndpoint(P2pEndpoint &&other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)),
      relay_policy_(other.relay_policy_) {}

P2pEndpoint &P2pEndpoint::operator=(P2pEndpoint &&other) noexcept {
  if (this != &other) {
    close();
    handle_ = std::exchange(other.handle_, nullptr);
    relay_policy_ = other.relay_policy_;
  }
  return *this;
}

P2pEndpoint::~P2pEndpoint() { close(); }

void P2pEndpoint::close() noexcept { handle_ = nullptr; }

Result<P2pEndpoint> P2pEndpoint::create(const P2pEndpointConfig & /*config*/) {
  return Result<P2pEndpoint>::failure({ErrorCode::unsupported});
}

Result<P2pPubkey> P2pEndpoint::local_pubkey() const {
  return Result<P2pPubkey>::failure({ErrorCode::unsupported});
}

Result<std::vector<P2pDirectAddr>> P2pEndpoint::local_direct_addrs() const {
  return Result<std::vector<P2pDirectAddr>>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::set_allowed_peers(std::span<const P2pPubkey> /*peers*/) {
  return Result<void>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::allow_peer(const P2pPubkey & /*peer_pubkey*/) {
  return Result<void>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::set_lan_open_admission(bool /*enabled*/) {
  return Result<void>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::revoke_peer(const P2pPubkey & /*peer_pubkey*/) {
  return Result<void>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::connect_peer(const P2pPeerTarget & /*target*/) {
  return Result<void>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::send_frame(const P2pPubkey & /*peer_pubkey*/,
                                     P2pLane /*lane*/,
                                     std::span<const std::uint8_t> /*payload*/) {
  return Result<void>::failure({ErrorCode::unsupported});
}

Result<void> P2pEndpoint::send_frame(const P2pPubkey &peer_pubkey, P2pLane lane,
                                     std::string_view payload) {
  const auto *bytes = reinterpret_cast<const std::uint8_t *>(payload.data());
  return send_frame(peer_pubkey, lane,
                    std::span<const std::uint8_t>{bytes, payload.size()});
}

Result<std::optional<P2pEvent>> P2pEndpoint::poll_event(std::uint32_t /*timeout_ms*/) {
  return Result<std::optional<P2pEvent>>::failure({ErrorCode::unsupported});
}

#endif

} // namespace blackbird
