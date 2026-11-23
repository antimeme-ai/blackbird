#ifndef BLACKBIRD_P2P_ABI_H
#define BLACKBIRD_P2P_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BB_P2P_ABI_VERSION 1U
#define BB_P2P_PUBKEY_LEN 32U
#define BB_P2P_SECRET_KEY_LEN 32U
#define BB_P2P_MAX_CONTROL_FRAME_BYTES (64U * 1024U)
#define BB_P2P_MAX_CAUSAL_FRAME_BYTES (4U * 1024U * 1024U)
#define BB_P2P_MAX_EPHEMERAL_FRAME_BYTES 1200U
#define BB_P2P_MAX_RELAY_URL_BYTES 100U
#define BB_P2P_MAX_DIRECT_ADDRS 8U
#define BB_P2P_MAX_ALLOWED_PEERS 1024U

typedef struct BbP2pEndpoint BbP2pEndpoint;

typedef enum BbP2pStatus {
  BB_P2P_OK = 0,
  BB_P2P_ERR_NULL_POINTER = 1,
  BB_P2P_ERR_INVALID_ARG = 2,
  BB_P2P_ERR_POLICY_VIOLATION = 3,
  BB_P2P_ERR_NOT_ALLOWED = 4,
  BB_P2P_ERR_NOT_CONNECTED = 5,
  BB_P2P_ERR_FRAME_TOO_LARGE = 6,
  BB_P2P_ERR_TIMEOUT = 7,
  BB_P2P_ERR_CLOSED = 8,
  BB_P2P_ERR_TRANSPORT = 9,
  BB_P2P_ERR_CAPACITY = 10,
  BB_P2P_ERR_PANIC = 11,
  BB_P2P_ERR_UNSUPPORTED = 12
} BbP2pStatus;

typedef enum BbP2pRelayPolicy {
  BB_P2P_ALLOW_RELAYS = 0,
  BB_P2P_FORCE_RELAYS = 1,
  BB_P2P_NO_RELAYS = 2
} BbP2pRelayPolicy;

typedef enum BbP2pLane {
  BB_P2P_LANE_CONTROL = 0,
  BB_P2P_LANE_CAUSAL = 1,
  BB_P2P_LANE_EPHEMERAL = 2
} BbP2pLane;

typedef enum BbP2pEventKind {
  BB_P2P_EVENT_NONE = 0,
  BB_P2P_EVENT_PEER_CONNECTED = 1,
  BB_P2P_EVENT_PEER_DISCONNECTED = 2,
  BB_P2P_EVENT_FRAME_RECEIVED = 3
} BbP2pEventKind;

typedef struct BbP2pDirectAddr {
  uint8_t family; /* 4 = IPv4, 6 = IPv6 */
  uint8_t ip[16]; /* IPv4 uses ip[0..3] with ip[4..15]=0; IPv6 uses ip[0..15] */
  uint16_t port;  /* host byte order */
} BbP2pDirectAddr;

typedef struct BbP2pCreateConfig {
  uint32_t abi_version;      /* MUST equal BB_P2P_ABI_VERSION */
  uint32_t relay_policy;     /* BbP2pRelayPolicy */
  const uint8_t *secret_key; /* optional 32B Ed25519 seed; NULL = ephemeral CSPRNG */
  const char *relay_url;     /* optional https:// origin; REQUIRED for FORCE_RELAYS */
  size_t relay_url_len;      /* byte length of relay_url (<= 100) */
} BbP2pCreateConfig;

typedef struct BbP2pPeerTarget {
  uint8_t pubkey[BB_P2P_PUBKEY_LEN];
  uint32_t remote_relay_policy;        /* BbP2pRelayPolicy */
  const char *relay_url;               /* optional https:// origin */
  size_t relay_url_len;                /* byte length of relay_url (<= 100) */
  const BbP2pDirectAddr *direct_addrs; /* optional direct UDP addresses */
  size_t direct_addrs_count;           /* <= BB_P2P_MAX_DIRECT_ADDRS */
  uint32_t connect_timeout_ms;         /* 0 = default (10000 ms) */
} BbP2pPeerTarget;

typedef struct BbP2pEvent {
  uint32_t kind; /* BbP2pEventKind */
  uint32_t lane; /* BbP2pLane (valid when kind == FRAME_RECEIVED) */
  uint8_t peer_pubkey[BB_P2P_PUBKEY_LEN];
  uint8_t *data; /* owned by caller; release with bb_p2p_free_bytes */
  size_t data_len;
  uint32_t reason_code; /* close/error code when kind == PEER_DISCONNECTED */
} BbP2pEvent;

BbP2pStatus bb_p2p_check_relay_policy(uint32_t local_policy, uint32_t remote_policy);

BbP2pStatus bb_p2p_create(const BbP2pCreateConfig *config, BbP2pEndpoint **out_handle);

void bb_p2p_destroy(BbP2pEndpoint *handle);

BbP2pStatus bb_p2p_local_pubkey(const BbP2pEndpoint *handle,
                                uint8_t out_pubkey[BB_P2P_PUBKEY_LEN]);

BbP2pStatus bb_p2p_local_direct_addrs(const BbP2pEndpoint *handle,
                                      BbP2pDirectAddr *out_addrs, size_t max_addrs,
                                      size_t *out_count);

BbP2pStatus bb_p2p_set_allowed_peers(BbP2pEndpoint *handle,
                                     const uint8_t *pubkeys_32b_ptr, size_t count);

BbP2pStatus bb_p2p_revoke_peer(BbP2pEndpoint *handle,
                               const uint8_t pubkey_32b[BB_P2P_PUBKEY_LEN]);

BbP2pStatus bb_p2p_connect_peer(BbP2pEndpoint *handle, const BbP2pPeerTarget *target);

BbP2pStatus bb_p2p_send_frame(BbP2pEndpoint *handle,
                              const uint8_t peer_pk[BB_P2P_PUBKEY_LEN], uint32_t lane,
                              const uint8_t *data, size_t len);

BbP2pStatus bb_p2p_poll_event(BbP2pEndpoint *handle, uint32_t timeout_ms,
                              BbP2pEvent *out_event);

void bb_p2p_free_bytes(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BLACKBIRD_P2P_ABI_H */
