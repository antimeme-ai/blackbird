//! Panic-safe C-ABI staticlib wrapping `iroh` v1.5.0 for Blackbird P2P parties.
//!
//! Security & framing contract:
//! - QUIC (RFC 9000) + TLS 1.3 Mutual Raw Public Keys (RFC 7250, Ed25519).
//! - 0-RTT disabled (`max_tls_tickets(0)` + full 1-RTT accept handshake).
//! - RFC 9221 Unreliable Datagrams explicitly enabled (Lane 2, <= 1200 B).
//! - Zero N0 public pkarr / DNS address publication (`presets::Minimal`).
//! - ALPN `"blackbird-mp/1"`.
//! - Non-downgradeable relay policy (`ALLOW_RELAYS`, `FORCE_RELAYS`, `NO_RELAYS`).
//! - Mandatory peer allowlist enforced in `EndpointHooks` + accept loop before any
//!   streams or datagrams are processed; `revoke_peer` immediately closes active
//!   QUIC connections.
//! - 3-lane framing:
//!   - Lane 0 (`CONTROL`): Bidirectional Stream 0, u32 LE length-prefixed, <= 64 KiB, priority 10.
//!   - Lane 1 (`CAUSAL`): Bidirectional Stream 4, u32 LE length-prefixed, <= 4 MiB, priority 0.
//!   - Lane 2 (`EPHEMERAL`): RFC 9221 Unreliable Datagrams, <= 1200 B.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod mls_ffi;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh::address_lookup::AddrFilter;
use iroh::endpoint::{
    AfterHandshakeOutcome, BeforeConnectOutcome, ConnectError, ConnectWithOptsError,
    ConnectingError, Connection, ConnectionError, EndpointHooks, QuicTransportConfig, RecvStream,
    SendDatagramError, SendStream, VarInt, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMap, RelayMode, RelayUrl, SecretKey, TransportAddr};
use tokio::sync::{Notify, Semaphore, mpsc};
use url::Url;

pub const BB_P2P_ABI_VERSION: u32 = 1;
pub const BB_P2P_PUBKEY_LEN: usize = 32;
pub const BB_P2P_SECRET_KEY_LEN: usize = 32;
pub const BB_P2P_MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
pub const BB_P2P_MAX_CAUSAL_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const BB_P2P_MAX_EPHEMERAL_FRAME_BYTES: usize = 1200;
pub const BB_P2P_MAX_RELAY_URL_BYTES: usize = 100;
pub const BB_P2P_MAX_DIRECT_ADDRS: usize = 8;
pub const BB_P2P_MAX_ALLOWED_PEERS: usize = 1024;
pub const BB_P2P_MAX_PENDING_LAN_PEERS: usize = 16;

const BB_P2P_ALPN: &[u8] = b"blackbird-mp/1";
const STREAM_ID_CONTROL: u64 = 0;
const STREAM_ID_CAUSAL: u64 = 4;
const STREAM_INIT_MARKER: u32 = u32::MAX;
const LANE_CONTROL_PRIORITY: i32 = 10;
const LANE_CAUSAL_PRIORITY: i32 = 0;

const CLOSE_SHUTDOWN: u32 = 4000;
const CLOSE_PROTOCOL_VIOLATION: u32 = 4400;
const CLOSE_UNAUTHORIZED: u32 = 4401;
const CLOSE_PEER_REVOKED: u32 = 4403;
const CLOSE_SUPERSEDED: u32 = 4409;
const CLOSE_FRAME_TOO_LARGE: u32 = 4413;

const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 10_000;
const STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(10);
const SEND_QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
const LANE_CHANNEL_CAPACITY: usize = 256;
const MAX_PRIORITY_EVENTS: usize = 1024;
const MAX_PRIORITY_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUEUED_EVENTS: usize = 4096;
const MAX_QUEUED_EVENT_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONCURRENT_INBOUND_HANDSHAKES: usize = 64;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BbP2pStatus {
    Ok = 0,
    ErrNullPointer = 1,
    ErrInvalidArg = 2,
    ErrPolicyViolation = 3,
    ErrNotAllowed = 4,
    ErrNotConnected = 5,
    ErrFrameTooLarge = 6,
    ErrTimeout = 7,
    ErrClosed = 8,
    ErrTransport = 9,
    ErrCapacity = 10,
    ErrPanic = 11,
    ErrUnsupported = 12,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BbP2pRelayPolicy {
    AllowRelays = 0,
    ForceRelays = 1,
    NoRelays = 2,
}

impl BbP2pRelayPolicy {
    fn from_u32(value: u32) -> Result<Self, BbP2pStatus> {
        match value {
            0 => Ok(Self::AllowRelays),
            1 => Ok(Self::ForceRelays),
            2 => Ok(Self::NoRelays),
            _ => Err(BbP2pStatus::ErrInvalidArg),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BbP2pLane {
    Control = 0,
    Causal = 1,
    Ephemeral = 2,
}

impl BbP2pLane {
    fn from_u32(value: u32) -> Result<Self, BbP2pStatus> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Causal),
            2 => Ok(Self::Ephemeral),
            _ => Err(BbP2pStatus::ErrInvalidArg),
        }
    }

    fn max_frame_bytes(self) -> usize {
        match self {
            Self::Control => BB_P2P_MAX_CONTROL_FRAME_BYTES,
            Self::Causal => BB_P2P_MAX_CAUSAL_FRAME_BYTES,
            Self::Ephemeral => BB_P2P_MAX_EPHEMERAL_FRAME_BYTES,
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BbP2pEventKind {
    None = 0,
    PeerConnected = 1,
    PeerDisconnected = 2,
    FrameReceived = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct BbP2pDirectAddr {
    pub family: u8,
    pub ip: [u8; 16],
    pub port: u16,
}

#[repr(C)]
pub struct BbP2pCreateConfig {
    pub abi_version: u32,
    pub relay_policy: u32,
    pub secret_key: *const u8,
    pub relay_url: *const std::ffi::c_char,
    pub relay_url_len: usize,
}

#[repr(C)]
pub struct BbP2pPeerTarget {
    pub pubkey: [u8; BB_P2P_PUBKEY_LEN],
    pub remote_relay_policy: u32,
    pub relay_url: *const std::ffi::c_char,
    pub relay_url_len: usize,
    pub direct_addrs: *const BbP2pDirectAddr,
    pub direct_addrs_count: usize,
    pub connect_timeout_ms: u32,
}

#[repr(C)]
pub struct BbP2pEvent {
    pub kind: u32,
    pub lane: u32,
    pub peer_pubkey: [u8; BB_P2P_PUBKEY_LEN],
    pub data: *mut u8,
    pub data_len: usize,
    pub reason_code: u32,
}

struct QueuedEvent {
    kind: BbP2pEventKind,
    lane: BbP2pLane,
    peer_pubkey: [u8; BB_P2P_PUBKEY_LEN],
    data: Vec<u8>,
    reason_code: u32,
}

struct EventQueueInner {
    priority: VecDeque<QueuedEvent>,
    priority_bytes: usize,
    normal: VecDeque<QueuedEvent>,
    normal_bytes: usize,
    closed: bool,
}

impl EventQueueInner {
    fn pop_next(&mut self) -> Option<(QueuedEvent, bool)> {
        if let Some(ev) = self.priority.pop_front() {
            self.priority_bytes = self.priority_bytes.saturating_sub(ev.data.len());
            return Some((ev, true));
        }
        if let Some(ev) = self.normal.pop_front() {
            self.normal_bytes = self.normal_bytes.saturating_sub(ev.data.len());
            return Some((ev, false));
        }
        None
    }
}

struct EventQueue {
    inner: Mutex<EventQueueInner>,
    condvar: Condvar,
    priority_space_notify: Notify,
    normal_space_notify: Notify,
}

impl EventQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(EventQueueInner {
                priority: VecDeque::new(),
                priority_bytes: 0,
                normal: VecDeque::new(),
                normal_bytes: 0,
                closed: false,
            }),
            condvar: Condvar::new(),
            priority_space_notify: Notify::new(),
            normal_space_notify: Notify::new(),
        }
    }

    fn close(&self) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.closed = true;
        self.condvar.notify_all();
        self.priority_space_notify.notify_waiters();
        self.normal_space_notify.notify_waiters();
    }

    /// Push a bounded lifecycle event (`PeerConnected` / `PeerDisconnected`) ahead of
    /// normal Causal/ephemeral traffic. Strictly bounded by `MAX_PRIORITY_EVENTS`.
    fn push_lifecycle(&self, event: QueuedEvent) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return;
        }
        while guard.priority.len() >= MAX_PRIORITY_EVENTS {
            if let Some(idx) = guard
                .priority
                .iter()
                .position(|e| e.kind != BbP2pEventKind::FrameReceived)
                && let Some(removed) = guard.priority.remove(idx)
            {
                guard.priority_bytes = guard.priority_bytes.saturating_sub(removed.data.len());
                continue;
            }
            // Priority queue is completely full of reliable Control frames; drop this
            // redundant lifecycle notice rather than growing unbounded or dropping Control.
            return;
        }
        guard.priority_bytes = guard.priority_bytes.saturating_add(event.data.len());
        guard.priority.push_back(event);
        self.condvar.notify_one();
    }

    /// Push a reliable Control-lane (`Lane 0`) frame into the priority deque, using
    /// async backpressure if the priority deque is full rather than ever dropping it.
    /// Completely isolated from `normal` queue saturation so Control never HoL-blocks
    /// behind Causal frames.
    async fn push_control(&self, event: QueuedEvent) {
        let needed = event.data.len();
        loop {
            let notified = self.priority_space_notify.notified();
            {
                let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if guard.closed {
                    return;
                }
                if guard.priority.len() < MAX_PRIORITY_EVENTS
                    && guard.priority_bytes.saturating_add(needed) <= MAX_PRIORITY_BYTES
                {
                    guard.priority_bytes = guard.priority_bytes.saturating_add(needed);
                    guard.priority.push_back(event);
                    self.condvar.notify_one();
                    return;
                }
            }
            notified.await;
        }
    }

    /// Push an unreliable ephemeral datagram; drops cleanly when normal queue is full.
    fn push_ephemeral(&self, event: QueuedEvent) {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if guard.closed {
            return;
        }
        let needed = event.data.len();
        if guard.normal.len() >= MAX_QUEUED_EVENTS
            || guard.normal_bytes.saturating_add(needed) > MAX_QUEUED_EVENT_BYTES
        {
            return;
        }
        guard.normal_bytes = guard.normal_bytes.saturating_add(needed);
        guard.normal.push_back(event);
        self.condvar.notify_one();
    }

    /// Push a reliable Causal event, evicting stale ephemeral datagrams first and
    /// otherwise asynchronously waiting for space so QUIC stream flow control naturally
    /// backpressures the peer instead of dropping.
    async fn push_causal(&self, event: QueuedEvent) {
        let needed = event.data.len();
        loop {
            let notified = self.normal_space_notify.notified();
            {
                let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if guard.closed {
                    return;
                }
                while guard.normal.len() >= MAX_QUEUED_EVENTS
                    || guard.normal_bytes.saturating_add(needed) > MAX_QUEUED_EVENT_BYTES
                {
                    if let Some(idx) = guard.normal.iter().position(|e| {
                        e.kind == BbP2pEventKind::FrameReceived && e.lane == BbP2pLane::Ephemeral
                    }) && let Some(removed) = guard.normal.remove(idx)
                    {
                        guard.normal_bytes =
                            guard.normal_bytes.saturating_sub(removed.data.len());
                        continue;
                    }
                    break;
                }
                if guard.normal.len() < MAX_QUEUED_EVENTS
                    && guard.normal_bytes.saturating_add(needed) <= MAX_QUEUED_EVENT_BYTES
                {
                    guard.normal_bytes = guard.normal_bytes.saturating_add(needed);
                    guard.normal.push_back(event);
                    self.condvar.notify_one();
                    return;
                }
            }
            notified.await;
        }
    }

    fn pop_timeout(&self, timeout: Duration) -> Result<QueuedEvent, BbP2pStatus> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((ev, from_priority)) = guard.pop_next() {
            if from_priority {
                self.priority_space_notify.notify_waiters();
            } else {
                self.normal_space_notify.notify_waiters();
            }
            return Ok(ev);
        }
        if guard.closed {
            return Err(BbP2pStatus::ErrClosed);
        }
        if timeout.is_zero() {
            return Err(BbP2pStatus::ErrTimeout);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(BbP2pStatus::ErrTimeout);
            }
            let (new_guard, wait_res) = self
                .condvar
                .wait_timeout(guard, remaining)
                .unwrap_or_else(|e| e.into_inner());
            guard = new_guard;
            if let Some((ev, from_priority)) = guard.pop_next() {
                if from_priority {
                    self.priority_space_notify.notify_waiters();
                } else {
                    self.normal_space_notify.notify_waiters();
                }
                return Ok(ev);
            }
            if guard.closed {
                return Err(BbP2pStatus::ErrClosed);
            }
            if wait_res.timed_out() {
                return Err(BbP2pStatus::ErrTimeout);
            }
        }
    }
}

struct ActivePeer {
    conn_id: u64,
    conn: Connection,
    control_tx: mpsc::Sender<Bytes>,
    causal_tx: mpsc::Sender<Bytes>,
    is_pending: Arc<AtomicBool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ActivePeer {
    fn abort_tasks(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

struct InFlightPendingGuard {
    shared: Arc<SharedState>,
}

impl Drop for InFlightPendingGuard {
    fn drop(&mut self) {
        self.shared
            .in_flight_pending_lan
            .fetch_sub(1, Ordering::AcqRel);
    }
}

struct SharedState {
    relay_policy: BbP2pRelayPolicy,
    pinned_relay_url: Option<RelayUrl>,
    lan_open_admission: AtomicBool,
    in_flight_pending_lan: AtomicUsize,
    allowed_peers: RwLock<HashSet<EndpointId>>,
    peers: RwLock<HashMap<EndpointId, ActivePeer>>,
    next_conn_id: AtomicU64,
    events: EventQueue,
    closed: AtomicBool,
}

impl SharedState {
    fn is_allowed(&self, peer_id: &EndpointId) -> bool {
        let guard = self.allowed_peers.read().unwrap_or_else(|e| e.into_inner());
        guard.contains(peer_id)
    }

    fn is_lan_open_admission(&self) -> bool {
        self.relay_policy == BbP2pRelayPolicy::NoRelays
            && self.lan_open_admission.load(Ordering::Acquire)
    }

    fn pending_lan_slots_full(&self, candidate: &EndpointId) -> bool {
        let active_pending = {
            let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = peers.get(candidate)
                && existing.is_pending.load(Ordering::Acquire)
            {
                return false;
            }
            peers
                .values()
                .filter(|p| p.is_pending.load(Ordering::Acquire))
                .count()
        };
        let in_flight = self.in_flight_pending_lan.load(Ordering::Acquire);
        active_pending.saturating_add(in_flight) >= BB_P2P_MAX_PENDING_LAN_PEERS
    }

    fn try_reserve_in_flight_pending(
        self: &Arc<Self>,
        candidate: &EndpointId,
    ) -> Option<InFlightPendingGuard> {
        let peers = self.peers.read().unwrap_or_else(|e| e.into_inner());
        let already_pending_self = peers
            .get(candidate)
            .is_some_and(|p| p.is_pending.load(Ordering::Acquire));
        let active_pending = peers
            .values()
            .filter(|p| p.is_pending.load(Ordering::Acquire))
            .count();
        let effective_active = if already_pending_self {
            active_pending.saturating_sub(1)
        } else {
            active_pending
        };
        loop {
            let current = self.in_flight_pending_lan.load(Ordering::Acquire);
            if effective_active.saturating_add(current) >= BB_P2P_MAX_PENDING_LAN_PEERS {
                return None;
            }
            if self
                .in_flight_pending_lan
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(InFlightPendingGuard {
                    shared: Arc::clone(self),
                });
            }
        }
    }

    fn close_and_remove_peer(
        &self,
        peer_id: &EndpointId,
        expected_conn_id: Option<u64>,
        close_code: u32,
        reason: &[u8],
        emit_disconnect: bool,
    ) {
        let removed = {
            let mut peers = self.peers.write().unwrap_or_else(|e| e.into_inner());
            let should_remove = match (peers.get(peer_id), expected_conn_id) {
                (Some(existing), Some(cid)) => existing.conn_id == cid,
                (Some(_), None) => true,
                (None, _) => false,
            };
            if should_remove {
                peers.remove(peer_id)
            } else {
                None
            }
        };
        if let Some(mut peer) = removed {
            peer.conn.close(VarInt::from_u32(close_code), reason);
            peer.abort_tasks();
            if emit_disconnect {
                self.events.push_lifecycle(QueuedEvent {
                    kind: BbP2pEventKind::PeerDisconnected,
                    lane: BbP2pLane::Control,
                    peer_pubkey: *peer_id.as_bytes(),
                    data: Vec::new(),
                    reason_code: close_code,
                });
            }
        }
    }
}

/// Enforces mandatory peer allowlist and ALPN inside iroh's QUIC handshake hooks
/// BEFORE any streams or datagrams can be exchanged.
struct AllowlistHooks {
    shared: Arc<SharedState>,
}

impl std::fmt::Debug for AllowlistHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllowlistHooks")
            .field("relay_policy", &self.shared.relay_policy)
            .finish()
    }
}

impl EndpointHooks for AllowlistHooks {
    async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        if self.shared.closed.load(Ordering::Acquire) {
            return BeforeConnectOutcome::Reject;
        }
        if alpn != BB_P2P_ALPN {
            return BeforeConnectOutcome::Reject;
        }
        if !self.shared.is_allowed(&remote_addr.id) {
            return BeforeConnectOutcome::Reject;
        }
        if self.shared.relay_policy == BbP2pRelayPolicy::ForceRelays
            && remote_addr.addrs.iter().any(TransportAddr::is_ip)
        {
            return BeforeConnectOutcome::Reject;
        }
        BeforeConnectOutcome::Accept
    }

    async fn after_handshake(&self, conn: &Connection) -> AfterHandshakeOutcome {
        if self.shared.closed.load(Ordering::Acquire) {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(CLOSE_SHUTDOWN),
                reason: b"endpoint_closed".to_vec(),
            };
        }
        if conn.alpn() != BB_P2P_ALPN {
            return AfterHandshakeOutcome::Reject {
                error_code: VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                reason: b"wrong_alpn".to_vec(),
            };
        }
        let remote_id = conn.remote_id();
        if !self.shared.is_allowed(&remote_id) {
            if !self.shared.is_lan_open_admission() {
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    reason: b"peer_not_allowed".to_vec(),
                };
            }
            if self.shared.pending_lan_slots_full(&remote_id) {
                return AfterHandshakeOutcome::Reject {
                    error_code: VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    reason: b"pending_lan_cap_reached".to_vec(),
                };
            }
        }
        AfterHandshakeOutcome::Accept
    }
}

pub struct BbP2pEndpoint {
    runtime: tokio::runtime::Runtime,
    endpoint: Endpoint,
    shared: Arc<SharedState>,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

/// Non-downgradeable relay policy compatibility check:
/// - `ForceRelays` refuses `NoRelays` (prevents IP leak).
/// - `AllowRelays` and `NoRelays` refuse `ForceRelays` (prevents downgrading a
///   `ForceRelays` party to a direct-UDP endpoint).
pub fn relay_policy_compatible(local: BbP2pRelayPolicy, remote: BbP2pRelayPolicy) -> bool {
    !matches!(
        (local, remote),
        (BbP2pRelayPolicy::ForceRelays, BbP2pRelayPolicy::NoRelays)
            | (BbP2pRelayPolicy::AllowRelays, BbP2pRelayPolicy::ForceRelays)
            | (BbP2pRelayPolicy::NoRelays, BbP2pRelayPolicy::ForceRelays)
    )
}

fn validate_relay_url(raw: &str) -> Result<RelayUrl, BbP2pStatus> {
    if raw.is_empty() || raw.len() > BB_P2P_MAX_RELAY_URL_BYTES {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    if raw.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    let parsed = Url::parse(raw).map_err(|_| BbP2pStatus::ErrInvalidArg)?;
    if parsed.scheme() != "https" {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    if !parsed.has_host() {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    if !parsed.path().is_empty() && parsed.path() != "/" {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    raw.parse::<RelayUrl>()
        .map_err(|_| BbP2pStatus::ErrInvalidArg)
}

unsafe fn read_optional_utf8<'a>(
    ptr: *const std::ffi::c_char,
    len: usize,
    max_len: usize,
) -> Result<Option<&'a str>, BbP2pStatus> {
    if len == 0 {
        return Ok(None);
    }
    if ptr.is_null() {
        return Err(BbP2pStatus::ErrNullPointer);
    }
    if len > max_len {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    let bytes = unsafe { slice::from_raw_parts(ptr.cast::<u8>(), len) };
    let text = std::str::from_utf8(bytes).map_err(|_| BbP2pStatus::ErrInvalidArg)?;
    Ok(Some(text))
}

fn direct_addr_to_socket_addr(addr: &BbP2pDirectAddr) -> Result<SocketAddr, BbP2pStatus> {
    if addr.port == 0 {
        return Err(BbP2pStatus::ErrInvalidArg);
    }
    match addr.family {
        4 => {
            if addr.ip[4..].iter().any(|&b| b != 0) {
                return Err(BbP2pStatus::ErrInvalidArg);
            }
            let ip = Ipv4Addr::new(addr.ip[0], addr.ip[1], addr.ip[2], addr.ip[3]);
            if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                return Err(BbP2pStatus::ErrInvalidArg);
            }
            Ok(SocketAddr::new(IpAddr::V4(ip), addr.port))
        }
        6 => {
            let ip = Ipv6Addr::from(addr.ip);
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(BbP2pStatus::ErrInvalidArg);
            }
            if let Some(v4) = ip.to_ipv4_mapped()
                && (v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast())
            {
                return Err(BbP2pStatus::ErrInvalidArg);
            }
            Ok(SocketAddr::new(IpAddr::V6(ip), addr.port))
        }
        _ => Err(BbP2pStatus::ErrInvalidArg),
    }
}

fn socket_addr_to_direct_addr(addr: SocketAddr) -> BbP2pDirectAddr {
    match addr {
        SocketAddr::V4(v4) => {
            let mut ip = [0u8; 16];
            ip[..4].copy_from_slice(&v4.ip().octets());
            BbP2pDirectAddr {
                family: 4,
                ip,
                port: v4.port(),
            }
        }
        SocketAddr::V6(v6) => BbP2pDirectAddr {
            family: 6,
            ip: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

fn close_reason_code(err: &ConnectionError) -> u32 {
    match err {
        ConnectionError::ApplicationClosed(app) => {
            let code = app.error_code.into_inner();
            u32::try_from(code).unwrap_or(u32::MAX)
        }
        ConnectionError::LocallyClosed => CLOSE_SHUTDOWN,
        ConnectionError::TimedOut => 4408,
        ConnectionError::Reset => 4499,
        ConnectionError::ConnectionClosed(_)
        | ConnectionError::TransportError(_)
        | ConnectionError::VersionMismatch
        | ConnectionError::CidsExhausted => 4500,
    }
}

async fn write_framed_stream(
    mut send: SendStream,
    mut rx: mpsc::Receiver<Bytes>,
    conn: Connection,
    shared: Arc<SharedState>,
) {
    while let Some(payload) = rx.recv().await {
        let Ok(len_u32) = u32::try_from(payload.len()) else {
            conn.close(VarInt::from_u32(CLOSE_FRAME_TOO_LARGE), b"frame_too_large");
            return;
        };
        if send.write_all(&len_u32.to_le_bytes()).await.is_err()
            || (!payload.is_empty() && send.write_all(&payload).await.is_err())
        {
            if !shared.closed.load(Ordering::Acquire) && conn.close_reason().is_none() {
                conn.close(
                    VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                    b"stream_write_failed",
                );
            }
            return;
        }
    }
    let _ = send.finish();
}

fn check_inbound_lane_allowed(
    shared: &SharedState,
    peer_id: &EndpointId,
    lane: BbP2pLane,
    is_pending: &AtomicBool,
) -> Result<(), (u32, &'static [u8])> {
    if shared.is_allowed(peer_id) {
        return Ok(());
    }
    if is_pending.load(Ordering::Acquire) {
        if lane == BbP2pLane::Control {
            if shared.is_lan_open_admission() {
                return Ok(());
            }
            return Err((CLOSE_UNAUTHORIZED, b"lan_admission_closed"));
        }
        return Err((CLOSE_PROTOCOL_VIOLATION, b"pending_peer_lane_violation"));
    }
    Err((CLOSE_PEER_REVOKED, b"peer_revoked"))
}

async fn read_framed_stream(
    mut recv: RecvStream,
    lane: BbP2pLane,
    peer_id: EndpointId,
    conn_id: u64,
    is_pending: Arc<AtomicBool>,
    conn: Connection,
    shared: Arc<SharedState>,
) {
    let max_bytes = lane.max_frame_bytes();
    let mut len_buf = [0u8; 4];
    loop {
        if recv.read_exact(&mut len_buf).await.is_err() {
            if !shared.closed.load(Ordering::Acquire) && conn.close_reason().is_none() {
                shared.close_and_remove_peer(
                    &peer_id,
                    Some(conn_id),
                    CLOSE_PROTOCOL_VIOLATION,
                    b"stream_closed_unexpectedly",
                    true,
                );
            }
            return;
        }
        if let Err((code, reason)) =
            check_inbound_lane_allowed(&shared, &peer_id, lane, &is_pending)
        {
            shared.close_and_remove_peer(&peer_id, Some(conn_id), code, reason, true);
            return;
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > max_bytes {
            shared.close_and_remove_peer(
                &peer_id,
                Some(conn_id),
                CLOSE_FRAME_TOO_LARGE,
                b"frame_too_large",
                true,
            );
            return;
        }
        let mut payload = vec![0u8; len];
        if len > 0 && recv.read_exact(&mut payload).await.is_err() {
            if !shared.closed.load(Ordering::Acquire) && conn.close_reason().is_none() {
                shared.close_and_remove_peer(
                    &peer_id,
                    Some(conn_id),
                    CLOSE_PROTOCOL_VIOLATION,
                    b"stream_truncated_unexpectedly",
                    true,
                );
            }
            return;
        }
        if let Err((code, reason)) =
            check_inbound_lane_allowed(&shared, &peer_id, lane, &is_pending)
        {
            shared.close_and_remove_peer(&peer_id, Some(conn_id), code, reason, true);
            return;
        }
        let ev = QueuedEvent {
            kind: BbP2pEventKind::FrameReceived,
            lane,
            peer_pubkey: *peer_id.as_bytes(),
            data: payload,
            reason_code: 0,
        };
        match lane {
            BbP2pLane::Control => shared.events.push_control(ev).await,
            BbP2pLane::Causal => shared.events.push_causal(ev).await,
            BbP2pLane::Ephemeral => shared.events.push_ephemeral(ev),
        }
    }
}

async fn read_datagram_loop(
    peer_id: EndpointId,
    conn_id: u64,
    is_pending: Arc<AtomicBool>,
    conn: Connection,
    shared: Arc<SharedState>,
) {
    loop {
        let Ok(dgram) = conn.read_datagram().await else {
            return;
        };
        if let Err((code, reason)) =
            check_inbound_lane_allowed(&shared, &peer_id, BbP2pLane::Ephemeral, &is_pending)
        {
            shared.close_and_remove_peer(&peer_id, Some(conn_id), code, reason, true);
            return;
        }
        if dgram.len() > BB_P2P_MAX_EPHEMERAL_FRAME_BYTES {
            // Drop oversized unreliable datagram safely.
            continue;
        }
        shared.events.push_ephemeral(QueuedEvent {
            kind: BbP2pEventKind::FrameReceived,
            lane: BbP2pLane::Ephemeral,
            peer_pubkey: *peer_id.as_bytes(),
            data: dgram.to_vec(),
            reason_code: 0,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn register_active_peer(
    shared: &Arc<SharedState>,
    peer_id: EndpointId,
    conn: Connection,
    control_send: SendStream,
    control_recv: RecvStream,
    causal_send: SendStream,
    causal_recv: RecvStream,
    is_pending_lan: bool,
    pending_guard: Option<InFlightPendingGuard>,
) -> Result<(), BbP2pStatus> {
    if shared.closed.load(Ordering::Acquire) {
        conn.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"endpoint_closed");
        return Err(BbP2pStatus::ErrClosed);
    }
    if !shared.is_allowed(&peer_id) && (!is_pending_lan || !shared.is_lan_open_admission()) {
        conn.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"peer_not_allowed");
        return Err(BbP2pStatus::ErrNotAllowed);
    }

    let conn_id = shared.next_conn_id.fetch_add(1, Ordering::Relaxed) + 1;
    let is_pending = Arc::new(AtomicBool::new(is_pending_lan));
    let (control_tx, control_rx) = mpsc::channel(LANE_CHANNEL_CAPACITY);
    let (causal_tx, causal_rx) = mpsc::channel(LANE_CHANNEL_CAPACITY);

    let t_ctrl_w = tokio::spawn(write_framed_stream(
        control_send,
        control_rx,
        conn.clone(),
        Arc::clone(shared),
    ));
    let t_caus_w = tokio::spawn(write_framed_stream(
        causal_send,
        causal_rx,
        conn.clone(),
        Arc::clone(shared),
    ));
    let t_ctrl_r = tokio::spawn(read_framed_stream(
        control_recv,
        BbP2pLane::Control,
        peer_id,
        conn_id,
        Arc::clone(&is_pending),
        conn.clone(),
        Arc::clone(shared),
    ));
    let t_caus_r = tokio::spawn(read_framed_stream(
        causal_recv,
        BbP2pLane::Causal,
        peer_id,
        conn_id,
        Arc::clone(&is_pending),
        conn.clone(),
        Arc::clone(shared),
    ));
    let t_dgram_r = tokio::spawn(read_datagram_loop(
        peer_id,
        conn_id,
        Arc::clone(&is_pending),
        conn.clone(),
        Arc::clone(shared),
    ));

    let watcher_shared = Arc::clone(shared);
    let watcher_conn = conn.clone();
    let t_watcher = tokio::spawn(async move {
        let err = watcher_conn.closed().await;
        let code = close_reason_code(&err);
        watcher_shared.close_and_remove_peer(
            &peer_id,
            Some(conn_id),
            code,
            b"closed",
            true,
        );
    });

    let active = ActivePeer {
        conn_id,
        conn,
        control_tx,
        causal_tx,
        is_pending,
        tasks: vec![t_ctrl_w, t_caus_w, t_ctrl_r, t_caus_r, t_dgram_r, t_watcher],
    };

    let old = {
        let mut peers = shared.peers.write().unwrap_or_else(|e| e.into_inner());
        if shared.closed.load(Ordering::Acquire) {
            let mut dropped = active;
            dropped.conn.close(VarInt::from_u32(CLOSE_SHUTDOWN), b"endpoint_closed");
            dropped.abort_tasks();
            return Err(BbP2pStatus::ErrClosed);
        }
        let is_allowed_now = shared.is_allowed(&peer_id);
        if is_allowed_now {
            active.is_pending.store(false, Ordering::Release);
        } else {
            if !is_pending_lan || !shared.is_lan_open_admission() {
                let mut dropped = active;
                let (code, reason): (u32, &[u8]) = if is_pending_lan {
                    (CLOSE_UNAUTHORIZED, b"lan_admission_closed")
                } else {
                    (CLOSE_PEER_REVOKED, b"peer_revoked")
                };
                dropped.conn.close(VarInt::from_u32(code), reason);
                dropped.abort_tasks();
                return Err(BbP2pStatus::ErrNotAllowed);
            }
            let other_pending = peers
                .iter()
                .filter(|(id, p)| **id != peer_id && p.is_pending.load(Ordering::Acquire))
                .count();
            if other_pending >= BB_P2P_MAX_PENDING_LAN_PEERS {
                let mut dropped = active;
                dropped
                    .conn
                    .close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"pending_lan_cap_reached");
                dropped.abort_tasks();
                return Err(BbP2pStatus::ErrNotAllowed);
            }
        }
        let previous = peers.insert(peer_id, active);
        // Transfer slot accounting from in-flight to active map under the write lock.
        drop(pending_guard);
        previous
    };

    if let Some(mut previous) = old {
        previous
            .conn
            .close(VarInt::from_u32(CLOSE_SUPERSEDED), b"superseded");
        previous.abort_tasks();
    }

    shared.events.push_lifecycle(QueuedEvent {
        kind: BbP2pEventKind::PeerConnected,
        lane: BbP2pLane::Control,
        peer_pubkey: *peer_id.as_bytes(),
        data: Vec::new(),
        reason_code: 0,
    });
    Ok(())
}

async fn handle_incoming_connection(
    incoming: iroh::endpoint::Incoming,
    shared: Arc<SharedState>,
) {
    let Ok(accepting) = incoming.accept() else {
        return;
    };
    // Full 1-RTT TLS 1.3 Mutual RPK handshake — never call into_0rtt().
    let Ok(Ok(conn)) = tokio::time::timeout(STREAM_SETUP_TIMEOUT, accepting).await else {
        return;
    };

    let remote_id = conn.remote_id();
    if conn.alpn() != BB_P2P_ALPN {
        conn.close(VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION), b"wrong_alpn");
        return;
    }
    let mut is_pending_lan = false;
    let mut pending_guard: Option<InFlightPendingGuard> = None;
    if !shared.is_allowed(&remote_id) {
        if !shared.is_lan_open_admission() {
            conn.close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"peer_not_allowed");
            return;
        }
        match shared.try_reserve_in_flight_pending(&remote_id) {
            Some(guard) => {
                is_pending_lan = true;
                pending_guard = Some(guard);
            }
            None => {
                conn.close(
                    VarInt::from_u32(CLOSE_UNAUTHORIZED),
                    b"pending_lan_cap_reached",
                );
                return;
            }
        }
    }

    // Accept bidirectional Stream 0 (Control) and Stream 4 (Causal) in any arrival order.
    let setup = tokio::time::timeout(STREAM_SETUP_TIMEOUT, async {
        let mut control: Option<(SendStream, RecvStream)> = None;
        let mut causal: Option<(SendStream, RecvStream)> = None;

        while control.is_none() || causal.is_none() {
            let (send, mut recv) = conn.accept_bi().await.map_err(|_| CLOSE_PROTOCOL_VIOLATION)?;
            let sid = u64::from(recv.id());
            let mut marker = [0u8; 4];
            recv.read_exact(&mut marker)
                .await
                .map_err(|_| CLOSE_PROTOCOL_VIOLATION)?;
            if u32::from_le_bytes(marker) != STREAM_INIT_MARKER {
                return Err(CLOSE_PROTOCOL_VIOLATION);
            }
            match sid {
                STREAM_ID_CONTROL if control.is_none() => {
                    let _ = send.set_priority(LANE_CONTROL_PRIORITY);
                    control = Some((send, recv));
                }
                STREAM_ID_CAUSAL if causal.is_none() => {
                    let _ = send.set_priority(LANE_CAUSAL_PRIORITY);
                    causal = Some((send, recv));
                }
                _ => return Err(CLOSE_PROTOCOL_VIOLATION),
            }
        }

        let Some((mut control_send, control_recv)) = control else {
            return Err(CLOSE_PROTOCOL_VIOLATION);
        };
        let Some((causal_send, causal_recv)) = causal else {
            return Err(CLOSE_PROTOCOL_VIOLATION);
        };

        if !shared.is_allowed(&remote_id) && (!is_pending_lan || !shared.is_lan_open_admission()) {
            return Err(CLOSE_UNAUTHORIZED);
        }

        // Send 4-byte readiness ACK on Stream 0 so the dialer knows both lanes
        // passed allowlist + stream verification.
        control_send
            .write_all(&STREAM_INIT_MARKER.to_le_bytes())
            .await
            .map_err(|_| CLOSE_PROTOCOL_VIOLATION)?;

        Ok((control_send, control_recv, causal_send, causal_recv))
    })
    .await;

    match setup {
        Ok(Ok((control_send, control_recv, causal_send, causal_recv))) => {
            let _ = register_active_peer(
                &shared,
                remote_id,
                conn,
                control_send,
                control_recv,
                causal_send,
                causal_recv,
                is_pending_lan,
                pending_guard,
            );
        }
        Ok(Err(code)) => {
            conn.close(VarInt::from_u32(code), b"stream_setup_rejected");
        }
        Err(_) => {
            conn.close(VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION), b"stream_setup_timeout");
        }
    }
}

async fn accept_loop(endpoint: Endpoint, shared: Arc<SharedState>) {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_INBOUND_HANDSHAKES));
    while let Some(incoming) = endpoint.accept().await {
        if shared.closed.load(Ordering::Acquire) {
            break;
        }
        let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
            break;
        };
        let shared_clone = Arc::clone(&shared);
        tokio::spawn(async move {
            let _permit = permit;
            handle_incoming_connection(incoming, shared_clone).await;
        });
    }
}

fn map_connect_error(err: &ConnectionError) -> BbP2pStatus {
    match err {
        ConnectionError::ApplicationClosed(app) => {
            let code = app.error_code.into_inner();
            if code == u64::from(CLOSE_UNAUTHORIZED) || code == u64::from(CLOSE_PEER_REVOKED) {
                BbP2pStatus::ErrNotAllowed
            } else {
                BbP2pStatus::ErrTransport
            }
        }
        ConnectionError::TimedOut => BbP2pStatus::ErrTimeout,
        _ => BbP2pStatus::ErrTransport,
    }
}

fn map_endpoint_connect_error(err: &ConnectError) -> BbP2pStatus {
    match err {
        ConnectError::Connection { source, .. } => map_connect_error(source),
        ConnectError::Connecting { source, .. } => match source {
            ConnectingError::ConnectionError { source, .. } => map_connect_error(source),
            ConnectingError::LocallyRejected { .. } | ConnectingError::HandshakeFailure { .. } => {
                BbP2pStatus::ErrNotAllowed
            }
            _ => BbP2pStatus::ErrTransport,
        },
        ConnectError::Connect { source, .. } => match source {
            ConnectWithOptsError::LocallyRejected { .. } => BbP2pStatus::ErrNotAllowed,
            ConnectWithOptsError::EndpointClosed { .. } => BbP2pStatus::ErrClosed,
            ConnectWithOptsError::SelfConnect { .. } | ConnectWithOptsError::InvalidAlpn { .. } => {
                BbP2pStatus::ErrInvalidArg
            }
            _ => BbP2pStatus::ErrTransport,
        },
        _ => BbP2pStatus::ErrTransport,
    }
}

fn catch_ffi_status<F>(f: F) -> BbP2pStatus
where
    F: FnOnce() -> Result<(), BbP2pStatus>,
{
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(())) => BbP2pStatus::Ok,
        Ok(Err(status)) => status,
        Err(_) => BbP2pStatus::ErrPanic,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bb_p2p_check_relay_policy(
    local_policy: u32,
    remote_policy: u32,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        let local = BbP2pRelayPolicy::from_u32(local_policy)?;
        let remote = BbP2pRelayPolicy::from_u32(remote_policy)?;
        if relay_policy_compatible(local, remote) {
            Ok(())
        } else {
            Err(BbP2pStatus::ErrPolicyViolation)
        }
    })
}

/// Creates a new iroh-backed P2P endpoint and stores its opaque handle in `out_handle`.
///
/// # Safety
/// `config` and `out_handle` must be valid, properly aligned non-null pointers.
/// Any non-null pointer fields inside `config` must remain valid for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_create(
    config: *const BbP2pCreateConfig,
    out_handle: *mut *mut BbP2pEndpoint,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if config.is_null() || out_handle.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        unsafe {
            *out_handle = ptr::null_mut();
        }
        let cfg = unsafe { &*config };
        if cfg.abi_version != BB_P2P_ABI_VERSION {
            return Err(BbP2pStatus::ErrInvalidArg);
        }
        let relay_policy = BbP2pRelayPolicy::from_u32(cfg.relay_policy)?;
        let raw_relay_url =
            unsafe { read_optional_utf8(cfg.relay_url, cfg.relay_url_len, BB_P2P_MAX_RELAY_URL_BYTES)? };

        let pinned_relay_url = match (relay_policy, raw_relay_url) {
            (BbP2pRelayPolicy::ForceRelays, None) => return Err(BbP2pStatus::ErrInvalidArg),
            (BbP2pRelayPolicy::ForceRelays, Some(raw)) => Some(validate_relay_url(raw)?),
            (BbP2pRelayPolicy::AllowRelays, Some(raw)) => Some(validate_relay_url(raw)?),
            (BbP2pRelayPolicy::AllowRelays, None) => None,
            (BbP2pRelayPolicy::NoRelays, Some(_)) => return Err(BbP2pStatus::ErrInvalidArg),
            (BbP2pRelayPolicy::NoRelays, None) => None,
        };

        let secret_key = if cfg.secret_key.is_null() {
            SecretKey::generate()
        } else {
            let bytes = unsafe { slice::from_raw_parts(cfg.secret_key, BB_P2P_SECRET_KEY_LEN) };
            let mut seed = [0u8; BB_P2P_SECRET_KEY_LEN];
            seed.copy_from_slice(bytes);
            SecretKey::from_bytes(&seed)
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("blackbird-p2p")
            .enable_all()
            .build()
            .map_err(|_| BbP2pStatus::ErrTransport)?;

        let shared = Arc::new(SharedState {
            relay_policy,
            pinned_relay_url: pinned_relay_url.clone(),
            lan_open_admission: AtomicBool::new(false),
            in_flight_pending_lan: AtomicUsize::new(0),
            allowed_peers: RwLock::new(HashSet::new()),
            peers: RwLock::new(HashMap::new()),
            next_conn_id: AtomicU64::new(0),
            events: EventQueue::new(),
            closed: AtomicBool::new(false),
        });

        let hooks = AllowlistHooks {
            shared: Arc::clone(&shared),
        };

        let mut transport_cfg = QuicTransportConfig::builder()
            // Exactly 2 bidirectional streams (Stream 0 Control, Stream 4 Causal), 0 uni streams.
            .max_concurrent_bidi_streams(VarInt::from_u32(2))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            // RFC 9221 Unreliable Datagrams explicitly enabled.
            .datagram_receive_buffer_size(Some(65_536))
            .datagram_send_buffer_size(65_536)
            .allow_spin(false)
            .keep_alive_interval(Duration::from_secs(5));
        if let Ok(idle) = Duration::from_secs(30).try_into() {
            transport_cfg = transport_cfg.max_idle_timeout(Some(idle));
        }

        // presets::Minimal installs the rustls ring crypto provider with ZERO N0
        // public pkarr/DNS address lookup publication.
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret_key)
            .alpns(vec![BB_P2P_ALPN.to_vec()])
            // Disable 0-RTT ticket caching completely.
            .max_tls_tickets(0)
            .transport_config(transport_cfg.build())
            .hooks(hooks);

        builder = match relay_policy {
            BbP2pRelayPolicy::AllowRelays => {
                if let Some(url) = pinned_relay_url {
                    builder.relay_mode(RelayMode::Custom(RelayMap::from(url)))
                } else {
                    builder.relay_mode(RelayMode::Default)
                }
            }
            BbP2pRelayPolicy::ForceRelays => {
                let Some(url) = pinned_relay_url else {
                    return Err(BbP2pStatus::ErrInvalidArg);
                };
                builder
                    .clear_ip_transports()
                    .addr_filter(AddrFilter::relay_only())
                    .relay_mode(RelayMode::Custom(RelayMap::from(url)))
            }
            BbP2pRelayPolicy::NoRelays => builder.relay_mode(RelayMode::Disabled),
        };

        let endpoint = runtime
            .block_on(builder.bind())
            .map_err(|_| BbP2pStatus::ErrTransport)?;

        let accept_task = runtime.spawn(accept_loop(endpoint.clone(), Arc::clone(&shared)));

        let boxed = Box::new(BbP2pEndpoint {
            runtime,
            endpoint,
            shared,
            accept_task: Some(accept_task),
        });
        unsafe {
            *out_handle = Box::into_raw(boxed);
        }
        Ok(())
    })
}

/// Gracefully closes and destroys an endpoint created by `bb_p2p_create`.
///
/// # Safety
/// `handle` must be null or a valid pointer previously returned by `bb_p2p_create`
/// that has not already been destroyed, and no other thread may concurrently use it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_destroy(handle: *mut BbP2pEndpoint) {
    if handle.is_null() {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        let mut ep = unsafe { Box::from_raw(handle) };
        ep.shared.closed.store(true, Ordering::Release);
        ep.shared.events.close();

        // Close all active peer connections immediately.
        let drained: Vec<ActivePeer> = {
            let mut peers = ep.shared.peers.write().unwrap_or_else(|e| e.into_inner());
            peers.drain().map(|(_, p)| p).collect()
        };
        for mut peer in drained {
            peer.conn
                .close(VarInt::from_u32(CLOSE_SHUTDOWN), b"endpoint_shutdown");
            peer.abort_tasks();
        }
        if let Some(task) = ep.accept_task.take() {
            task.abort();
        }
        let endpoint = ep.endpoint.clone();
        ep.runtime.block_on(async move {
            let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.close()).await;
        });
        ep.runtime.shutdown_timeout(Duration::from_secs(1));
    }));
}

/// Writes the endpoint's 32-byte Ed25519 public key into `out_pubkey`.
///
/// # Safety
/// `handle` must be a valid endpoint pointer and `out_pubkey` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_local_pubkey(
    handle: *const BbP2pEndpoint,
    out_pubkey: *mut u8,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || out_pubkey.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        let id = ep.endpoint.id();
        let out = unsafe { slice::from_raw_parts_mut(out_pubkey, BB_P2P_PUBKEY_LEN) };
        out.copy_from_slice(id.as_bytes());
        Ok(())
    })
}

/// Queries bound local direct UDP addresses (always 0 under `BB_P2P_FORCE_RELAYS`).
///
/// # Safety
/// `handle` and `out_count` must be valid pointers; when `max_addrs > 0`, `out_addrs` must
/// point to at least `max_addrs` writable `BbP2pDirectAddr` elements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_local_direct_addrs(
    handle: *const BbP2pEndpoint,
    out_addrs: *mut BbP2pDirectAddr,
    max_addrs: usize,
    out_count: *mut usize,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || out_count.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        if max_addrs > 0 && out_addrs.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        if ep.shared.relay_policy == BbP2pRelayPolicy::ForceRelays {
            unsafe {
                *out_count = 0;
            }
            return Ok(());
        }

        let mut collected: Vec<SocketAddr> = Vec::new();
        let mut seen: HashSet<SocketAddr> = HashSet::new();

        // Include explicit loopback addresses for any unspecified bound UDP sockets
        // so offline loopback connectivity always has a deterministic local target.
        for bound in ep.endpoint.bound_sockets() {
            let candidate = match bound {
                SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v4.port())
                }
                SocketAddr::V6(v6) if v6.ip().is_unspecified() => {
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), v6.port())
                }
                other => other,
            };
            if candidate.port() != 0 && seen.insert(candidate) {
                collected.push(candidate);
            }
        }

        for addr in ep.endpoint.addr().ip_addrs() {
            if addr.port() != 0 && seen.insert(*addr) {
                collected.push(*addr);
            }
        }

        collected.truncate(BB_P2P_MAX_DIRECT_ADDRS);

        let write_count = collected.len().min(max_addrs);
        if write_count > 0 {
            let out_slice = unsafe { slice::from_raw_parts_mut(out_addrs, write_count) };
            for (dst, src) in out_slice.iter_mut().zip(collected.iter().take(write_count)) {
                *dst = socket_addr_to_direct_addr(*src);
            }
        }
        unsafe {
            *out_count = collected.len();
        }
        Ok(())
    })
}

/// Replaces the active peer Ed25519 allowlist and immediately closes any removed active peers.
///
/// # Safety
/// `handle` must be a valid endpoint pointer; when `count > 0`, `pubkeys_32b_ptr` must
/// point to `count * 32` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_set_allowed_peers(
    handle: *mut BbP2pEndpoint,
    pubkeys_32b_ptr: *const u8,
    count: usize,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        if count > BB_P2P_MAX_ALLOWED_PEERS {
            return Err(BbP2pStatus::ErrCapacity);
        }
        if count > 0 && pubkeys_32b_ptr.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        if ep.shared.closed.load(Ordering::Acquire) {
            return Err(BbP2pStatus::ErrClosed);
        }

        let mut next_allowed = HashSet::with_capacity(count);
        if count > 0 {
            let total_bytes = count
                .checked_mul(BB_P2P_PUBKEY_LEN)
                .ok_or(BbP2pStatus::ErrInvalidArg)?;
            let raw = unsafe { slice::from_raw_parts(pubkeys_32b_ptr, total_bytes) };
            for chunk in raw.chunks_exact(BB_P2P_PUBKEY_LEN) {
                let mut key_bytes = [0u8; BB_P2P_PUBKEY_LEN];
                key_bytes.copy_from_slice(chunk);
                let pk = PublicKey::from_bytes(&key_bytes).map_err(|_| BbP2pStatus::ErrInvalidArg)?;
                next_allowed.insert(pk);
            }
        }

        {
            let mut guard = ep
                .shared
                .allowed_peers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *guard = next_allowed.clone();
        }

        // Promote any pending peers now in the allowlist and sever any removed active peers.
        let to_revoke: Vec<EndpointId> = {
            let peers = ep.shared.peers.read().unwrap_or_else(|e| e.into_inner());
            let mut revoke = Vec::new();
            for (id, peer) in peers.iter() {
                if next_allowed.contains(id) {
                    peer.is_pending.store(false, Ordering::Release);
                } else {
                    revoke.push(*id);
                }
            }
            revoke
        };
        for peer_id in to_revoke {
            ep.shared.close_and_remove_peer(
                &peer_id,
                None,
                CLOSE_PEER_REVOKED,
                b"peer_removed_from_allowlist",
                true,
            );
        }
        Ok(())
    })
}

/// Additively inserts a single Ed25519 peer public key into the allowlist while respecting
/// `BB_P2P_MAX_ALLOWED_PEERS`. If the peer is currently connected as a pending LAN peer,
/// promotes the live connection to full Lanes 0/1/2 access without dropping it.
///
/// # Safety
/// `handle` must be a valid endpoint pointer and `peer_pubkey` must point to 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_allow_peer(
    handle: *mut BbP2pEndpoint,
    peer_pubkey: *const u8,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || peer_pubkey.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        if ep.shared.closed.load(Ordering::Acquire) {
            return Err(BbP2pStatus::ErrClosed);
        }
        let raw = unsafe { slice::from_raw_parts(peer_pubkey, BB_P2P_PUBKEY_LEN) };
        let mut key_bytes = [0u8; BB_P2P_PUBKEY_LEN];
        key_bytes.copy_from_slice(raw);
        let peer_id = PublicKey::from_bytes(&key_bytes).map_err(|_| BbP2pStatus::ErrInvalidArg)?;

        {
            let mut guard = ep
                .shared
                .allowed_peers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            if !guard.contains(&peer_id) {
                if guard.len() >= BB_P2P_MAX_ALLOWED_PEERS {
                    return Err(BbP2pStatus::ErrCapacity);
                }
                guard.insert(peer_id);
            }
        }

        // Promote any existing pending LAN connection cleanly without dropping it.
        {
            let peers = ep.shared.peers.read().unwrap_or_else(|e| e.into_inner());
            if let Some(peer) = peers.get(&peer_id) {
                peer.is_pending.store(false, Ordering::Release);
            }
        }
        Ok(())
    })
}

/// Enables or disables opt-in open LAN admission on `BB_P2P_NO_RELAYS` endpoints.
///
/// Fails closed with `BB_P2P_ERR_POLICY_VIOLATION` on `AllowRelays` or `ForceRelays` endpoints.
/// When disabled (`enabled == 0`), immediately closes all still-pending un-allowlisted peers
/// while preserving all already-allowlisted peers.
///
/// # Safety
/// `handle` must be a valid endpoint pointer created by `bb_p2p_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_set_lan_open_admission(
    handle: *mut BbP2pEndpoint,
    enabled: u8,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        if enabled > 1 {
            return Err(BbP2pStatus::ErrInvalidArg);
        }
        let ep = unsafe { &*handle };
        if ep.shared.closed.load(Ordering::Acquire) {
            return Err(BbP2pStatus::ErrClosed);
        }
        if ep.shared.relay_policy != BbP2pRelayPolicy::NoRelays {
            return Err(BbP2pStatus::ErrPolicyViolation);
        }

        let enable = enabled == 1;
        ep.shared.lan_open_admission.store(enable, Ordering::Release);

        if !enable {
            let drained_pending: Vec<(EndpointId, ActivePeer)> = {
                let mut peers = ep.shared.peers.write().unwrap_or_else(|e| e.into_inner());
                let pending_ids: Vec<EndpointId> = peers
                    .iter()
                    .filter(|(id, p)| {
                        p.is_pending.load(Ordering::Acquire) && !ep.shared.is_allowed(id)
                    })
                    .map(|(id, _)| *id)
                    .collect();
                let mut removed = Vec::with_capacity(pending_ids.len());
                for id in pending_ids {
                    if let Some(peer) = peers.remove(&id) {
                        removed.push((id, peer));
                    }
                }
                removed
            };
            for (peer_id, mut peer) in drained_pending {
                peer.conn
                    .close(VarInt::from_u32(CLOSE_UNAUTHORIZED), b"lan_admission_closed");
                peer.abort_tasks();
                ep.shared.events.push_lifecycle(QueuedEvent {
                    kind: BbP2pEventKind::PeerDisconnected,
                    lane: BbP2pLane::Control,
                    peer_pubkey: *peer_id.as_bytes(),
                    data: Vec::new(),
                    reason_code: CLOSE_UNAUTHORIZED,
                });
            }
        }
        Ok(())
    })
}

/// Removes a peer from the allowlist and immediately closes any active QUIC connection to it.
///
/// # Safety
/// `handle` must be a valid endpoint pointer and `pubkey_32b` must point to 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_revoke_peer(
    handle: *mut BbP2pEndpoint,
    pubkey_32b: *const u8,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || pubkey_32b.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        if ep.shared.closed.load(Ordering::Acquire) {
            return Err(BbP2pStatus::ErrClosed);
        }
        let raw = unsafe { slice::from_raw_parts(pubkey_32b, BB_P2P_PUBKEY_LEN) };
        let mut key_bytes = [0u8; BB_P2P_PUBKEY_LEN];
        key_bytes.copy_from_slice(raw);
        let peer_id = PublicKey::from_bytes(&key_bytes).map_err(|_| BbP2pStatus::ErrInvalidArg)?;

        {
            let mut guard = ep
                .shared
                .allowed_peers
                .write()
                .unwrap_or_else(|e| e.into_inner());
            guard.remove(&peer_id);
        }

        ep.shared.close_and_remove_peer(
            &peer_id,
            None,
            CLOSE_PEER_REVOKED,
            b"peer_revoked",
            true,
        );
        Ok(())
    })
}

/// Connects to an allowlisted peer and opens bidirectional Stream 0 (Control) and Stream 4 (Causal).
///
/// # Safety
/// `handle` and `target` must be valid pointers, and any slices referenced inside `target`
/// must remain valid for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_connect_peer(
    handle: *mut BbP2pEndpoint,
    target: *const BbP2pPeerTarget,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || target.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        if ep.shared.closed.load(Ordering::Acquire) {
            return Err(BbP2pStatus::ErrClosed);
        }
        let tgt = unsafe { &*target };
        let peer_id =
            PublicKey::from_bytes(&tgt.pubkey).map_err(|_| BbP2pStatus::ErrInvalidArg)?;
        if peer_id == ep.endpoint.id() {
            return Err(BbP2pStatus::ErrInvalidArg);
        }

        let remote_policy = BbP2pRelayPolicy::from_u32(tgt.remote_relay_policy)?;
        if !relay_policy_compatible(ep.shared.relay_policy, remote_policy) {
            return Err(BbP2pStatus::ErrPolicyViolation);
        }

        if tgt.direct_addrs_count > BB_P2P_MAX_DIRECT_ADDRS {
            return Err(BbP2pStatus::ErrInvalidArg);
        }
        if tgt.direct_addrs_count > 0 && tgt.direct_addrs.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let raw_relay_url = unsafe {
            read_optional_utf8(tgt.relay_url, tgt.relay_url_len, BB_P2P_MAX_RELAY_URL_BYTES)?
        };

        let mut transport_addrs: Vec<TransportAddr> = Vec::new();
        match ep.shared.relay_policy {
            BbP2pRelayPolicy::ForceRelays => {
                // True IP-hiding: never accept direct IP addresses, enforce pinned relay URL.
                if tgt.direct_addrs_count > 0 {
                    return Err(BbP2pStatus::ErrPolicyViolation);
                }
                let Some(pinned) = ep.shared.pinned_relay_url.as_ref() else {
                    return Err(BbP2pStatus::ErrPolicyViolation);
                };
                if let Some(raw) = raw_relay_url {
                    let parsed = validate_relay_url(raw)?;
                    if &parsed != pinned {
                        return Err(BbP2pStatus::ErrPolicyViolation);
                    }
                }
                transport_addrs.push(TransportAddr::Relay(pinned.clone()));
            }
            BbP2pRelayPolicy::NoRelays => {
                if raw_relay_url.is_some() {
                    return Err(BbP2pStatus::ErrPolicyViolation);
                }
                if tgt.direct_addrs_count == 0 {
                    return Err(BbP2pStatus::ErrInvalidArg);
                }
                let addrs = unsafe { slice::from_raw_parts(tgt.direct_addrs, tgt.direct_addrs_count) };
                for a in addrs {
                    transport_addrs.push(TransportAddr::Ip(direct_addr_to_socket_addr(a)?));
                }
            }
            BbP2pRelayPolicy::AllowRelays => {
                if remote_policy == BbP2pRelayPolicy::NoRelays && raw_relay_url.is_some() {
                    return Err(BbP2pStatus::ErrPolicyViolation);
                }
                if let Some(raw) = raw_relay_url {
                    transport_addrs.push(TransportAddr::Relay(validate_relay_url(raw)?));
                }
                if tgt.direct_addrs_count > 0 {
                    let addrs =
                        unsafe { slice::from_raw_parts(tgt.direct_addrs, tgt.direct_addrs_count) };
                    for a in addrs {
                        transport_addrs.push(TransportAddr::Ip(direct_addr_to_socket_addr(a)?));
                    }
                }
                if transport_addrs.is_empty() {
                    return Err(BbP2pStatus::ErrInvalidArg);
                }
            }
        }

        if !ep.shared.is_allowed(&peer_id) {
            return Err(BbP2pStatus::ErrNotAllowed);
        }

        // Reuse existing healthy connection if already connected.
        {
            let peers = ep.shared.peers.read().unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = peers.get(&peer_id)
                && existing.conn.close_reason().is_none()
            {
                return Ok(());
            }
        }

        let timeout_ms = if tgt.connect_timeout_ms == 0 {
            DEFAULT_CONNECT_TIMEOUT_MS
        } else {
            tgt.connect_timeout_ms
        };
        let timeout = Duration::from_millis(u64::from(timeout_ms));
        let endpoint_addr = EndpointAddr::from_parts(peer_id, transport_addrs);
        let endpoint = ep.endpoint.clone();
        let shared = Arc::clone(&ep.shared);

        ep.runtime.block_on(async move {
            let conn = tokio::time::timeout(timeout, endpoint.connect(endpoint_addr, BB_P2P_ALPN))
                .await
                .map_err(|_| BbP2pStatus::ErrTimeout)?
                .map_err(|e| map_endpoint_connect_error(&e))?;

            // Open Stream 0 (Control) and Stream 4 (Causal) in deterministic order.
            let setup = tokio::time::timeout(timeout, async {
                let (mut control_send, mut control_recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| map_connect_error(&e))?;
                if u64::from(control_send.id()) != STREAM_ID_CONTROL {
                    return Err(BbP2pStatus::ErrTransport);
                }
                let _ = control_send.set_priority(LANE_CONTROL_PRIORITY);
                control_send
                    .write_all(&STREAM_INIT_MARKER.to_le_bytes())
                    .await
                    .map_err(|_| match conn.close_reason() {
                        Some(reason) => map_connect_error(&reason),
                        None => BbP2pStatus::ErrTransport,
                    })?;

                let (mut causal_send, causal_recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| map_connect_error(&e))?;
                if u64::from(causal_send.id()) != STREAM_ID_CAUSAL {
                    return Err(BbP2pStatus::ErrTransport);
                }
                let _ = causal_send.set_priority(LANE_CAUSAL_PRIORITY);
                causal_send
                    .write_all(&STREAM_INIT_MARKER.to_le_bytes())
                    .await
                    .map_err(|_| match conn.close_reason() {
                        Some(reason) => map_connect_error(&reason),
                        None => BbP2pStatus::ErrTransport,
                    })?;

                // Await accepter's 4-byte readiness ACK on Stream 0 so unauthorized
                // rejections from the peer's after_handshake hook fail closed immediately.
                let mut ack = [0u8; 4];
                control_recv.read_exact(&mut ack).await.map_err(|_| {
                    match conn.close_reason() {
                        Some(reason) => map_connect_error(&reason),
                        None => BbP2pStatus::ErrTransport,
                    }
                })?;
                if u32::from_le_bytes(ack) != STREAM_INIT_MARKER {
                    return Err(BbP2pStatus::ErrTransport);
                }

                Ok((control_send, control_recv, causal_send, causal_recv))
            })
            .await;

            let (control_send, control_recv, causal_send, causal_recv) = match setup {
                Ok(Ok(streams)) => streams,
                Ok(Err(status)) => {
                    if conn.close_reason().is_none() {
                        conn.close(
                            VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                            b"connect_setup_failed",
                        );
                    }
                    return Err(status);
                }
                Err(_) => {
                    if conn.close_reason().is_none() {
                        conn.close(
                            VarInt::from_u32(CLOSE_PROTOCOL_VIOLATION),
                            b"connect_setup_timeout",
                        );
                    }
                    return Err(BbP2pStatus::ErrTimeout);
                }
            };

            register_active_peer(
                &shared,
                peer_id,
                conn,
                control_send,
                control_recv,
                causal_send,
                causal_recv,
                false,
                None,
            )
        })
    })
}

/// Sends a length-bounded frame on Lane 0 (Control), Lane 1 (Causal), or Lane 2 (RFC 9221 Datagram).
///
/// # Safety
/// `handle` must be a valid endpoint pointer, `peer_pk` must point to 32 readable bytes,
/// and when `len > 0`, `data` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_send_frame(
    handle: *mut BbP2pEndpoint,
    peer_pk: *const u8,
    lane: u32,
    data: *const u8,
    len: usize,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || peer_pk.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        if len > 0 && data.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        let ep = unsafe { &*handle };
        if ep.shared.closed.load(Ordering::Acquire) {
            return Err(BbP2pStatus::ErrClosed);
        }
        let lane = BbP2pLane::from_u32(lane)?;
        if len > lane.max_frame_bytes() {
            return Err(BbP2pStatus::ErrFrameTooLarge);
        }

        let raw_pk = unsafe { slice::from_raw_parts(peer_pk, BB_P2P_PUBKEY_LEN) };
        let mut key_bytes = [0u8; BB_P2P_PUBKEY_LEN];
        key_bytes.copy_from_slice(raw_pk);
        let peer_id = PublicKey::from_bytes(&key_bytes).map_err(|_| BbP2pStatus::ErrInvalidArg)?;

        let allowed = ep.shared.is_allowed(&peer_id);

        let payload = if len == 0 {
            Bytes::new()
        } else {
            let bytes = unsafe { slice::from_raw_parts(data, len) };
            Bytes::copy_from_slice(bytes)
        };

        let (conn, sender_opt) = {
            let peers = ep.shared.peers.read().unwrap_or_else(|e| e.into_inner());
            let Some(peer) = peers.get(&peer_id) else {
                return Err(if allowed {
                    BbP2pStatus::ErrNotConnected
                } else {
                    BbP2pStatus::ErrNotAllowed
                });
            };
            if !allowed {
                let can_send_pending_control = lane == BbP2pLane::Control
                    && peer.is_pending.load(Ordering::Acquire)
                    && ep.shared.is_lan_open_admission();
                if !can_send_pending_control {
                    return Err(BbP2pStatus::ErrNotAllowed);
                }
            }
            if peer.conn.close_reason().is_some() {
                return Err(BbP2pStatus::ErrNotConnected);
            }
            let tx = match lane {
                BbP2pLane::Control => Some(peer.control_tx.clone()),
                BbP2pLane::Causal => Some(peer.causal_tx.clone()),
                BbP2pLane::Ephemeral => None,
            };
            (peer.conn.clone(), tx)
        };

        match lane {
            BbP2pLane::Ephemeral => conn.send_datagram(payload).map_err(|err| match err {
                SendDatagramError::TooLarge => BbP2pStatus::ErrFrameTooLarge,
                SendDatagramError::ConnectionLost(_) => BbP2pStatus::ErrNotConnected,
                SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
                    BbP2pStatus::ErrUnsupported
                }
            }),
            BbP2pLane::Control | BbP2pLane::Causal => {
                let Some(tx) = sender_opt else {
                    return Err(BbP2pStatus::ErrNotConnected);
                };
                ep.runtime.block_on(async move {
                    match tokio::time::timeout(SEND_QUEUE_TIMEOUT, tx.send(payload)).await {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(_)) => Err(BbP2pStatus::ErrNotConnected),
                        Err(_) => Err(BbP2pStatus::ErrTimeout),
                    }
                })
            }
        }
    })
}

/// Polls the next peer lifecycle or received-frame event, waiting up to `timeout_ms`.
///
/// # Safety
/// `handle` and `out_event` must be valid non-null pointers. Any returned non-null `out_event.data`
/// buffer must be freed exactly once with `bb_p2p_free_bytes(out_event.data, out_event.data_len)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_poll_event(
    handle: *mut BbP2pEndpoint,
    timeout_ms: u32,
    out_event: *mut BbP2pEvent,
) -> BbP2pStatus {
    catch_ffi_status(|| {
        if handle.is_null() || out_event.is_null() {
            return Err(BbP2pStatus::ErrNullPointer);
        }
        unsafe {
            *out_event = BbP2pEvent {
                kind: BbP2pEventKind::None as u32,
                lane: 0,
                peer_pubkey: [0u8; BB_P2P_PUBKEY_LEN],
                data: ptr::null_mut(),
                data_len: 0,
                reason_code: 0,
            };
        }
        let ep = unsafe { &*handle };
        let ev = ep
            .shared
            .events
            .pop_timeout(Duration::from_millis(u64::from(timeout_ms)))?;

        let (data_ptr, data_len) = if ev.data.is_empty() {
            (ptr::null_mut(), 0)
        } else {
            let mut boxed = ev.data.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            let len = boxed.len();
            std::mem::forget(boxed);
            (ptr, len)
        };

        unsafe {
            *out_event = BbP2pEvent {
                kind: ev.kind as u32,
                lane: ev.lane as u32,
                peer_pubkey: ev.peer_pubkey,
                data: data_ptr,
                data_len,
                reason_code: ev.reason_code,
            };
        }
        Ok(())
    })
}

/// Releases a byte buffer previously returned by `bb_p2p_poll_event`.
///
/// # Safety
/// `ptr` must be null or a pointer returned in `BbP2pEvent.data` with the exact matching `len`,
/// and must not be freed more than once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bb_p2p_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let _ = panic::catch_unwind(AssertUnwindSafe(|| {
        unsafe {
            drop(Box::from_raw(ptr::slice_from_raw_parts_mut(ptr, len)));
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_no_relays_endpoint() -> (*mut BbP2pEndpoint, [u8; 32], Vec<BbP2pDirectAddr>) {
        let cfg = BbP2pCreateConfig {
            abi_version: BB_P2P_ABI_VERSION,
            relay_policy: BbP2pRelayPolicy::NoRelays as u32,
            secret_key: ptr::null(),
            relay_url: ptr::null(),
            relay_url_len: 0,
        };
        let mut handle: *mut BbP2pEndpoint = ptr::null_mut();
        let st = unsafe { bb_p2p_create(&cfg, &mut handle) };
        assert_eq!(st, BbP2pStatus::Ok);
        assert!(!handle.is_null());

        let mut pk = [0u8; 32];
        assert_eq!(unsafe { bb_p2p_local_pubkey(handle, pk.as_mut_ptr()) }, BbP2pStatus::Ok);

        let mut addrs = [BbP2pDirectAddr {
            family: 0,
            ip: [0u8; 16],
            port: 0,
        }; BB_P2P_MAX_DIRECT_ADDRS];
        let mut count: usize = 0;
        assert_eq!(
            unsafe { bb_p2p_local_direct_addrs(handle, addrs.as_mut_ptr(), addrs.len(), &mut count) },
            BbP2pStatus::Ok
        );
        assert!(count > 0, "no_relays endpoint should bind direct loopback address");
        (handle, pk, addrs[..count.min(addrs.len())].to_vec())
    }

    fn poll_next_frame(handle: *mut BbP2pEndpoint, expected_lane: BbP2pLane) -> ([u8; 32], Vec<u8>) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut ev = BbP2pEvent {
                kind: 0,
                lane: 0,
                peer_pubkey: [0u8; 32],
                data: ptr::null_mut(),
                data_len: 0,
                reason_code: 0,
            };
            let st = unsafe { bb_p2p_poll_event(handle, 500, &mut ev) };
            if st == BbP2pStatus::ErrTimeout {
                continue;
            }
            assert_eq!(st, BbP2pStatus::Ok);
            if ev.kind == BbP2pEventKind::FrameReceived as u32 {
                let bytes = if ev.data_len > 0 && !ev.data.is_null() {
                    let v = unsafe { slice::from_raw_parts(ev.data, ev.data_len) }.to_vec();
                    unsafe { bb_p2p_free_bytes(ev.data, ev.data_len) };
                    v
                } else {
                    Vec::new()
                };
                assert_eq!(ev.lane, expected_lane as u32);
                return (ev.peer_pubkey, bytes);
            }
            if !ev.data.is_null() {
                unsafe { bb_p2p_free_bytes(ev.data, ev.data_len) };
            }
        }
        panic!("timed out waiting for frame on lane {expected_lane:?}");
    }

    #[test]
    fn relay_policy_non_downgrade_matrix() {
        assert_eq!(
            bb_p2p_check_relay_policy(
                BbP2pRelayPolicy::ForceRelays as u32,
                BbP2pRelayPolicy::NoRelays as u32,
            ),
            BbP2pStatus::ErrPolicyViolation
        );
        assert_eq!(
            bb_p2p_check_relay_policy(
                BbP2pRelayPolicy::NoRelays as u32,
                BbP2pRelayPolicy::ForceRelays as u32,
            ),
            BbP2pStatus::ErrPolicyViolation
        );
        assert_eq!(
            bb_p2p_check_relay_policy(
                BbP2pRelayPolicy::AllowRelays as u32,
                BbP2pRelayPolicy::ForceRelays as u32,
            ),
            BbP2pStatus::ErrPolicyViolation
        );
        assert_eq!(
            bb_p2p_check_relay_policy(
                BbP2pRelayPolicy::ForceRelays as u32,
                BbP2pRelayPolicy::ForceRelays as u32,
            ),
            BbP2pStatus::Ok
        );
        assert_eq!(
            bb_p2p_check_relay_policy(
                BbP2pRelayPolicy::NoRelays as u32,
                BbP2pRelayPolicy::NoRelays as u32,
            ),
            BbP2pStatus::Ok
        );
    }

    #[test]
    fn force_relays_has_zero_direct_sockets_and_rejects_no_relays_dial() {
        let relay = "https://relay.multiplayer.tech";
        let cfg = BbP2pCreateConfig {
            abi_version: BB_P2P_ABI_VERSION,
            relay_policy: BbP2pRelayPolicy::ForceRelays as u32,
            secret_key: ptr::null(),
            relay_url: relay.as_ptr().cast(),
            relay_url_len: relay.len(),
        };
        let mut handle: *mut BbP2pEndpoint = ptr::null_mut();
        assert_eq!(unsafe { bb_p2p_create(&cfg, &mut handle) }, BbP2pStatus::Ok);

        // Zero direct IP sockets bound!
        let mut addrs = [BbP2pDirectAddr {
            family: 0,
            ip: [0u8; 16],
            port: 0,
        }; BB_P2P_MAX_DIRECT_ADDRS];
        let mut count: usize = 99;
        assert_eq!(
            unsafe { bb_p2p_local_direct_addrs(handle, addrs.as_mut_ptr(), addrs.len(), &mut count) },
            BbP2pStatus::Ok
        );
        assert_eq!(count, 0);

        let peer_sk = SecretKey::generate();
        let peer_pk = *peer_sk.public().as_bytes();
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(handle, peer_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );

        // Mismatched no_relays target is rejected cleanly.
        let target_mismatch = BbP2pPeerTarget {
            pubkey: peer_pk,
            remote_relay_policy: BbP2pRelayPolicy::NoRelays as u32,
            relay_url: ptr::null(),
            relay_url_len: 0,
            direct_addrs: ptr::null(),
            direct_addrs_count: 0,
            connect_timeout_ms: 1000,
        };
        assert_eq!(
            unsafe { bb_p2p_connect_peer(handle, &target_mismatch) },
            BbP2pStatus::ErrPolicyViolation
        );

        // Passing direct IP addrs under force_relays is also rejected cleanly.
        let direct = BbP2pDirectAddr {
            family: 4,
            ip: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 12345,
        };
        let target_direct_leak = BbP2pPeerTarget {
            pubkey: peer_pk,
            remote_relay_policy: BbP2pRelayPolicy::ForceRelays as u32,
            relay_url: relay.as_ptr().cast(),
            relay_url_len: relay.len(),
            direct_addrs: &direct,
            direct_addrs_count: 1,
            connect_timeout_ms: 1000,
        };
        assert_eq!(
            unsafe { bb_p2p_connect_peer(handle, &target_direct_leak) },
            BbP2pStatus::ErrPolicyViolation
        );

        unsafe { bb_p2p_destroy(handle) };
    }

    #[test]
    fn live_loopback_quic_tls13_rpk_three_lanes_allowlist_and_revoke() {
        let (alice, alice_pk, alice_addrs) = create_no_relays_endpoint();
        let (bob, bob_pk, _bob_addrs) = create_no_relays_endpoint();
        let (mallory, _mallory_pk, _mallory_addrs) = create_no_relays_endpoint();

        // 1. Mallory allowlists Alice, but Alice does NOT allowlist Mallory.
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(mallory, alice_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );
        let target_alice = BbP2pPeerTarget {
            pubkey: alice_pk,
            remote_relay_policy: BbP2pRelayPolicy::NoRelays as u32,
            relay_url: ptr::null(),
            relay_url_len: 0,
            direct_addrs: alice_addrs.as_ptr(),
            direct_addrs_count: alice_addrs.len(),
            connect_timeout_ms: 5000,
        };
        let mallory_res = unsafe { bb_p2p_connect_peer(mallory, &target_alice) };
        assert_eq!(
            mallory_res,
            BbP2pStatus::ErrNotAllowed,
            "unallowed mallory must be rejected immediately by alice"
        );

        // Verify Alice received zero events from Mallory.
        let mut ev = BbP2pEvent {
            kind: 0,
            lane: 0,
            peer_pubkey: [0u8; 32],
            data: ptr::null_mut(),
            data_len: 0,
            reason_code: 0,
        };
        assert_eq!(
            unsafe { bb_p2p_poll_event(alice, 150, &mut ev) },
            BbP2pStatus::ErrTimeout
        );

        // 2. Alice and Bob mutually allowlist each other.
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(alice, bob_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(bob, alice_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );

        // Bob dials Alice over loopback QUIC + TLS 1.3 RPK.
        assert_eq!(
            unsafe { bb_p2p_connect_peer(bob, &target_alice) },
            BbP2pStatus::Ok
        );

        // Wait for Alice to observe PEER_CONNECTED for Bob.
        let mut alice_saw_connect = false;
        for _ in 0..20 {
            let st = unsafe { bb_p2p_poll_event(alice, 250, &mut ev) };
            if st == BbP2pStatus::Ok && ev.kind == BbP2pEventKind::PeerConnected as u32 {
                assert_eq!(ev.peer_pubkey, bob_pk);
                alice_saw_connect = true;
                break;
            }
        }
        assert!(alice_saw_connect, "alice must observe bob connected");

        // 3. Exchange frames on all 3 lanes in BOTH directions.
        let ctrl_msg = b"control:grant-epoch-42";
        let causal_msg = vec![0x5Au8; 128 * 1024]; // 128 KiB (> Control limit, valid on Causal)
        let eph_msg = b"presence:online:flightdeck-tick-7";

        // Oversized control frame rejected before touching wire.
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    bob_pk.as_ptr(),
                    BbP2pLane::Control as u32,
                    causal_msg.as_ptr(),
                    causal_msg.len(),
                )
            },
            BbP2pStatus::ErrFrameTooLarge
        );

        // Oversized ephemeral datagram rejected before touching wire.
        let oversized_dgram = vec![0xABu8; BB_P2P_MAX_EPHEMERAL_FRAME_BYTES + 1];
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    bob_pk.as_ptr(),
                    BbP2pLane::Ephemeral as u32,
                    oversized_dgram.as_ptr(),
                    oversized_dgram.len(),
                )
            },
            BbP2pStatus::ErrFrameTooLarge
        );

        // Alice -> Bob on Lanes 0, 1, 2
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    bob_pk.as_ptr(),
                    BbP2pLane::Control as u32,
                    ctrl_msg.as_ptr(),
                    ctrl_msg.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got_ctrl) = poll_next_frame(bob, BbP2pLane::Control);
        assert_eq!(from, alice_pk);
        assert_eq!(got_ctrl, ctrl_msg);

        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    bob_pk.as_ptr(),
                    BbP2pLane::Causal as u32,
                    causal_msg.as_ptr(),
                    causal_msg.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got_causal) = poll_next_frame(bob, BbP2pLane::Causal);
        assert_eq!(from, alice_pk);
        assert_eq!(got_causal, causal_msg);

        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    bob_pk.as_ptr(),
                    BbP2pLane::Ephemeral as u32,
                    eph_msg.as_ptr(),
                    eph_msg.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got_eph) = poll_next_frame(bob, BbP2pLane::Ephemeral);
        assert_eq!(from, alice_pk);
        assert_eq!(got_eph, eph_msg);

        // Bob -> Alice on Lanes 0, 1, 2
        let bob_ctrl = b"bob-ctrl-ack";
        let bob_causal = b"bob-causal-checkpoint";
        let bob_eph = b"bob-telemetry-99";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    bob,
                    alice_pk.as_ptr(),
                    BbP2pLane::Control as u32,
                    bob_ctrl.as_ptr(),
                    bob_ctrl.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(alice, BbP2pLane::Control);
        assert_eq!(from, bob_pk);
        assert_eq!(got, bob_ctrl);

        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    bob,
                    alice_pk.as_ptr(),
                    BbP2pLane::Causal as u32,
                    bob_causal.as_ptr(),
                    bob_causal.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(alice, BbP2pLane::Causal);
        assert_eq!(from, bob_pk);
        assert_eq!(got, bob_causal);

        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    bob,
                    alice_pk.as_ptr(),
                    BbP2pLane::Ephemeral as u32,
                    bob_eph.as_ptr(),
                    bob_eph.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(alice, BbP2pLane::Ephemeral);
        assert_eq!(from, bob_pk);
        assert_eq!(got, bob_eph);

        // 4. Alice revokes Bob -> immediate QUIC connection close + send rejection.
        assert_eq!(unsafe { bb_p2p_revoke_peer(alice, bob_pk.as_ptr()) }, BbP2pStatus::Ok);
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    bob_pk.as_ptr(),
                    BbP2pLane::Control as u32,
                    ctrl_msg.as_ptr(),
                    ctrl_msg.len(),
                )
            },
            BbP2pStatus::ErrNotAllowed
        );

        // Bob must observe PEER_DISCONNECTED with CLOSE_PEER_REVOKED (4403).
        let mut bob_saw_disconnect = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let st = unsafe { bb_p2p_poll_event(bob, 250, &mut ev) };
            if st == BbP2pStatus::Ok && ev.kind == BbP2pEventKind::PeerDisconnected as u32 {
                assert_eq!(ev.peer_pubkey, alice_pk);
                assert_eq!(ev.reason_code, CLOSE_PEER_REVOKED);
                bob_saw_disconnect = true;
                break;
            }
            if !ev.data.is_null() {
                unsafe { bb_p2p_free_bytes(ev.data, ev.data_len) };
            }
        }
        assert!(bob_saw_disconnect, "bob must observe immediate disconnect on revoke");

        unsafe {
            bb_p2p_destroy(mallory);
            bb_p2p_destroy(bob);
            bb_p2p_destroy(alice);
        }
    }

    #[test]
    fn ffi_null_guards_and_deterministic_secret_key() {
        let mut handle: *mut BbP2pEndpoint = ptr::null_mut();
        assert_eq!(
            unsafe { bb_p2p_create(ptr::null(), &mut handle) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_local_pubkey(ptr::null(), ptr::null_mut()) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_local_direct_addrs(ptr::null(), ptr::null_mut(), 0, ptr::null_mut()) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(ptr::null_mut(), ptr::null(), 0) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_revoke_peer(ptr::null_mut(), ptr::null()) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_connect_peer(ptr::null_mut(), ptr::null()) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_send_frame(ptr::null_mut(), ptr::null(), 0, ptr::null(), 0) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_poll_event(ptr::null_mut(), 0, ptr::null_mut()) },
            BbP2pStatus::ErrNullPointer
        );
        unsafe {
            bb_p2p_destroy(ptr::null_mut());
            bb_p2p_free_bytes(ptr::null_mut(), 0);
        }

        // Deterministic 32-byte seed yields identical Ed25519 public key across instances.
        let seed = [0x42u8; 32];
        let cfg = BbP2pCreateConfig {
            abi_version: BB_P2P_ABI_VERSION,
            relay_policy: BbP2pRelayPolicy::NoRelays as u32,
            secret_key: seed.as_ptr(),
            relay_url: ptr::null(),
            relay_url_len: 0,
        };
        let mut h1: *mut BbP2pEndpoint = ptr::null_mut();
        let mut h2: *mut BbP2pEndpoint = ptr::null_mut();
        assert_eq!(unsafe { bb_p2p_create(&cfg, &mut h1) }, BbP2pStatus::Ok);
        assert_eq!(unsafe { bb_p2p_create(&cfg, &mut h2) }, BbP2pStatus::Ok);

        let mut pk1 = [0u8; 32];
        let mut pk2 = [0u8; 32];
        assert_eq!(unsafe { bb_p2p_local_pubkey(h1, pk1.as_mut_ptr()) }, BbP2pStatus::Ok);
        assert_eq!(unsafe { bb_p2p_local_pubkey(h2, pk2.as_mut_ptr()) }, BbP2pStatus::Ok);
        assert_eq!(pk1, pk2);

        // Bad ABI version fails closed.
        let bad_cfg = BbP2pCreateConfig {
            abi_version: 999,
            relay_policy: BbP2pRelayPolicy::NoRelays as u32,
            secret_key: ptr::null(),
            relay_url: ptr::null(),
            relay_url_len: 0,
        };
        let mut h3: *mut BbP2pEndpoint = ptr::null_mut();
        assert_eq!(
            unsafe { bb_p2p_create(&bad_cfg, &mut h3) },
            BbP2pStatus::ErrInvalidArg
        );
        assert!(h3.is_null());

        unsafe {
            bb_p2p_destroy(h1);
            bb_p2p_destroy(h2);
        }
    }

    #[test]
    fn direct_addr_rejects_unspecified_multicast_broadcast() {
        let bad_addrs = [
            // 0.0.0.0:4433 (IPv4 unspecified)
            BbP2pDirectAddr {
                family: 4,
                ip: [0; 16],
                port: 4433,
            },
            // 224.0.0.1:4433 (IPv4 multicast)
            BbP2pDirectAddr {
                family: 4,
                ip: [224, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 4433,
            },
            // 255.255.255.255:4433 (IPv4 broadcast)
            BbP2pDirectAddr {
                family: 4,
                ip: [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                port: 4433,
            },
            // [::]:4433 (IPv6 unspecified)
            BbP2pDirectAddr {
                family: 6,
                ip: [0; 16],
                port: 4433,
            },
            // [ff02::1]:4433 (IPv6 multicast)
            BbP2pDirectAddr {
                family: 6,
                ip: [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: 4433,
            },
            // [::ffff:0.0.0.0]:4433 (IPv4-mapped unspecified)
            BbP2pDirectAddr {
                family: 6,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0],
                port: 4433,
            },
            // [::ffff:255.255.255.255]:4433 (IPv4-mapped broadcast)
            BbP2pDirectAddr {
                family: 6,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 255, 255, 255, 255],
                port: 4433,
            },
        ];
        for bad in bad_addrs {
            assert_eq!(
                direct_addr_to_socket_addr(&bad),
                Err(BbP2pStatus::ErrInvalidArg),
                "invalid direct addr {bad:?} must be rejected"
            );
        }

        let good_v4 = BbP2pDirectAddr {
            family: 4,
            ip: [127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            port: 4433,
        };
        assert!(direct_addr_to_socket_addr(&good_v4).is_ok());

        let good_v6 = BbP2pDirectAddr {
            family: 6,
            ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 4433,
        };
        assert!(direct_addr_to_socket_addr(&good_v6).is_ok());
    }

    #[test]
    fn event_queue_control_prioritized_non_drop_and_bounded_lifecycle() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let queue = EventQueue::new();

        rt.block_on(async {
            // Saturate normal queue completely with Causal frames.
            for i in 0..MAX_QUEUED_EVENTS {
                queue
                    .push_causal(QueuedEvent {
                        kind: BbP2pEventKind::FrameReceived,
                        lane: BbP2pLane::Causal,
                        peer_pubkey: [1u8; 32],
                        data: (i as u32).to_le_bytes().to_vec(),
                        reason_code: 0,
                    })
                    .await;
            }

            // Push a Control frame while normal queue is 100% full: must NOT drop
            // and must NOT block on normal queue saturation.
            let ctrl_payload = b"urgent-revoke-control".to_vec();
            tokio::time::timeout(
                Duration::from_secs(1),
                queue.push_control(QueuedEvent {
                    kind: BbP2pEventKind::FrameReceived,
                    lane: BbP2pLane::Control,
                    peer_pubkey: [2u8; 32],
                    data: ctrl_payload.clone(),
                    reason_code: 0,
                }),
            )
            .await
            .expect("push_control must not stall when normal queue is full");

            // Popping must deliver Control FIRST (zero HoL blocking behind Causal).
            let first = queue
                .pop_timeout(Duration::from_millis(10))
                .expect("expected control frame first");
            assert_eq!(first.lane, BbP2pLane::Control);
            assert_eq!(first.data, ctrl_payload);

            // Next pop delivers the first Causal frame in exact FIFO order.
            let second = queue
                .pop_timeout(Duration::from_millis(10))
                .expect("expected first causal frame");
            assert_eq!(second.lane, BbP2pLane::Causal);
            assert_eq!(second.data, 0u32.to_le_bytes().to_vec());
        });

        // Lifecycle events must stay strictly bounded at MAX_PRIORITY_EVENTS.
        for i in 0..(MAX_PRIORITY_EVENTS + 64) {
            queue.push_lifecycle(QueuedEvent {
                kind: BbP2pEventKind::PeerDisconnected,
                lane: BbP2pLane::Control,
                peer_pubkey: [3u8; 32],
                data: Vec::new(),
                reason_code: i as u32,
            });
        }
        let prio_len = queue.inner.lock().expect("lock").priority.len();
        assert_eq!(prio_len, MAX_PRIORITY_EVENTS);
    }

    #[test]
    fn stream_eof_closes_connection_and_emits_disconnect() {
        let (alice, alice_pk, alice_addrs) = create_no_relays_endpoint();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("rt");

        let raw_sk = SecretKey::generate();
        let raw_pk = *raw_sk.public().as_bytes();
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(alice, raw_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );

        let alice_id = PublicKey::from_bytes(&alice_pk).expect("alice pk");
        let transport_addrs: Vec<TransportAddr> = alice_addrs
            .iter()
            .map(|a| TransportAddr::Ip(direct_addr_to_socket_addr(a).expect("addr")))
            .collect();
        let alice_ep_addr = EndpointAddr::from_parts(alice_id, transport_addrs);

        let raw_ep = rt.block_on(async move {
            let ep = Endpoint::builder(presets::Minimal)
                .secret_key(raw_sk)
                .alpns(vec![BB_P2P_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await
                .expect("bind raw ep");
            let conn = ep.connect(alice_ep_addr, BB_P2P_ALPN).await.expect("connect");

            let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.expect("open ctrl");
            ctrl_send
                .write_all(&STREAM_INIT_MARKER.to_le_bytes())
                .await
                .expect("write ctrl marker");
            let (mut caus_send, _caus_recv) = conn.open_bi().await.expect("open caus");
            caus_send
                .write_all(&STREAM_INIT_MARKER.to_le_bytes())
                .await
                .expect("write caus marker");
            let mut ack = [0u8; 4];
            ctrl_recv.read_exact(&mut ack).await.expect("read ack");
            assert_eq!(u32::from_le_bytes(ack), STREAM_INIT_MARKER);

            // Wait for Alice to register PEER_CONNECTED.
            let mut ev = BbP2pEvent {
                kind: 0,
                lane: 0,
                peer_pubkey: [0u8; 32],
                data: ptr::null_mut(),
                data_len: 0,
                reason_code: 0,
            };
            let mut connected = false;
            for _ in 0..20 {
                if unsafe { bb_p2p_poll_event(alice, 200, &mut ev) } == BbP2pStatus::Ok
                    && ev.kind == BbP2pEventKind::PeerConnected as u32
                {
                    connected = true;
                    break;
                }
            }
            assert!(connected, "alice must observe raw peer connected");

            // Send FIN on Stream 0 while keeping the QUIC connection alive!
            ctrl_send.finish().expect("finish ctrl stream");

            // Raw peer must observe Alice closing the QUIC connection with CLOSE_PROTOCOL_VIOLATION.
            let close_err = tokio::time::timeout(Duration::from_secs(5), conn.closed())
                .await
                .expect("alice must close QUIC connection on stream EOF");
            assert_eq!(close_reason_code(&close_err), CLOSE_PROTOCOL_VIOLATION);

            ep
        });

        // Alice must emit PEER_DISCONNECTED and reject subsequent sends (no zombie peer).
        let mut ev = BbP2pEvent {
            kind: 0,
            lane: 0,
            peer_pubkey: [0u8; 32],
            data: ptr::null_mut(),
            data_len: 0,
            reason_code: 0,
        };
        let mut disconnected = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if unsafe { bb_p2p_poll_event(alice, 200, &mut ev) } == BbP2pStatus::Ok
                && ev.kind == BbP2pEventKind::PeerDisconnected as u32
            {
                assert_eq!(ev.peer_pubkey, raw_pk);
                disconnected = true;
                break;
            }
        }
        assert!(disconnected, "alice must emit PEER_DISCONNECTED after stream EOF");

        let msg = b"after-eof";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    alice,
                    raw_pk.as_ptr(),
                    BbP2pLane::Control as u32,
                    msg.as_ptr(),
                    msg.len(),
                )
            },
            BbP2pStatus::ErrNotConnected
        );

        rt.block_on(raw_ep.close());
        unsafe { bb_p2p_destroy(alice) };
    }

    fn wait_for_peer_event(
        handle: *mut BbP2pEndpoint,
        expected_kind: BbP2pEventKind,
        expected_peer: [u8; 32],
    ) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut ev = BbP2pEvent {
                kind: 0,
                lane: 0,
                peer_pubkey: [0u8; 32],
                data: ptr::null_mut(),
                data_len: 0,
                reason_code: 0,
            };
            let st = unsafe { bb_p2p_poll_event(handle, 200, &mut ev) };
            if st == BbP2pStatus::ErrTimeout {
                continue;
            }
            assert_eq!(st, BbP2pStatus::Ok);
            if !ev.data.is_null() {
                unsafe { bb_p2p_free_bytes(ev.data, ev.data_len) };
            }
            if ev.kind == expected_kind as u32 && ev.peer_pubkey == expected_peer {
                return ev.reason_code;
            }
        }
        panic!("timed out waiting for {expected_kind:?} for peer");
    }

    fn target_for(host_pk: [u8; 32], host_addrs: &[BbP2pDirectAddr]) -> BbP2pPeerTarget {
        BbP2pPeerTarget {
            pubkey: host_pk,
            remote_relay_policy: BbP2pRelayPolicy::NoRelays as u32,
            relay_url: ptr::null(),
            relay_url_len: 0,
            direct_addrs: host_addrs.as_ptr(),
            direct_addrs_count: host_addrs.len(),
            connect_timeout_ms: 5000,
        }
    }

    #[test]
    fn lan_open_admission_fails_closed_on_online_relay_policies() {
        // Null & invalid flag guards.
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(ptr::null_mut(), 1) },
            BbP2pStatus::ErrNullPointer
        );
        assert_eq!(
            unsafe { bb_p2p_allow_peer(ptr::null_mut(), ptr::null()) },
            BbP2pStatus::ErrNullPointer
        );

        // AllowRelays endpoint must fail closed with ErrPolicyViolation.
        let relay = "https://relay.multiplayer.tech";
        let allow_cfg = BbP2pCreateConfig {
            abi_version: BB_P2P_ABI_VERSION,
            relay_policy: BbP2pRelayPolicy::AllowRelays as u32,
            secret_key: ptr::null(),
            relay_url: relay.as_ptr().cast(),
            relay_url_len: relay.len(),
        };
        let mut allow_ep: *mut BbP2pEndpoint = ptr::null_mut();
        assert_eq!(
            unsafe { bb_p2p_create(&allow_cfg, &mut allow_ep) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(allow_ep, 1) },
            BbP2pStatus::ErrPolicyViolation
        );
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(allow_ep, 0) },
            BbP2pStatus::ErrPolicyViolation
        );
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(allow_ep, 2) },
            BbP2pStatus::ErrInvalidArg
        );
        unsafe { bb_p2p_destroy(allow_ep) };

        // ForceRelays endpoint must fail closed with ErrPolicyViolation.
        let force_cfg = BbP2pCreateConfig {
            abi_version: BB_P2P_ABI_VERSION,
            relay_policy: BbP2pRelayPolicy::ForceRelays as u32,
            secret_key: ptr::null(),
            relay_url: relay.as_ptr().cast(),
            relay_url_len: relay.len(),
        };
        let mut force_ep: *mut BbP2pEndpoint = ptr::null_mut();
        assert_eq!(
            unsafe { bb_p2p_create(&force_cfg, &mut force_ep) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(force_ep, 1) },
            BbP2pStatus::ErrPolicyViolation
        );
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(force_ep, 0) },
            BbP2pStatus::ErrPolicyViolation
        );
        unsafe { bb_p2p_destroy(force_ep) };
    }

    #[test]
    fn lan_open_admission_pending_lane_enforcement_promotion_and_lock() {
        let (host, host_pk, host_addrs) = create_no_relays_endpoint();
        let (peer_a, pk_a, _) = create_no_relays_endpoint();
        let (peer_b, pk_b, _) = create_no_relays_endpoint();
        let (peer_c, pk_c, _) = create_no_relays_endpoint();
        let (peer_d, pk_d, _) = create_no_relays_endpoint();
        let (peer_e, pk_e, _) = create_no_relays_endpoint();
        let (peer_f, _pk_f, _) = create_no_relays_endpoint();

        let host_target = target_for(host_pk, &host_addrs);
        for p in [peer_a, peer_b, peer_c, peer_d, peer_e, peer_f] {
            assert_eq!(
                unsafe { bb_p2p_set_allowed_peers(p, host_pk.as_ptr(), 1) },
                BbP2pStatus::Ok
            );
        }

        // Default on NoRelays is strict allowlist (closed).
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_a, &host_target) },
            BbP2pStatus::ErrNotAllowed
        );

        // Enable open LAN admission on host.
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(host, 2) },
            BbP2pStatus::ErrInvalidArg
        );
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(host, 1) },
            BbP2pStatus::Ok
        );

        // 1. Un-allowlisted peer A connects as pending and exchanges Lane 0 Control frames.
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_a, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, pk_a);

        // Host cannot send Lane 1 or Lane 2 to pending peer A before promotion.
        let blocked = b"not-yet-promoted";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    host,
                    pk_a.as_ptr(),
                    BbP2pLane::Causal as u32,
                    blocked.as_ptr(),
                    blocked.len(),
                )
            },
            BbP2pStatus::ErrNotAllowed
        );
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    host,
                    pk_a.as_ptr(),
                    BbP2pLane::Ephemeral as u32,
                    blocked.as_ptr(),
                    blocked.len(),
                )
            },
            BbP2pStatus::ErrNotAllowed
        );

        // Host <-> pending peer A exchange Lane 0 handshake frames.
        let lan_hello = b"LAN_HELLO:nonce=0123456789abcdef";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    host,
                    pk_a.as_ptr(),
                    BbP2pLane::Control as u32,
                    lan_hello.as_ptr(),
                    lan_hello.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(peer_a, BbP2pLane::Control);
        assert_eq!(from, host_pk);
        assert_eq!(got, lan_hello);

        let lan_join = b"LAN_JOIN:pin_proof=ok";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    peer_a,
                    host_pk.as_ptr(),
                    BbP2pLane::Control as u32,
                    lan_join.as_ptr(),
                    lan_join.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(host, BbP2pLane::Control);
        assert_eq!(from, pk_a);
        assert_eq!(got, lan_join);

        // 2. Pending peer B sending Lane 1 (Causal) is dropped & closed with CLOSE_PROTOCOL_VIOLATION.
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_b, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, pk_b);

        let rogue_causal = b"rogue-causal-before-pin";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    peer_b,
                    host_pk.as_ptr(),
                    BbP2pLane::Causal as u32,
                    rogue_causal.as_ptr(),
                    rogue_causal.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let host_b_disc = wait_for_peer_event(host, BbP2pEventKind::PeerDisconnected, pk_b);
        assert_eq!(host_b_disc, CLOSE_PROTOCOL_VIOLATION);
        let b_disc = wait_for_peer_event(peer_b, BbP2pEventKind::PeerDisconnected, host_pk);
        assert_eq!(b_disc, CLOSE_PROTOCOL_VIOLATION);

        // 3. Pending peer C sending Lane 2 (Ephemeral) is dropped & closed with CLOSE_PROTOCOL_VIOLATION.
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_c, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, pk_c);

        let rogue_dgram = b"rogue-dgram-before-pin";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    peer_c,
                    host_pk.as_ptr(),
                    BbP2pLane::Ephemeral as u32,
                    rogue_dgram.as_ptr(),
                    rogue_dgram.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let host_c_disc = wait_for_peer_event(host, BbP2pEventKind::PeerDisconnected, pk_c);
        assert_eq!(host_c_disc, CLOSE_PROTOCOL_VIOLATION);
        let c_disc = wait_for_peer_event(peer_c, BbP2pEventKind::PeerDisconnected, host_pk);
        assert_eq!(c_disc, CLOSE_PROTOCOL_VIOLATION);

        // 4. Pending peer D rejected via bb_p2p_revoke_peer closes immediately with CLOSE_PEER_REVOKED.
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_d, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, pk_d);
        assert_eq!(
            unsafe { bb_p2p_revoke_peer(host, pk_d.as_ptr()) },
            BbP2pStatus::Ok
        );
        let d_disc = wait_for_peer_event(peer_d, BbP2pEventKind::PeerDisconnected, host_pk);
        assert_eq!(d_disc, CLOSE_PEER_REVOKED);

        // 5. Host promotes pending peer A via bb_p2p_allow_peer (idempotent) without dropping conn.
        assert_eq!(
            unsafe { bb_p2p_allow_peer(host, pk_a.as_ptr()) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_allow_peer(host, pk_a.as_ptr()) },
            BbP2pStatus::Ok
        );

        let causal_a2h = b"promoted-causal-from-a";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    peer_a,
                    host_pk.as_ptr(),
                    BbP2pLane::Causal as u32,
                    causal_a2h.as_ptr(),
                    causal_a2h.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(host, BbP2pLane::Causal);
        assert_eq!(from, pk_a);
        assert_eq!(got, causal_a2h);

        let causal_h2a = b"promoted-causal-from-host";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    host,
                    pk_a.as_ptr(),
                    BbP2pLane::Causal as u32,
                    causal_h2a.as_ptr(),
                    causal_h2a.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(peer_a, BbP2pLane::Causal);
        assert_eq!(from, host_pk);
        assert_eq!(got, causal_h2a);

        // 6. Connect pending peer E, then lock lobby via set_lan_open_admission(0):
        //    E must be immediately closed while promoted peer A stays connected!
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_e, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, pk_e);

        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(host, 0) },
            BbP2pStatus::Ok
        );
        let host_e_disc = wait_for_peer_event(host, BbP2pEventKind::PeerDisconnected, pk_e);
        assert_eq!(host_e_disc, CLOSE_UNAUTHORIZED);
        let e_disc = wait_for_peer_event(peer_e, BbP2pEventKind::PeerDisconnected, host_pk);
        assert_eq!(e_disc, CLOSE_UNAUTHORIZED);

        // New un-allowlisted peer F is rejected after lock.
        assert_eq!(
            unsafe { bb_p2p_connect_peer(peer_f, &host_target) },
            BbP2pStatus::ErrNotAllowed
        );

        // Promoted peer A still exchanges Causal frames cleanly!
        let post_lock = b"causal-after-lobby-lock";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    peer_a,
                    host_pk.as_ptr(),
                    BbP2pLane::Causal as u32,
                    post_lock.as_ptr(),
                    post_lock.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(host, BbP2pLane::Causal);
        assert_eq!(from, pk_a);
        assert_eq!(got, post_lock);

        for p in [peer_f, peer_e, peer_d, peer_c, peer_b, peer_a, host] {
            unsafe { bb_p2p_destroy(p) };
        }
    }

    #[test]
    fn lan_open_admission_enforces_16_pending_peer_cap() {
        let (host, host_pk, host_addrs) = create_no_relays_endpoint();
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(host, 1) },
            BbP2pStatus::Ok
        );
        let host_target = target_for(host_pk, &host_addrs);

        let mut pending_peers = Vec::with_capacity(BB_P2P_MAX_PENDING_LAN_PEERS);
        for _ in 0..BB_P2P_MAX_PENDING_LAN_PEERS {
            let (ep, pk, _) = create_no_relays_endpoint();
            assert_eq!(
                unsafe { bb_p2p_set_allowed_peers(ep, host_pk.as_ptr(), 1) },
                BbP2pStatus::Ok
            );
            assert_eq!(
                unsafe { bb_p2p_connect_peer(ep, &host_target) },
                BbP2pStatus::Ok
            );
            wait_for_peer_event(host, BbP2pEventKind::PeerConnected, pk);
            pending_peers.push((ep, pk));
        }

        // 17th un-allowlisted peer MUST be rejected with CLOSE_UNAUTHORIZED -> ErrNotAllowed.
        let (overflow_ep, overflow_pk, _) = create_no_relays_endpoint();
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(overflow_ep, host_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_connect_peer(overflow_ep, &host_target) },
            BbP2pStatus::ErrNotAllowed
        );

        // Already-allowlisted peer MUST still connect even while 16 pending slots are full.
        let (vip_ep, vip_pk, _) = create_no_relays_endpoint();
        assert_eq!(
            unsafe { bb_p2p_allow_peer(host, vip_pk.as_ptr()) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(vip_ep, host_pk.as_ptr(), 1) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_connect_peer(vip_ep, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, vip_pk);

        // Promoting 1 pending peer frees 1 pending slot so overflow_ep can now connect!
        let promoted_pk = pending_peers[0].1;
        assert_eq!(
            unsafe { bb_p2p_allow_peer(host, promoted_pk.as_ptr()) },
            BbP2pStatus::Ok
        );
        assert_eq!(
            unsafe { bb_p2p_connect_peer(overflow_ep, &host_target) },
            BbP2pStatus::Ok
        );
        wait_for_peer_event(host, BbP2pEventKind::PeerConnected, overflow_pk);

        // Closing open admission closes all remaining pending peers while keeping vip_ep alive.
        assert_eq!(
            unsafe { bb_p2p_set_lan_open_admission(host, 0) },
            BbP2pStatus::Ok
        );
        let overflow_disc =
            wait_for_peer_event(overflow_ep, BbP2pEventKind::PeerDisconnected, host_pk);
        assert_eq!(overflow_disc, CLOSE_UNAUTHORIZED);

        let vip_msg = b"vip-still-alive";
        assert_eq!(
            unsafe {
                bb_p2p_send_frame(
                    vip_ep,
                    host_pk.as_ptr(),
                    BbP2pLane::Causal as u32,
                    vip_msg.as_ptr(),
                    vip_msg.len(),
                )
            },
            BbP2pStatus::Ok
        );
        let (from, got) = poll_next_frame(host, BbP2pLane::Causal);
        assert_eq!(from, vip_pk);
        assert_eq!(got, vip_msg);

        unsafe {
            bb_p2p_destroy(overflow_ep);
            bb_p2p_destroy(vip_ep);
            for (ep, _) in pending_peers {
                bb_p2p_destroy(ep);
            }
            bb_p2p_destroy(host);
        }
    }

    #[test]
    fn allow_peer_respects_max_allowed_peers_capacity() {
        let (host, _, _) = create_no_relays_endpoint();
        let mut keys = Vec::with_capacity(BB_P2P_MAX_ALLOWED_PEERS * BB_P2P_PUBKEY_LEN);
        let mut first_pk = [0u8; 32];
        for i in 0..BB_P2P_MAX_ALLOWED_PEERS {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
            let pk = *SecretKey::from_bytes(&seed).public().as_bytes();
            if i == 0 {
                first_pk = pk;
            }
            keys.extend_from_slice(&pk);
        }
        assert_eq!(
            unsafe { bb_p2p_set_allowed_peers(host, keys.as_ptr(), BB_P2P_MAX_ALLOWED_PEERS) },
            BbP2pStatus::Ok
        );
        // Re-allowing an already-present peer succeeds (idempotent).
        assert_eq!(
            unsafe { bb_p2p_allow_peer(host, first_pk.as_ptr()) },
            BbP2pStatus::Ok
        );
        // Adding a 1025th distinct peer fails closed with ErrCapacity.
        let extra_pk = *SecretKey::generate().public().as_bytes();
        assert_eq!(
            unsafe { bb_p2p_allow_peer(host, extra_pk.as_ptr()) },
            BbP2pStatus::ErrCapacity
        );
        unsafe { bb_p2p_destroy(host) };
    }
}
