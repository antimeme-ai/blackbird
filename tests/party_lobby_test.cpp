#include "blackbird/party_lobby.hpp"

#include "blackbird/json.hpp"
#include "blackbird/party_chat.hpp"
#include "blackbird/peer_identity.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

namespace fs = std::filesystem;

const char *g_stage = "startup";

void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(std::string{g_stage} + ": " + message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: " + error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void must_void(Result<void> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{g_stage} + " [" + context +
                             "]: " + error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
}

struct TempDir {
  fs::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
};

bool has_any_party_json(const fs::path &root) {
  if (!fs::exists(root))
    return false;
  for (const auto &entry : fs::recursive_directory_iterator(root)) {
    if (entry.path().filename() == "party.json")
      return true;
  }
  return false;
}

struct LeaseSpec {
  std::string room_id;
  std::string alias;
  PartyMemberRole role = PartyMemberRole::worker;
  std::int64_t issued_ns = 0;
  std::int64_t ttl_ns = kPartyLobbyDefaultTtlNs;
  std::uint64_t revocation_epoch = 0;
  std::uint64_t seq = 1;
};

PartyLease make_signed_lease(const PeerIdentityStore &identity, const LeaseSpec &spec) {
  PartyLease draft{};
  draft.room_id = spec.room_id;
  draft.alias = spec.alias;
  draft.role = spec.role;
  draft.host = "macbook-air";
  draft.model = "claude-opus-4-6";
  draft.issued_ns = spec.issued_ns;
  draft.expires_ns = spec.issued_ns + spec.ttl_ns;
  draft.lease_seq = spec.seq;
  draft.revocation_epoch = spec.revocation_epoch;
  return must(sign_party_lease(identity, std::move(draft)), "sign_party_lease");
}

std::string send_raw_unix_frame(const fs::path &socket_path,
                                std::string_view raw_bytes) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  require(fd >= 0, "raw socket failed");
#ifdef SO_NOSIGPIPE
  const int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string &native = socket_path.native();
  require(native.size() < sizeof(addr.sun_path), "socket path too long");
  std::memcpy(addr.sun_path, native.data(), native.size());
  require(::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0,
          "raw connect failed");

  std::size_t off = 0;
  while (off < raw_bytes.size()) {
#ifdef MSG_NOSIGNAL
    const ssize_t n =
        ::send(fd, raw_bytes.data() + off, raw_bytes.size() - off, MSG_NOSIGNAL);
#else
    const ssize_t n = ::send(fd, raw_bytes.data() + off, raw_bytes.size() - off, 0);
#endif
    if (n <= 0) {
      if (n < 0 && errno == EINTR)
        continue;
      break;
    }
    off += static_cast<std::size_t>(n);
  }

  std::string reply;
  std::array<char, 4096> buf{};
  for (;;) {
    pollfd pfd{fd, POLLIN, 0};
    const int prc = ::poll(&pfd, 1, 2000);
    if (prc <= 0)
      break;
    const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
    if (n <= 0)
      break;
    reply.append(buf.data(), static_cast<std::size_t>(n));
    if (reply.find('\n') != std::string::npos)
      break;
  }
  (void)::close(fd);
  return reply;
}

void test_socket_path_resolution_and_dir_hardening() {
  g_stage = "socket_path_resolution_and_dir_hardening";
  const auto xdg_path = resolve_party_socket_path("/run/user/1000", 1000);
  require(xdg_path == fs::path{"/run/user/1000/blackbird/party.sock"},
          "XDG_RUNTIME_DIR path mismatch");

  const auto fallback = resolve_party_socket_path(std::nullopt, 501);
  require(fallback == fs::path{"/tmp/blackbird-501/party.sock"},
          "fallback /tmp/blackbird-<uid>/party.sock mismatch");

  const auto empty_xdg = resolve_party_socket_path("", 501);
  require(empty_xdg == fs::path{"/tmp/blackbird-501/party.sock"},
          "empty XDG_RUNTIME_DIR should fall back");

  // Reject `..` traversal components and control chars in XDG_RUNTIME_DIR.
  const auto dotdot_xdg = resolve_party_socket_path("/run/user/../etc", 501);
  require(dotdot_xdg == fs::path{"/tmp/blackbird-501/party.sock"},
          "traversal in XDG_RUNTIME_DIR should fall back");
  const auto ctrl_xdg =
      resolve_party_socket_path(std::string_view{"/run/user/\x1b[31m"}, 501);
  require(ctrl_xdg == fs::path{"/tmp/blackbird-501/party.sock"},
          "control char in XDG_RUNTIME_DIR should fall back");
  const auto bidi_xdg = resolve_party_socket_path("/run/user/\xe2\x80\xae", 501);
  require(bidi_xdg == fs::path{"/tmp/blackbird-501/party.sock"},
          "BiDi control in XDG_RUNTIME_DIR should fall back");

  TempDir base("bb-lobby-sec");
  // Reject 0755 parent directory.
  const fs::path loose_dir = base.path / "loose";
  require(::mkdir(loose_dir.c_str(), mode_t{0755}) == 0, "mkdir loose");
  require(::chmod(loose_dir.c_str(), mode_t{0755}) == 0, "chmod loose");
  PartyLobbyServerConfig loose_cfg{};
  loose_cfg.socket_path = loose_dir / "party.sock";
  require(!PartyLobbyServer::start(loose_cfg).has_value(),
          "server accepted 0755 parent directory");

  // Reject symlink parent directory.
  const fs::path real_dir = base.path / "real0700";
  require(::mkdir(real_dir.c_str(), mode_t{0700}) == 0, "mkdir real0700");
  const fs::path link_dir = base.path / "symlink_dir";
  require(::symlink(real_dir.c_str(), link_dir.c_str()) == 0, "symlink dir");
  PartyLobbyServerConfig link_cfg{};
  link_cfg.socket_path = link_dir / "party.sock";
  require(!PartyLobbyServer::start(link_cfg).has_value(),
          "server accepted symlink parent directory");
}

void test_solo_startup_permissions_and_zero_disk_party_json() {
  g_stage = "solo_startup_permissions_and_zero_disk_party_json";
  TempDir base("bb-lobby-solo");
  const fs::path sock_dir = base.path / "run";
  const fs::path sock_path = sock_dir / "party.sock";

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  auto server = must(PartyLobbyServer::start(cfg), "start server");
  require(server->running(), "server not running");

  // Verify 0700 parent dir and 0600 socket owned by geteuid().
  struct stat dir_st{};
  require(::lstat(sock_dir.c_str(), &dir_st) == 0 && S_ISDIR(dir_st.st_mode) &&
              dir_st.st_uid == ::geteuid() && (dir_st.st_mode & 0777) == 0700,
          "socket parent dir must be 0700 owned by geteuid()");
  struct stat sock_st{};
  require(::lstat(sock_path.c_str(), &sock_st) == 0 && S_ISSOCK(sock_st.st_mode) &&
              sock_st.st_uid == ::geteuid() && (sock_st.st_mode & 0777) == 0600,
          "party.sock must be 0600 owned by geteuid()");

  auto client = must(PartyLobbyClient::connect(sock_path), "connect client");
  const auto pong = must(client.ping(), "ping");
  require(pong.ok && pong.protocol_version == kPartyLobbyProtocolVersion &&
              pong.revocation_epoch == 0 && !pong.active_room_id.has_value() &&
              pong.room_count == 0,
          "unexpected initial ping");

  const auto snap = must(client.snapshot(), "initial snapshot");
  require(snap.room_scope.empty() && snap.participants.empty() &&
              snap.messages.empty() && !snap.party_config_present,
          "initial snapshot must be SOLO / empty");
  require(!has_any_party_json(base.path), "party.json must NEVER be created on disk");

  must_void(client.shutdown(), "shutdown rpc");
  client.close();
  server->stop();
  require(!fs::exists(sock_path), "party.sock must be unlinked on clean stop");
}

void test_room_leases_invite_friend_modes_and_wire_ssh_target_strip() {
  g_stage = "room_leases_invite_friend_modes_and_wire_ssh_target_strip";
  TempDir base("bb-lobby-room");
  auto local_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-local"), "local id");
  auto winter_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-winter"), "winter id");
  auto mallory_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-mallory"), "mallory id");

  auto peers = must(KnownPeersStore::open(base.path / "peers"), "open peers");
  (void)must(peers.pin_peer(PinPeerRequest{
                 "wintermute",
                 winter_id.identity().public_key,
                 "trusted colleague ssh_target=winter@10.0.0.42",
             }),
             "pin wintermute");

  std::atomic<std::int64_t> fake_now{1700000000LL * 1000000000LL};
  const fs::path sock_path = base.path / "run" / "party.sock";

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  cfg.local_identity_dir = local_id.root();
  cfg.known_peers_dir = peers.root();
  cfg.clock_now_ns = [&fake_now]() { return fake_now.load(); };

  auto server = must(PartyLobbyServer::start(cfg), "start server");
  auto client = must(PartyLobbyClient::connect(sock_path), "connect");

  // list_friends() returns pinned non-revoked peers from KnownPeersStore.
  const auto friends = must(client.list_friends(), "list_friends");
  require(friends.size() == 1U && friends[0].alias == "wintermute" &&
              friends[0].fingerprint == winter_id.identity().fingerprint,
          "list_friends mismatch");

  // create_room("party/rollcall") with signed local operator lease.
  const PartyLease host_lease = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs});
  const auto created =
      must(client.create_room("party/rollcall", host_lease), "create_room");
  require(created.room_scope == "party/rollcall" &&
              created.mode == PartyMode::single_operator &&
              created.participants.size() == 1U && created.participants[0].local_self &&
              created.participants[0].id == "patrick",
          "create_room snapshot mismatch");

  // invite_friend("wintermute") resolves automatically from KnownPeersStore without
  // passing a fingerprint!
  const auto invited =
      must(client.invite_friend("party/rollcall", "wintermute"), "invite_friend");
  require(invited.id == "wintermute" &&
              invited.fingerprint == winter_id.identity().fingerprint &&
              invited.role == PartyMemberRole::platoon_leader &&
              invited.state == PartyParticipantState::offline &&
              invited.ssh_target.has_value() &&
              *invited.ssh_target == "winter@10.0.0.42",
          "invited friend slot mismatch");

  // Reject inviting unknown friend alias.
  const auto bad_inv = client.invite_friend("party/rollcall", "stranger");
  require(!bad_inv.has_value() && bad_inv.error().code == ErrorCode::invalid_identity,
          "unknown friend invite must fail with invalid_identity");

  // Signed remote peer lease join as platoon_leader -> single_operator mode.
  const PartyLease winter_leader = make_signed_lease(
      winter_id, {"party/rollcall", "wintermute", PartyMemberRole::platoon_leader,
                  fake_now.load(), kPartyLobbyDefaultTtlNs, 0, 1});
  const auto snap_single =
      must(client.join_room("party/rollcall", winter_leader), "winter join leader");
  require(snap_single.mode == PartyMode::single_operator &&
              snap_single.participants.size() == 2U,
          "single_operator mode expected with 1 operator + 1 leader");

  // Verify untrusted wire ssh_target injection is ALWAYS stripped!
  const PartyLease winter_op = make_signed_lease(
      winter_id, {"party/rollcall", "wintermute", PartyMemberRole::operator_human,
                  fake_now.load(), kPartyLobbyDefaultTtlNs, 0, 2});
  const Value evil_req = Value::object({
      {"v", Value{Number{kPartyLobbyProtocolVersion}}},
      {"op", Value{"join_room"}},
      {"params",
       Value::object({
           {"room_id", Value{"party/rollcall"}},
           {"lease",
            Value::object({
                {"room_id", Value{winter_op.room_id}},
                {"actor_fingerprint", Value{winter_op.actor_fingerprint}},
                {"alias", Value{winter_op.alias}},
                {"role", Value{"operator_human"}},
                {"host", Value{winter_op.host}},
                {"model", Value{winter_op.model}},
                {"ssh_target", Value{"evil@attacker.example"}},
                {"issued_ns", Value{Number{winter_op.issued_ns}}},
                {"expires_ns", Value{Number{winter_op.expires_ns}}},
                {"lease_seq", Value{Number{winter_op.lease_seq}}},
                {"revocation_epoch", Value{Number{winter_op.revocation_epoch}}},
                {"signature_b64", Value{winter_op.signature_b64}},
            })},
       })},
  });
  const std::string evil_line = must(dump_json(evil_req), "dump evil req") + "\n";
  const std::string evil_reply = send_raw_unix_frame(sock_path, evil_line);
  require(
      evil_reply.find("\"ok\":true") != std::string::npos,
      "signed wintermute upgrade should succeed while stripping untrusted ssh_target");
  require(evil_reply.find("attacker.example") == std::string::npos,
          "untrusted wire ssh_target leaked into server state!");

  // Now 2 distinct operator_human members -> multi_operator mode!
  const auto snap_multi = must(client.snapshot(), "snapshot multi");
  require(snap_multi.mode == PartyMode::multi_operator &&
              snap_multi.participants.size() == 2U,
          "multi_operator mode expected with 2 operator_human participants");
  for (const auto &p : snap_multi.participants) {
    if (p.id == "wintermute") {
      require(p.state == PartyParticipantState::online && p.ssh_target.has_value() &&
                  *p.ssh_target == "winter@10.0.0.42",
              "wintermute ssh_target must come ONLY from trusted KnownPeersStore");
    }
  }

  // Heartbeat renewal works with valid Ed25519 signature.
  const std::int64_t earlier_exp = fake_now.load() + 450LL * 1000000000LL;
  const std::string earlier_hb_sig =
      must(sign_party_heartbeat(winter_id, "party/rollcall", earlier_exp, 0),
           "sign earlier hb");
  const std::int64_t renewed_exp = fake_now.load() + 600LL * 1000000000LL;
  const std::string hb_sig = must(
      sign_party_heartbeat(winter_id, "party/rollcall", renewed_exp, 0), "sign hb");
  const auto renewed =
      must(client.heartbeat("party/rollcall", winter_id.identity().fingerprint,
                            renewed_exp, hb_sig),
           "heartbeat");
  require(renewed.expires_ns == renewed_exp && renewed.lease_seq == 3U,
          "heartbeat did not renew expires_ns/lease_seq");

  // Replaying the exact same heartbeat signature MUST be rejected.
  const auto replay_hb = client.heartbeat(
      "party/rollcall", winter_id.identity().fingerprint, renewed_exp, hb_sig);
  require(!replay_hb.has_value() && replay_hb.error().code == ErrorCode::stale_handle,
          "replayed heartbeat must fail with ErrorCode::stale_handle");

  // Replaying an earlier still-valid heartbeat MUST NOT shorten the active lease.
  const auto shorten_hb = client.heartbeat(
      "party/rollcall", winter_id.identity().fingerprint, earlier_exp, earlier_hb_sig);
  require(!shorten_hb.has_value() && shorten_hb.error().code == ErrorCode::stale_handle,
          "shortening heartbeat must fail with ErrorCode::stale_handle");

  // Equal lease_seq replay on join_room MUST be rejected (strictly monotonic seq).
  const PartyLease equal_seq = make_signed_lease(
      winter_id, {"party/rollcall", "wintermute", PartyMemberRole::operator_human,
                  fake_now.load(), kPartyLobbyDefaultTtlNs, 0, renewed.lease_seq});
  const auto equal_seq_res = client.join_room("party/rollcall", equal_seq);
  require(!equal_seq_res.has_value() &&
              equal_seq_res.error().code == ErrorCode::stale_handle,
          "equal lease_seq replay must fail with ErrorCode::stale_handle");

  // UTF-8 C1 and BiDi controls in host/model MUST be rejected.
  PartyLease c1_host_draft{};
  c1_host_draft.room_id = "party/rollcall";
  c1_host_draft.alias = "wintermute";
  c1_host_draft.role = PartyMemberRole::operator_human;
  c1_host_draft.host = "bad\xc2\x9b"
                       "host";
  c1_host_draft.model = "claude-opus-4-6";
  c1_host_draft.issued_ns = fake_now.load();
  c1_host_draft.expires_ns = fake_now.load() + kPartyLobbyDefaultTtlNs;
  c1_host_draft.lease_seq = renewed.lease_seq + 1U;
  require(!sign_party_lease(winter_id, c1_host_draft).has_value(),
          "UTF-8 C1 in host must be rejected");
  PartyLease bidi_model_draft = c1_host_draft;
  bidi_model_draft.host = "clean-host";
  bidi_model_draft.model = "model\xe2\x80\xae"
                           "evil";
  require(!sign_party_lease(winter_id, bidi_model_draft).has_value(),
          "BiDi override in model must be rejected");

  // Tampered signature rejected with ErrorCode::invalid_identity.
  PartyLease tampered = winter_op;
  tampered.lease_seq = 10U;
  tampered.signature_b64[0] = (tampered.signature_b64[0] == 'A') ? 'B' : 'A';
  const auto tampered_res = client.join_room("party/rollcall", tampered);
  require(!tampered_res.has_value() &&
              tampered_res.error().code == ErrorCode::invalid_identity,
          "tampered signature must fail with ErrorCode::invalid_identity");

  // Unpinned peer (mallory) rejected with ErrorCode::invalid_identity.
  const PartyLease mallory_lease = make_signed_lease(
      mallory_id, {"party/rollcall", "mallory", PartyMemberRole::operator_human,
                   fake_now.load(), kPartyLobbyDefaultTtlNs});
  const auto mallory_res = client.join_room("party/rollcall", mallory_lease);
  require(!mallory_res.has_value() &&
              mallory_res.error().code == ErrorCode::invalid_identity,
          "unpinned peer must fail with ErrorCode::invalid_identity");

  // kick_member removes wintermute immediately from RAM.
  must_void(client.kick_member("party/rollcall", "wintermute"), "kick wintermute");
  const auto after_kick = must(client.snapshot(), "snapshot after kick");
  require(after_kick.participants.size() == 1U &&
              after_kick.mode == PartyMode::single_operator,
          "kick_member did not remove member");

  require(!has_any_party_json(base.path), "party.json must NEVER be created on disk");
  server->stop();
}

void test_ttl_expiration_reaping() {
  g_stage = "ttl_expiration_reaping";
  TempDir base("bb-lobby-ttl");
  auto local_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-local"), "local id");
  auto ghost_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-ghost"), "ghost id");
  auto peers = must(KnownPeersStore::open(base.path / "peers"), "peers");
  (void)must(peers.pin_peer({"ghost", ghost_id.identity().public_key, ""}),
             "pin ghost");

  std::atomic<std::int64_t> fake_now{1700000000LL * 1000000000LL};
  const fs::path sock_path = base.path / "run" / "party.sock";

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  cfg.local_identity_dir = local_id.root();
  cfg.known_peers_dir = peers.root();
  cfg.clock_now_ns = [&fake_now]() { return fake_now.load(); };

  auto server = must(PartyLobbyServer::start(cfg), "start");
  auto client = must(PartyLobbyClient::connect(sock_path), "connect");

  const PartyLease host_lease = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), 300LL * 1000000000LL});
  (void)must(client.create_room("party/rollcall", host_lease), "create");

  // Ghost joins with a short 2-second TTL.
  const PartyLease ghost_lease =
      make_signed_lease(ghost_id, {"party/rollcall", "ghost", PartyMemberRole::worker,
                                   fake_now.load(), 2LL * 1000000000LL});
  (void)must(client.join_room("party/rollcall", ghost_lease), "ghost join");
  require(must(client.snapshot(), "before reap").participants.size() == 2U,
          "expected 2 members before expiration");

  // Advance clock by 5 seconds and reap_expired -> ghost disappears cleanly!
  fake_now.store(fake_now.load() + 5LL * 1000000000LL);
  const std::size_t reaped = server->reap_expired(fake_now.load());
  require(reaped == 1U, "expected exactly 1 expired lease reaped");

  const auto snap = must(client.snapshot(), "after reap");
  require(snap.participants.size() == 1U && snap.participants[0].id == "patrick",
          "ghost member did not disappear after TTL expiry");

  server->stop();
}

void test_multi_client_messages_and_solo_leave_sync() {
  g_stage = "multi_client_messages_and_solo_leave_sync";
  TempDir base("bb-lobby-multi");
  auto local_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-local"), "local id");
  const fs::path sock_path = base.path / "run" / "party.sock";

  std::atomic<std::int64_t> fake_now{1700000000LL * 1000000000LL};
  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  cfg.local_identity_dir = local_id.root();
  cfg.clock_now_ns = [&fake_now]() { return fake_now.load(); };

  auto server = must(PartyLobbyServer::start(cfg), "start");
  // Two concurrent persistent clients: main Blackbird window + detached flightdeck.
  auto client1 = must(PartyLobbyClient::connect(sock_path), "connect client1");
  auto client2 = must(PartyLobbyClient::connect(sock_path), "connect client2");

  const PartyLease host_lease = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs});
  (void)must(client1.create_room("party/rollcall", host_lease), "client1 create");

  // Post a message containing hostile ANSI escape codes -> must be sanitized.
  const auto seq1 = must(client1.post_message("party/rollcall", "patrick", "@all",
                                              "hello \x1b[31mred\x1b[0m flightdeck"),
                         "post msg 1");
  const auto seq2 = must(
      client2.post_message("party/rollcall", "patrick", "flightdeck", "roger that"),
      "post msg 2");
  require(seq1 == 1U && seq2 == 2U, "message sequence numbers must be monotonic");

  // Both clients see the exact same live in-RAM room and sanitized messages.
  const auto snap1 = must(client1.snapshot(), "snap1");
  const auto snap2 = must(client2.snapshot(), "snap2");
  require(snap1 == snap2, "client1 and client2 snapshots diverged");
  require(snap2.room_scope == "party/rollcall" && snap2.messages.size() == 2U,
          "client2 did not observe live room and messages");
  require(snap2.messages[0].body.find('\x1b') == std::string::npos,
          "ESC control char leaked into message body");
  require(snap2.messages[1].target == "@flightdeck", "target normalization mismatch");

  // Client 1 leaves -> Client 2 immediately flips back to SOLO!
  must_void(client1.leave_room("party/rollcall", local_id.identity().fingerprint),
            "client1 leave");
  const auto solo2 = must(client2.snapshot(), "client2 snapshot after leave");
  require(solo2.room_scope.empty() && solo2.participants.empty() &&
              solo2.messages.empty(),
          "client2 must immediately return to SOLO when last local member leaves");

  server->stop();
}

void test_revocation_invalidation() {
  g_stage = "revocation_invalidation";
  TempDir base("bb-lobby-revoke");
  auto local_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-local"), "local id");
  auto peer_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-peer"), "peer id");
  auto peers = must(KnownPeersStore::open(base.path / "peers"), "peers");
  (void)must(peers.pin_peer({"wintermute", peer_id.identity().public_key, ""}),
             "pin wintermute");

  std::atomic<std::int64_t> fake_now{1700000000LL * 1000000000LL};
  const fs::path sock_path = base.path / "run" / "party.sock";

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  cfg.local_identity_dir = local_id.root();
  cfg.known_peers_dir = peers.root();
  cfg.clock_now_ns = [&fake_now]() { return fake_now.load(); };

  auto server = must(PartyLobbyServer::start(cfg), "start");
  auto client = must(PartyLobbyClient::connect(sock_path), "connect");

  const PartyLease host_lease = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs, 0, 1});
  (void)must(client.create_room("party/rollcall", host_lease), "create");

  const PartyLease peer_lease = make_signed_lease(
      peer_id, {"party/rollcall", "wintermute", PartyMemberRole::operator_human,
                fake_now.load(), kPartyLobbyDefaultTtlNs, 0, 1});
  (void)must(client.join_room("party/rollcall", peer_lease), "peer join");
  require(must(client.snapshot(), "before revoke").participants.size() == 2U,
          "expected 2 members before revocation");

  // Revoke wintermute in durable KnownPeersStore + refresh server!
  (void)must(peers.revoke_peer({peer_id.identity().fingerprint, "compromised laptop"}),
             "revoke peer");
  const std::uint64_t new_epoch = must(client.refresh_revocations(), "refresh");
  require(new_epoch > 0U && server->revocation_epoch() == new_epoch,
          "revocation_epoch must advance after peer revocation");

  // Stale epoch & revoked peer leases are immediately evicted!
  const auto after_revoke = must(client.snapshot(), "after revoke");
  for (const auto &p : after_revoke.participants) {
    require(p.fingerprint != peer_id.identity().fingerprint,
            "revoked peer lease was not evicted");
  }
  require(after_revoke.participants.empty(),
          "leases signed with stale revocation_epoch must be invalidated");

  // Revoked peer cannot re-join even with the new revocation_epoch.
  const PartyLease revoked_retry = make_signed_lease(
      peer_id, {"party/rollcall", "wintermute", PartyMemberRole::operator_human,
                fake_now.load(), kPartyLobbyDefaultTtlNs, new_epoch, 2});
  // Re-create room as local operator with new epoch first.
  const PartyLease stale_host = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs, 0, 2});
  const auto stale_res = client.create_room("party/rollcall", stale_host);
  require(!stale_res.has_value() &&
              stale_res.error().code == ErrorCode::invalid_identity,
          "stale revocation_epoch lease must be rejected");

  const PartyLease fresh_host = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs, new_epoch, 2});
  (void)must(client.create_room("party/rollcall", fresh_host), "fresh host create");

  const auto revoked_join = client.join_room("party/rollcall", revoked_retry);
  require(!revoked_join.has_value() &&
              revoked_join.error().code == ErrorCode::invalid_identity,
          "revoked peer must be rejected with ErrorCode::invalid_identity");

  // list_friends() no longer lists revoked peer.
  const auto friends = must(client.list_friends(), "list_friends after revoke");
  require(friends.empty(), "revoked peer must not appear in list_friends()");

  server->stop();
}

void test_oversized_frame_rejection_and_server_survival() {
  g_stage = "oversized_frame_rejection_and_server_survival";
  TempDir base("bb-lobby-dos");
  const fs::path sock_path = base.path / "run" / "party.sock";

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  auto server = must(PartyLobbyServer::start(cfg), "start");

  // Send a > 256 KiB oversized frame over a raw socket connection.
  std::string huge(kPartyLobbyMaxLineBytes + 4096U, 'A');
  huge.push_back('\n');
  const std::string reply = send_raw_unix_frame(sock_path, huge);
  require(reply.find("\"ok\":false") != std::string::npos &&
              reply.find("capacity") != std::string::npos,
          "oversized frame must be rejected cleanly with capacity error");

  // Server must still be completely healthy for subsequent legitimate clients!
  auto client = must(PartyLobbyClient::connect(sock_path), "connect after oversized");
  const auto pong = must(client.ping(), "ping after oversized");
  require(pong.ok, "server must survive oversized frame attack");

  server->stop();
}

void test_invited_room_teardown_alias_collision_ansi_and_client_desync() {
  g_stage = "invited_room_teardown_alias_collision_ansi_and_client_desync";
  TempDir base("bb-lobby-hardening");
  auto local_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-local"), "local id");
  auto friend_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-friend"), "friend id");
  auto collide_id =
      must(PeerIdentityStore::open_or_create(base.path / "id-collide"), "collide id");
  auto peers = must(KnownPeersStore::open(base.path / "peers"), "peers");
  (void)must(peers.pin_peer({"wintermute", friend_id.identity().public_key, ""}),
             "pin wintermute");
  // Pin a friend whose alias matches the local operator alias ("patrick") to test
  // invite_friend alias collision rejection.
  (void)must(peers.pin_peer({"patrick", collide_id.identity().public_key, ""}),
             "pin colliding alias");

  std::atomic<std::int64_t> fake_now{1700000000LL * 1000000000LL};
  const fs::path sock_path = base.path / "run" / "party.sock";

  PartyLobbyServerConfig cfg{};
  cfg.socket_path = sock_path;
  cfg.local_identity_dir = local_id.root();
  cfg.known_peers_dir = peers.root();
  cfg.clock_now_ns = [&fake_now]() { return fake_now.load(); };

  auto server = must(PartyLobbyServer::start(cfg), "start");
  auto client = must(PartyLobbyClient::connect(sock_path), "connect");

  // 1. Create room as "patrick" (short 2s TTL) and invite "wintermute".
  const PartyLease short_host = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), 2LL * 1000000000LL, 0, 1});
  (void)must(client.create_room("party/rollcall", short_host), "create");
  (void)must(client.invite_friend("party/rollcall", "wintermute"), "invite wintermute");

  // 2. Invite alias collision: inviting "patrick" (different fingerprint) must fail
  // with ErrorCode::conflict.
  const auto collide_res = client.invite_friend("party/rollcall", "patrick");
  require(!collide_res.has_value() && collide_res.error().code == ErrorCode::conflict,
          "invite_friend alias collision must fail with ErrorCode::conflict");

  // 3. Pure-ANSI / pure-control message bodies must be rejected as empty ghost msgs.
  const auto ansi_only =
      client.post_message("party/rollcall", "patrick", "@all", "\x1b[31m\x1b[0m");
  require(!ansi_only.has_value() && ansi_only.error().code == ErrorCode::invalid_range,
          "pure-ANSI message body must be rejected");
  const auto c1_only = client.post_message("party/rollcall", "patrick", "@all",
                                           "\xc2\x9b"
                                           "31m");
  require(!c1_only.has_value() && c1_only.error().code == ErrorCode::invalid_range,
          "pure-C1 message body must be rejected");
  const auto bidi_only =
      client.post_message("party/rollcall", "patrick", "@all", "\xe2\x80\xae   ");
  require(!bidi_only.has_value() && bidi_only.error().code == ErrorCode::invalid_range,
          "pure-BiDi whitespace message body must be rejected");

  // 4. Host TTL expires while "wintermute" is still in room.invited -> zombie room
  // MUST be torn down immediately and lobby returns to SOLO!
  fake_now.store(fake_now.load() + 5LL * 1000000000LL);
  require(server->reap_expired(fake_now.load()) == 1U, "host lease must reap");
  const auto solo_after_expiry = must(client.snapshot(), "snapshot after host expiry");
  const auto ping_after_expiry = must(client.ping(), "ping after host expiry");
  require(solo_after_expiry.room_scope.empty() &&
              solo_after_expiry.participants.empty() &&
              !ping_after_expiry.active_room_id.has_value() &&
              ping_after_expiry.room_count == 0U,
          "invited-only zombie room must tear down to SOLO on host expiry");

  // 5. Re-create room + invite "wintermute", then revoke unrelated peer -> stale
  // epoch evicts host while invited slot exists -> room MUST tear down to SOLO!
  const PartyLease host2 = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs, 0, 1});
  (void)must(client.create_room("party/rollcall", host2), "re-create");
  (void)must(client.invite_friend("party/rollcall", "wintermute"), "re-invite");
  (void)must(peers.revoke_peer({collide_id.identity().fingerprint, "revoked"}),
             "revoke collide");
  (void)must(client.refresh_revocations(), "refresh after revoke");
  const auto solo_after_rev = must(client.snapshot(), "snapshot after revoke");
  const auto ping_after_rev = must(client.ping(), "ping after revoke");
  require(
      solo_after_rev.room_scope.empty() && solo_after_rev.participants.empty() &&
          !ping_after_rev.active_room_id.has_value() && ping_after_rev.room_count == 0U,
      "invited-only zombie room must tear down to SOLO on host revocation eviction");

  // 6. Newline flood from one client does not starve another client's RPC.
  const std::string flood(2048U, '\n');
  const int flood_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  require(flood_fd >= 0, "flood socket");
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const std::string &native = sock_path.native();
  std::memcpy(addr.sun_path, native.data(), native.size());
  require(
      ::connect(flood_fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0,
      "flood connect");
  (void)::send(flood_fd, flood.data(), flood.size(), 0);
  const auto pong_under_flood = must(client.ping(), "ping under newline flood");
  require(pong_under_flood.ok, "server starved under newline flood");
  (void)::close(flood_fd);

  // 7. Client stream desync invalidation: oversized response triggers capacity error,
  // closes/invalidates fd_ immediately, and subsequent RPC fails with stale_handle.
  const std::uint64_t cur_epoch = server->revocation_epoch();
  const PartyLease host3 = make_signed_lease(
      local_id, {"party/rollcall", "patrick", PartyMemberRole::operator_human,
                 fake_now.load(), kPartyLobbyDefaultTtlNs, cur_epoch, 2});
  (void)must(client.create_room("party/rollcall", host3), "host3 create");
  const std::string big_body(2000U, 'X');
  (void)must(client.post_message("party/rollcall", "patrick", "@all", big_body),
             "post big msg");

  PartyLobbyClientConfig tiny_cfg{};
  tiny_cfg.max_line_bytes = 1024U; // smaller than snapshot response (~2.5 KiB)
  auto tiny_client =
      must(PartyLobbyClient::connect(sock_path, tiny_cfg), "connect tiny client");
  const auto tiny_snap = tiny_client.snapshot();
  require(!tiny_snap.has_value() && tiny_snap.error().code == ErrorCode::capacity,
          "oversized server response must fail with ErrorCode::capacity");
  require(!tiny_client.connected(),
          "client must invalidate fd after framing/capacity error");
  const auto after_desync = tiny_client.ping();
  require(!after_desync.has_value() &&
              after_desync.error().code == ErrorCode::stale_handle,
          "invalidated client must reject subsequent RPCs with stale_handle");

  server->stop();
}

} // namespace

int main() {
  try {
    test_socket_path_resolution_and_dir_hardening();
    test_solo_startup_permissions_and_zero_disk_party_json();
    test_room_leases_invite_friend_modes_and_wire_ssh_target_strip();
    test_ttl_expiration_reaping();
    test_multi_client_messages_and_solo_leave_sync();
    test_revocation_invalidation();
    test_oversized_frame_rejection_and_server_survival();
    test_invited_room_teardown_alias_collision_ansi_and_client_desync();
    std::cout << "party_lobby_test: ALL PASSED\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "party_lobby_test FAILED at [" << g_stage << "]: " << ex.what()
              << "\n";
    return 1;
  }
}
