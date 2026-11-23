#include "blackbird/json.hpp"
#include "blackbird/jupyter_notebook.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <source_location>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <openssl/evp.h>

namespace {

using namespace blackbird;
namespace fs = std::filesystem;

[[noreturn]] void
fail_require(std::string_view claim,
             std::source_location loc = std::source_location::current()) {
  std::ostringstream out;
  out << loc.file_name() << ':' << loc.line() << ": failed requirement: " << claim;
  throw std::runtime_error(out.str());
}

void require(bool condition, std::string_view claim,
             std::source_location loc = std::source_location::current()) {
  if (!condition) {
    fail_require(claim, loc);
  }
}

std::size_t count_open_fds() {
  std::size_t count = 0U;
  for (int fd = 0; fd < 1024; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1) {
      ++count;
    }
  }
  return count;
}

class TempDir {
public:
  explicit TempDir(std::string_view prefix) {
    std::string pattern =
        (fs::temp_directory_path() / (std::string{prefix} + "-XXXXXX")).string();
    std::vector<char> buf(pattern.begin(), pattern.end());
    buf.push_back('\0');
    char *created = ::mkdtemp(buf.data());
    require(created != nullptr, "mkdtemp must succeed");
    path_ = fs::canonical(fs::path{created});
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path_, ec);
  }
  const fs::path &path() const noexcept { return path_; }

private:
  fs::path path_;
};

std::string test_base64_encode(const unsigned char *data, std::size_t len) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  std::size_t i = 0U;
  while (i + 3U <= len) {
    const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16U) |
                            (static_cast<std::uint32_t>(data[i + 1U]) << 8U) |
                            static_cast<std::uint32_t>(data[i + 2U]);
    out.push_back(kTable[(n >> 18U) & 0x3fU]);
    out.push_back(kTable[(n >> 12U) & 0x3fU]);
    out.push_back(kTable[(n >> 6U) & 0x3fU]);
    out.push_back(kTable[n & 0x3fU]);
    i += 3U;
  }
  const std::size_t rem = len - i;
  if (rem == 1U) {
    const std::uint32_t n = static_cast<std::uint32_t>(data[i]) << 16U;
    out.push_back(kTable[(n >> 18U) & 0x3fU]);
    out.push_back(kTable[(n >> 12U) & 0x3fU]);
    out.push_back('=');
    out.push_back('=');
  } else if (rem == 2U) {
    const std::uint32_t n = (static_cast<std::uint32_t>(data[i]) << 16U) |
                            (static_cast<std::uint32_t>(data[i + 1U]) << 8U);
    out.push_back(kTable[(n >> 18U) & 0x3fU]);
    out.push_back(kTable[(n >> 12U) & 0x3fU]);
    out.push_back(kTable[(n >> 6U) & 0x3fU]);
    out.push_back('=');
  }
  return out;
}

std::string mock_ws_accept(std::string_view key) {
  std::string input{key};
  input.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  std::array<unsigned char, 20U> digest{};
  unsigned int dlen = 0U;
  require(EVP_Digest(input.data(), input.size(), digest.data(), &dlen, EVP_sha1(),
                     nullptr) == 1 &&
              dlen == 20U,
          "mock SHA-1 must succeed");
  return test_base64_encode(digest.data(), digest.size());
}

bool send_all_fd(int fd, const void *buf, std::size_t len) {
  const auto *ptr = static_cast<const std::uint8_t *>(buf);
  std::size_t off = 0U;
  while (off < len) {
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags |= MSG_NOSIGNAL;
#endif
    const ssize_t n = ::send(fd, ptr + off, len - off, flags);
    if (n > 0) {
      off += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

bool send_text_fd(int fd, std::string_view text) {
  return send_all_fd(fd, text.data(), text.size());
}

bool recv_exact_fd(int fd, std::span<std::uint8_t> dst,
                   std::chrono::milliseconds timeout = std::chrono::milliseconds{
                       5000}) {
  std::size_t off = 0U;
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (off < dst.size()) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      return false;
    }
    const auto rem =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    const int prc = ::poll(&pfd, 1U, static_cast<int>(rem));
    if (prc <= 0) {
      if (prc < 0 && errno == EINTR) {
        continue;
      }
      return false;
    }
    const ssize_t n = ::recv(fd, dst.data() + off, dst.size() - off, 0);
    if (n > 0) {
      off += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

enum class MockWsOp : std::uint8_t {
  continuation = 0x0U,
  text = 0x1U,
  ping = 0x9U,
};

struct MockWsFrame {
  bool fin = true;
  bool masked = false;
  std::uint8_t opcode = 0U;
  std::string payload;
};

std::optional<MockWsFrame> mock_read_ws_frame(
    int fd, std::chrono::milliseconds timeout = std::chrono::milliseconds{5000}) {
  std::array<std::uint8_t, 2U> hdr{};
  if (!recv_exact_fd(fd, hdr, timeout)) {
    return std::nullopt;
  }
  MockWsFrame frame;
  frame.fin = (hdr[0U] & 0x80U) != 0U;
  frame.opcode = static_cast<std::uint8_t>(hdr[0U] & 0x0fU);
  frame.masked = (hdr[1U] & 0x80U) != 0U;
  std::uint64_t len = static_cast<std::uint64_t>(hdr[1U] & 0x7fU);
  if (len == 126U) {
    std::array<std::uint8_t, 2U> ext{};
    if (!recv_exact_fd(fd, ext, timeout)) {
      return std::nullopt;
    }
    len = (static_cast<std::uint64_t>(ext[0U]) << 8U) |
          static_cast<std::uint64_t>(ext[1U]);
  } else if (len == 127U) {
    std::array<std::uint8_t, 8U> ext{};
    if (!recv_exact_fd(fd, ext, timeout)) {
      return std::nullopt;
    }
    len = 0U;
    for (const std::uint8_t b : ext) {
      len = (len << 8U) | b;
    }
  }
  std::array<std::uint8_t, 4U> mask{};
  if (frame.masked && !recv_exact_fd(fd, mask, timeout)) {
    return std::nullopt;
  }
  frame.payload.resize(static_cast<std::size_t>(len));
  if (len > 0U &&
      !recv_exact_fd(fd,
                     std::span<std::uint8_t>{
                         reinterpret_cast<std::uint8_t *>(frame.payload.data()),
                         static_cast<std::size_t>(len)},
                     timeout)) {
    return std::nullopt;
  }
  if (frame.masked) {
    for (std::size_t i = 0U; i < frame.payload.size(); ++i) {
      frame.payload[i] =
          static_cast<char>(static_cast<std::uint8_t>(frame.payload[i]) ^ mask[i & 3U]);
    }
  }
  return frame;
}

bool mock_send_ws_frame(int fd, MockWsOp opcode, std::string_view payload,
                        bool fin = true) {
  std::vector<std::uint8_t> out;
  out.reserve(10U + payload.size());
  out.push_back(static_cast<std::uint8_t>((fin ? 0x80U : 0x00U) |
                                          (static_cast<std::uint8_t>(opcode) & 0x0fU)));
  if (payload.size() <= 125U) {
    out.push_back(static_cast<std::uint8_t>(payload.size()));
  } else if (payload.size() <= 65535U) {
    out.push_back(126U);
    out.push_back(static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(payload.size() & 0xffU));
  } else {
    out.push_back(127U);
    const auto len64 = static_cast<std::uint64_t>(payload.size());
    for (int shift = 56; shift >= 0; shift -= 8) {
      out.push_back(
          static_cast<std::uint8_t>((len64 >> static_cast<unsigned>(shift)) & 0xffU));
    }
  }
  out.insert(out.end(), payload.begin(), payload.end());
  return send_all_fd(fd, out.data(), out.size());
}

// ---------------------------------------------------------------------------
// Deterministic In-Process Loopback Mock Jupyter Server
// ---------------------------------------------------------------------------

class MockJupyterServer {
public:
  explicit MockJupyterServer(std::string expected_token)
      : expected_token_(std::move(expected_token)) {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    require(listen_fd_ >= 0, "mock server socket() must succeed");
    (void)::fcntl(listen_fd_, F_SETFD, FD_CLOEXEC);
    const int one = 1;
    (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_NOSIGPIPE
    (void)::setsockopt(listen_fd_, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    require(::bind(listen_fd_, reinterpret_cast<const sockaddr *>(&addr),
                   sizeof(addr)) == 0,
            "mock server bind() must succeed");
    socklen_t len = sizeof(addr);
    require(::getsockname(listen_fd_, reinterpret_cast<sockaddr *>(&addr), &len) == 0,
            "mock server getsockname() must succeed");
    port_ = ntohs(addr.sin_port);
    require(::listen(listen_fd_, 16) == 0, "mock server listen() must succeed");

    // Seed one pre-existing kernel so list_kernels sees it immediately.
    kernels_.push_back(JupyterKernelInfo{
        .id = "kernel-existing-1",
        .name = "python3",
        .execution_state = "idle",
        .last_activity = "2026-11-23T00:00:00Z",
        .connections = 1U,
    });

    thread_ = std::thread([this] { serve_loop(); });
  }

  MockJupyterServer(const MockJupyterServer &) = delete;
  MockJupyterServer &operator=(const MockJupyterServer &) = delete;

  ~MockJupyterServer() { stop(); }

  void stop() {
    if (stopped_.exchange(true)) {
      return;
    }
    if (listen_fd_ >= 0) {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  std::string base_url() const { return "http://127.0.0.1:" + std::to_string(port_); }

  void set_bad_ws_accept(bool bad) { bad_ws_accept_.store(bad); }
  void set_silent_ws(bool silent) { silent_ws_.store(silent); }

  std::size_t interrupt_count() const { return interrupt_count_.load(); }
  std::size_t shutdown_count() const { return shutdown_count_.load(); }
  std::size_t pong_verified_count() const { return pong_verified_count_.load(); }
  std::size_t masked_request_count() const { return masked_request_count_.load(); }

private:
  void serve_loop() {
    while (!stopped_.load()) {
      pollfd pfd{};
      pfd.fd = listen_fd_;
      pfd.events = POLLIN;
      const int prc = ::poll(&pfd, 1U, 50);
      if (prc <= 0) {
        continue;
      }
      sockaddr_in peer{};
      socklen_t peer_len = sizeof(peer);
      const int client =
          ::accept(listen_fd_, reinterpret_cast<sockaddr *>(&peer), &peer_len);
      if (client < 0) {
        continue;
      }
      (void)::fcntl(client, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
      const int one = 1;
      (void)::setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
      handle_client(client);
      (void)::close(client);
    }
  }

  void handle_client(int fd) {
    std::string req;
    std::array<char, 4096U> buf{};
    std::size_t header_end = std::string::npos;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (header_end == std::string::npos) {
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        return;
      }
      pollfd pfd{};
      pfd.fd = fd;
      pfd.events = POLLIN;
      if (::poll(&pfd, 1U, 200) <= 0) {
        if (stopped_.load()) {
          return;
        }
        continue;
      }
      const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
      if (n <= 0) {
        return;
      }
      req.append(buf.data(), static_cast<std::size_t>(n));
      header_end = req.find("\r\n\r\n");
    }

    const std::string head_str = req.substr(0U, header_end);
    std::string body = req.substr(header_end + 4U);

    // Parse request line.
    const std::size_t line_end = head_str.find("\r\n");
    const std::string first_line =
        line_end == std::string::npos ? head_str : head_str.substr(0U, line_end);
    const std::size_t sp1 = first_line.find(' ');
    const std::size_t sp2 =
        sp1 == std::string::npos ? std::string::npos : first_line.find(' ', sp1 + 1U);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
      return;
    }
    const std::string method = first_line.substr(0U, sp1);
    const std::string target = first_line.substr(sp1 + 1U, sp2 - sp1 - 1U);

    // Extract headers.
    std::string auth_header;
    std::string ws_key;
    std::size_t content_length = 0U;
    std::size_t pos = line_end == std::string::npos ? head_str.size() : line_end + 2U;
    while (pos < head_str.size()) {
      const std::size_t next = head_str.find("\r\n", pos);
      const std::string line = next == std::string::npos
                                   ? head_str.substr(pos)
                                   : head_str.substr(pos, next - pos);
      const std::size_t colon = line.find(':');
      if (colon != std::string::npos) {
        std::string key = line.substr(0U, colon);
        for (char &c : key) {
          if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
          }
        }
        std::string val = line.substr(colon + 1U);
        while (!val.empty() && val.front() == ' ') {
          val.erase(val.begin());
        }
        if (key == "authorization") {
          auth_header = val;
        } else if (key == "sec-websocket-key") {
          ws_key = val;
        } else if (key == "content-length") {
          content_length =
              static_cast<std::size_t>(std::strtoull(val.c_str(), nullptr, 10));
        }
      }
      if (next == std::string::npos) {
        break;
      }
      pos = next + 2U;
    }

    while (body.size() < content_length) {
      const std::size_t need = content_length - body.size();
      std::string extra(need, '\0');
      if (!recv_exact_fd(fd,
                         std::span<std::uint8_t>{
                             reinterpret_cast<std::uint8_t *>(extra.data()), need})) {
        return;
      }
      body.append(extra);
    }

    // Check auth token.
    if (!expected_token_.empty() && auth_header != ("token " + expected_token_)) {
      send_text_fd(fd, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 18\r\n"
                       "Connection: close\r\n\r\n{\"error\":\"denied\"}");
      return;
    }

    // Route WebSocket channels.
    if (method == "GET" && target.find("/api/kernels/") == 0U &&
        target.find("/channels") != std::string::npos) {
      handle_ws_channels(fd, ws_key);
      return;
    }

    // Route REST endpoints.
    if (method == "GET" && target == "/api/kernels") {
      Value::Array arr;
      {
        std::lock_guard<std::mutex> lock(mu_);
        for (const auto &k : kernels_) {
          Value::Object obj;
          obj.emplace_back("id", Value{k.id});
          obj.emplace_back("name", Value{k.name});
          obj.emplace_back("execution_state", Value{k.execution_state});
          obj.emplace_back("last_activity", Value{k.last_activity});
          obj.emplace_back("connections", Value{Number{k.connections}});
          arr.push_back(Value::object(std::move(obj)));
        }
      }
      const auto dumped = dump_json(Value{std::move(arr)});
      const std::string json_body = dumped.has_value() ? dumped.value() : "[]";
      // Exercise Transfer-Encoding: chunked in list_kernels!
      std::ostringstream resp;
      resp << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
           << "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
      const std::size_t mid = json_body.size() / 2U;
      if (mid > 0U) {
        resp << std::hex << mid << "\r\n" << json_body.substr(0U, mid) << "\r\n";
      }
      resp << std::hex << (json_body.size() - mid) << "\r\n"
           << json_body.substr(mid) << "\r\n0\r\n\r\n";
      send_text_fd(fd, resp.str());
      return;
    }

    if (method == "POST" && target == "/api/kernels") {
      std::string kname = "python3";
      if (!body.empty()) {
        auto parsed = parse_json(body);
        if (parsed.has_value() &&
            std::holds_alternative<Value::Object>(parsed.value().value())) {
          if (const Value *nv = parsed.value().find("name");
              nv != nullptr && std::holds_alternative<std::string>(nv->value()) &&
              !nv->string().empty()) {
            kname = nv->string();
          }
        }
      }
      JupyterKernelInfo created;
      {
        std::lock_guard<std::mutex> lock(mu_);
        ++next_kernel_num_;
        created.id = "kernel-started-" + std::to_string(next_kernel_num_);
        created.name = kname;
        created.execution_state = "idle";
        created.last_activity = "2026-11-23T00:01:00Z";
        created.connections = 0U;
        kernels_.push_back(created);
      }
      Value::Object obj;
      obj.emplace_back("id", Value{created.id});
      obj.emplace_back("name", Value{created.name});
      obj.emplace_back("execution_state", Value{created.execution_state});
      obj.emplace_back("last_activity", Value{created.last_activity});
      obj.emplace_back("connections", Value{Number{created.connections}});
      const auto dumped = dump_json(Value::object(std::move(obj)));
      const std::string json_body = dumped.has_value() ? dumped.value() : "{}";
      const std::string resp =
          "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: " +
          std::to_string(json_body.size()) + "\r\nConnection: close\r\n\r\n" +
          json_body;
      send_text_fd(fd, resp);
      return;
    }

    if (method == "POST" && target.starts_with("/api/kernels/") &&
        target.ends_with("/interrupt")) {
      interrupt_count_.fetch_add(1U);
      send_text_fd(fd, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
      return;
    }

    if (method == "DELETE" && target.starts_with("/api/kernels/")) {
      const std::string kid = target.substr(std::string_view{"/api/kernels/"}.size());
      {
        std::lock_guard<std::mutex> lock(mu_);
        std::erase_if(kernels_,
                      [&kid](const JupyterKernelInfo &k) { return k.id == kid; });
      }
      shutdown_count_.fetch_add(1U);
      send_text_fd(fd, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
      return;
    }

    send_text_fd(
        fd,
        "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
  }

  void handle_ws_channels(int fd, std::string_view ws_key) {
    const std::string accept =
        bad_ws_accept_.load() ? "AAAAAAAAAAAAAAAAAAAAAAAAAAA=" : mock_ws_accept(ws_key);
    const std::string hs = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                           "Connection: Upgrade\r\nSec-WebSocket-Accept: " +
                           accept + "\r\n\r\n";
    if (!send_text_fd(fd, hs)) {
      return;
    }
    if (bad_ws_accept_.load()) {
      return;
    }

    auto req_frame = mock_read_ws_frame(fd, std::chrono::milliseconds{5000});
    if (!req_frame.has_value() || !req_frame->masked || req_frame->opcode != 0x1U) {
      return;
    }
    masked_request_count_.fetch_add(1U);

    if (silent_ws_.load()) {
      // Hold socket open briefly to exercise bounded client timeout.
      const auto until =
          std::chrono::steady_clock::now() + std::chrono::milliseconds{600};
      while (!stopped_.load() && std::chrono::steady_clock::now() < until) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (::poll(&pfd, 1U, 20) > 0) {
          char sink[64];
          if (::recv(fd, sink, sizeof(sink), 0) <= 0) {
            break;
          }
        }
      }
      return;
    }

    auto parsed_req = parse_json(req_frame->payload);
    if (!parsed_req.has_value() ||
        !std::holds_alternative<Value::Object>(parsed_req.value().value())) {
      return;
    }
    const Value *hdr = parsed_req.value().find("header");
    const Value *content = parsed_req.value().find("content");
    if (hdr == nullptr || content == nullptr) {
      return;
    }
    const Value *msg_id_v = hdr->find("msg_id");
    const Value *code_v = content->find("code");
    if (msg_id_v == nullptr || code_v == nullptr) {
      return;
    }
    const std::string req_msg_id = msg_id_v->string();
    const std::string code = code_v->string();

    struct WireMsgSpec {
      std::string_view channel;
      std::string_view parent_id;
      std::string_view msg_type;
      Value content;
    };
    auto make_msg = [&](WireMsgSpec spec) -> std::string {
      Value::Object h;
      h.emplace_back("msg_id", Value{"srv-" + std::string{spec.msg_type}});
      h.emplace_back("msg_type", Value{std::string{spec.msg_type}});
      h.emplace_back("version", Value{"5.3"});
      Value::Object ph;
      ph.emplace_back("msg_id", Value{std::string{spec.parent_id}});
      Value::Object env;
      env.emplace_back("channel", Value{std::string{spec.channel}});
      env.emplace_back("header", Value::object(std::move(h)));
      env.emplace_back("parent_header", Value::object(std::move(ph)));
      env.emplace_back("metadata", Value::object({}));
      env.emplace_back("content", std::move(spec.content));
      auto dumped = dump_json(Value::object(std::move(env)));
      return dumped.has_value() ? dumped.value() : "{}";
    };

    // 1. Send unrelated broadcast with a DIFFERENT parent_header.msg_id.
    {
      Value::Object c;
      c.emplace_back("name", Value{"stdout"});
      c.emplace_back("text", Value{"UNRELATED_NOISE_MUST_BE_FILTERED\n"});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = "other-client-msg-999",
                                         .msg_type = "stream",
                                         .content = Value::object(std::move(c))}));
    }

    // 2. Send a Ping frame and verify client responds with a masked Pong!
    {
      (void)mock_send_ws_frame(fd, MockWsOp::ping, "hb-ping-42", true);
      auto pong = mock_read_ws_frame(fd, std::chrono::milliseconds{3000});
      if (pong.has_value() && pong->masked && pong->opcode == 0xAU &&
          pong->payload == "hb-ping-42") {
        pong_verified_count_.fetch_add(1U);
      }
    }

    // 3. Branch on code to test both rich success and error execution paths.
    if (code.find("1/0") != std::string::npos) {
      // Send shell execute_reply BEFORE iopub status: idle to test order independence.
      Value::Array tb;
      tb.emplace_back("\x1b[31mZeroDivisionError\x1b[0m: division by zero");
      Value::Object err_c;
      err_c.emplace_back("ename", Value{"ZeroDivisionError"});
      err_c.emplace_back("evalue", Value{"division by zero"});
      err_c.emplace_back("traceback", Value{tb});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = req_msg_id,
                                         .msg_type = "error",
                                         .content = Value::object(std::move(err_c))}));

      Value::Object rep;
      rep.emplace_back("status", Value{"error"});
      rep.emplace_back("execution_count", Value{Number{std::int64_t{2}}});
      rep.emplace_back("ename", Value{"ZeroDivisionError"});
      rep.emplace_back("evalue", Value{"division by zero"});
      rep.emplace_back("traceback", Value{std::move(tb)});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "shell",
                                         .parent_id = req_msg_id,
                                         .msg_type = "execute_reply",
                                         .content = Value::object(std::move(rep))}));

      Value::Object idle;
      idle.emplace_back("execution_state", Value{"idle"});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = req_msg_id,
                                         .msg_type = "status",
                                         .content = Value::object(std::move(idle))}));
    } else {
      // Busy status.
      Value::Object busy;
      busy.emplace_back("execution_state", Value{"busy"});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = req_msg_id,
                                         .msg_type = "status",
                                         .content = Value::object(std::move(busy))}));

      // Fragmented stream message split across 2 frames WITH an interleaved Ping!
      Value::Object stream_c;
      stream_c.emplace_back("name", Value{"stdout"});
      stream_c.emplace_back("text", Value{"\x1b[32mhello from kernel\x1b[0m\n"});
      const std::string stream_msg =
          make_msg({.channel = "iopub",
                    .parent_id = req_msg_id,
                    .msg_type = "stream",
                    .content = Value::object(std::move(stream_c))});
      const std::size_t split = stream_msg.size() / 2U;
      (void)mock_send_ws_frame(fd, MockWsOp::text, stream_msg.substr(0U, split), false);
      (void)mock_send_ws_frame(fd, MockWsOp::ping, "mid-frag-ping", true);
      auto pong2 = mock_read_ws_frame(fd, std::chrono::milliseconds{3000});
      if (pong2.has_value() && pong2->masked && pong2->opcode == 0xAU &&
          pong2->payload == "mid-frag-ping") {
        pong_verified_count_.fetch_add(1U);
      }
      (void)mock_send_ws_frame(fd, MockWsOp::continuation, stream_msg.substr(split),
                               true);

      // execute_result
      Value::Object er_data;
      er_data.emplace_back("text/plain", Value{"42"});
      Value::Object er_c;
      er_c.emplace_back("execution_count", Value{Number{std::int64_t{1}}});
      er_c.emplace_back("data", Value::object(std::move(er_data)));
      er_c.emplace_back("metadata", Value::object({}));
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = req_msg_id,
                                         .msg_type = "execute_result",
                                         .content = Value::object(std::move(er_c))}));

      // display_data with large PNG base64
      Value::Object dd_data;
      dd_data.emplace_back("image/png", Value{std::string(2048U, 'A')});
      dd_data.emplace_back("text/plain", Value{"<Figure 640x480>"});
      Value::Object dd_c;
      dd_c.emplace_back("data", Value::object(std::move(dd_data)));
      dd_c.emplace_back("metadata", Value::object({}));
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = req_msg_id,
                                         .msg_type = "display_data",
                                         .content = Value::object(std::move(dd_c))}));

      // iopub status: idle
      Value::Object idle;
      idle.emplace_back("execution_state", Value{"idle"});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "iopub",
                                         .parent_id = req_msg_id,
                                         .msg_type = "status",
                                         .content = Value::object(std::move(idle))}));

      // shell execute_reply
      Value::Object rep;
      rep.emplace_back("status", Value{"ok"});
      rep.emplace_back("execution_count", Value{Number{std::int64_t{1}}});
      (void)mock_send_ws_frame(fd, MockWsOp::text,
                               make_msg({.channel = "shell",
                                         .parent_id = req_msg_id,
                                         .msg_type = "execute_reply",
                                         .content = Value::object(std::move(rep))}));
    }

    // Drain optional polite Close frame from client.
    (void)mock_read_ws_frame(fd, std::chrono::milliseconds{500});
  }

  std::string expected_token_;
  int listen_fd_ = -1;
  std::uint16_t port_ = 0U;
  std::atomic<bool> stopped_{false};
  std::atomic<bool> bad_ws_accept_{false};
  std::atomic<bool> silent_ws_{false};
  std::atomic<std::size_t> interrupt_count_{0U};
  std::atomic<std::size_t> shutdown_count_{0U};
  std::atomic<std::size_t> pong_verified_count_{0U};
  std::atomic<std::size_t> masked_request_count_{0U};
  mutable std::mutex mu_;
  std::vector<JupyterKernelInfo> kernels_;
  std::size_t next_kernel_num_ = 0U;
  std::thread thread_;
};

// ---------------------------------------------------------------------------
// Test 1: Exhaustive .ipynb Parse, Hygiene, Transforms & Canonical Round-Trip
// ---------------------------------------------------------------------------

void test_ipynb_engine_and_hygiene() {
  // Large synthetic valid base64 PNG payload (~12 KiB base64 -> ~9 KiB decoded).
  const std::string huge_png_b64(12000U, 'A');
  const std::string huge_pdf_b64(4000U, 'Q');

  Value::Object ks;
  ks.emplace_back("display_name", Value{"Python 3 (ipykernel)"});
  ks.emplace_back("language", Value{"python"});
  ks.emplace_back("name", Value{"python3"});

  Value::Object li;
  li.emplace_back("name", Value{"python"});
  li.emplace_back("version", Value{"3.12.4"});
  li.emplace_back("mimetype", Value{"text/x-python"});
  li.emplace_back("file_extension", Value{".py"});
  li.emplace_back("pygments_lexer", Value{"ipython3"});

  Value::Object nb_meta;
  nb_meta.emplace_back("kernelspec", Value::object(std::move(ks)));
  nb_meta.emplace_back("language_info", Value::object(std::move(li)));
  nb_meta.emplace_back("custom_tag", Value{"blackbird-wave20"});

  // Cell 0: Markdown cell with array source and attachments, no id (v4.4 style).
  Value::Array md_src;
  md_src.emplace_back("# Title\n");
  md_src.emplace_back("Body paragraph.");
  Value::Object md_att;
  md_att.emplace_back("logo.png", Value{"iVBORw0KGgo="});
  Value::Object cell0;
  cell0.emplace_back("cell_type", Value{"markdown"});
  cell0.emplace_back("metadata", Value::object({}));
  cell0.emplace_back("attachments", Value::object(std::move(md_att)));
  cell0.emplace_back("source", Value{std::move(md_src)});

  // Cell 1: Code cell with string source and all 4 output types.
  Value::Array outputs;
  {
    Value::Object stream_out;
    stream_out.emplace_back("output_type", Value{"stream"});
    stream_out.emplace_back("name", Value{"stdout"});
    Value::Array stxt;
    stxt.emplace_back("\x1b[32mOK:\x1b[0m line1\r\n");
    stxt.emplace_back("\x1b]0;WindowTitle\x07line2\n");
    stream_out.emplace_back("text", Value{std::move(stxt)});
    outputs.push_back(Value::object(std::move(stream_out)));
  }
  {
    Value::Object data_obj;
    data_obj.emplace_back("text/plain", Value{"<DataFrame 10x3>"});
    data_obj.emplace_back("image/png", Value{huge_png_b64});
    Value::Object er_out;
    er_out.emplace_back("output_type", Value{"execute_result"});
    er_out.emplace_back("execution_count", Value{Number{std::int64_t{7}}});
    er_out.emplace_back("data", Value::object(std::move(data_obj)));
    er_out.emplace_back("metadata", Value::object({}));
    outputs.push_back(Value::object(std::move(er_out)));
  }
  {
    Value::Object dd_data;
    dd_data.emplace_back("application/pdf", Value{huge_pdf_b64});
    Value::Object dd_out;
    dd_out.emplace_back("output_type", Value{"display_data"});
    dd_out.emplace_back("data", Value::object(std::move(dd_data)));
    dd_out.emplace_back("metadata", Value::object({}));
    outputs.push_back(Value::object(std::move(dd_out)));
  }
  {
    Value::Array tb;
    tb.emplace_back("\x1b[1;31mValueError\x1b[0m: bad input");
    tb.emplace_back("  at cell 1 line 2");
    Value::Object err_out;
    err_out.emplace_back("output_type", Value{"error"});
    err_out.emplace_back("ename", Value{"ValueError"});
    err_out.emplace_back("evalue", Value{"bad input"});
    err_out.emplace_back("traceback", Value{std::move(tb)});
    outputs.push_back(Value::object(std::move(err_out)));
  }

  Value::Object cell1;
  cell1.emplace_back("cell_type", Value{"code"});
  cell1.emplace_back("id", Value{"cell-0"}); // Collides with naive index 0 generator!
  cell1.emplace_back("execution_count", Value{Number{std::int64_t{7}}});
  cell1.emplace_back("metadata", Value::object({}));
  cell1.emplace_back("outputs", Value{std::move(outputs)});
  cell1.emplace_back("source", Value{"import math\nprint(math.pi)"});

  // Cell 2: Raw cell.
  Value::Object cell2;
  cell2.emplace_back("cell_type", Value{"raw"});
  cell2.emplace_back("id", Value{"raw-keep"});
  cell2.emplace_back("metadata", Value::object({}));
  cell2.emplace_back("source", Value{"raw LaTeX block"});

  Value::Array cells;
  cells.push_back(Value::object(std::move(cell0)));
  cells.push_back(Value::object(std::move(cell1)));
  cells.push_back(Value::object(std::move(cell2)));

  Value::Object root;
  root.emplace_back("nbformat", Value{Number{std::int64_t{4}}});
  root.emplace_back("nbformat_minor", Value{Number{std::int64_t{4}}});
  root.emplace_back("metadata", Value::object(std::move(nb_meta)));
  root.emplace_back("cells", Value{std::move(cells)});

  auto dumped_in = dump_json(Value::object(std::move(root)));
  require(dumped_in.has_value(), "fixture notebook JSON must serialize");

  auto parsed_res = parse_ipynb(dumped_in.value());
  require(parsed_res.has_value(), "parse_ipynb must accept valid nbformat 4.4");
  NotebookDocument doc = std::move(parsed_res).value();

  require(doc.nbformat == 4 && doc.nbformat_minor == 4, "nbformat version preserved");
  require(doc.metadata.kernelspec.has_value() &&
              doc.metadata.kernelspec->name == "python3",
          "kernelspec parsed and name matches");
  require(doc.metadata.language_info.has_value() &&
              doc.metadata.language_info->version == "3.12.4",
          "language_info parsed and version matches");
  require(doc.cells.size() == 3U, "3 cells parsed");
  require(doc.cells[0U].cell_type == NotebookCellType::markdown, "cell 0 is markdown");
  require(doc.cells[0U].source == "# Title\nBody paragraph.",
          "array source normalized cleanly");
  require(doc.cells[0U].attachments.has_value(), "attachments preserved");
  require(doc.cells[1U].cell_type == NotebookCellType::code, "cell 1 is code");
  require(doc.cells[1U].source == "import math\nprint(math.pi)",
          "string source normalized cleanly");
  require(doc.cells[1U].execution_count == std::optional<std::int64_t>{7},
          "execution_count preserved");
  require(doc.cells[1U].outputs.size() == 4U, "all 4 outputs parsed");
  require(doc.cells[2U].cell_type == NotebookCellType::raw, "cell 2 is raw");

  // Verify ANSI stripping directly.
  const std::string stripped = strip_ansi_and_control_sequences(
      "\x1b[38;5;196mRED\x1b[0m \x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\ "
      "\x07\x08ok\r\n");
  require(stripped == "RED link ok\n", "ANSI CSI/OSC/control stripped cleanly");

  // Verify outline hygiene: large PNG & PDF base64 summarized by mime+bytes, NOT
  // dumped!
  const std::string outline = format_notebook_outline(doc);
  require(outline.find("kernel=python3") != std::string::npos, "outline shows kernel");
  require(outline.find("[0] markdown") != std::string::npos, "outline shows cell 0");
  require(outline.find("[1] code") != std::string::npos, "outline shows cell 1");
  require(outline.find("[2] raw") != std::string::npos, "outline shows cell 2");
  require(outline.find("OK: line1") != std::string::npos,
          "outline strips ANSI cleanly");
  require(outline.find('\x1b') == std::string::npos, "outline contains zero ESC bytes");
  require(outline.find("[image/png: 9000 bytes]") != std::string::npos,
          "outline summarizes large PNG base64 by mime + decoded byte count");
  require(outline.find("[application/pdf: 3000 bytes]") != std::string::npos,
          "outline summarizes large PDF base64 by mime + decoded byte count");
  require(outline.find("AAAAAAAAAAAAAAAAAAAA") == std::string::npos,
          "outline must NEVER dump raw base64 blobs");
  require(outline.size() < 2048U,
          "outline remains compact despite 16KB binary outputs");

  // Verify raw outputs in NotebookDocument were NOT mutated by hygiene!
  require(doc.cells[1U].outputs[1U].data[1U].data.string() == huge_png_b64,
          "raw PNG base64 preserved verbatim in NotebookDocument");

  // Canonical nbformat v4.5 round-trip.
  auto ser_res = serialize_ipynb(doc);
  require(ser_res.has_value(), "serialize_ipynb must succeed");
  auto reparsed_res = parse_ipynb(ser_res.value());
  require(reparsed_res.has_value(), "re-parsing serialized nbformat v4.5 must succeed");
  const NotebookDocument &roundtrip = reparsed_res.value();

  require(roundtrip.nbformat == 4 && roundtrip.nbformat_minor == 5,
          "serialize_ipynb emits canonical nbformat v4.5");
  require(!roundtrip.cells[0U].id.empty() && roundtrip.cells[0U].id != "cell-0",
          "synthesized cell id avoids collision with existing cell-0");
  require(roundtrip.cells[1U].id == "cell-0", "explicit cell id preserved");
  require(roundtrip.cells[1U].outputs == doc.cells[1U].outputs,
          "outputs round-trip identically including raw PNG/PDF/ANSI");
  require(roundtrip.metadata == doc.metadata, "metadata round-trips identically");
  require(roundtrip.cells[0U].source == doc.cells[0U].source,
          "markdown source round-trips identically");

  // Structural in-memory cell transforms.
  require(replace_cell_source(doc, 1U, "x = 2 + 2\nx").has_value(),
          "replace_cell_source valid index");
  require(doc.cells[1U].source == "x = 2 + 2\nx", "cell source updated");
  require(!replace_cell_source(doc, 99U, "bad").has_value(),
          "replace_cell_source rejects out-of-range index");

  NotebookCell inserted;
  inserted.cell_type = NotebookCellType::code;
  inserted.source = "print('inserted')";
  require(insert_cell(doc, 1U, inserted).has_value(), "insert_cell at index 1");
  require(doc.cells.size() == 4U, "cell count incremented to 4");
  require(!doc.cells[1U].id.empty(), "inserted cell receives unique id");
  require(!insert_cell(doc, 99U, inserted).has_value(),
          "insert_cell rejects out-of-range index");

  NotebookOutput new_out;
  new_out.output_type = NotebookOutputType::stream;
  new_out.stream_name = "stdout";
  new_out.text = "inserted\n";
  require(update_cell_outputs(doc, 1U, {new_out}, std::int64_t{9}).has_value(),
          "update_cell_outputs on code cell succeeds");
  require(doc.cells[1U].execution_count == std::optional<std::int64_t>{9},
          "execution_count updated");
  require(!update_cell_outputs(doc, 0U, {new_out}, std::int64_t{1}).has_value(),
          "update_cell_outputs rejected on markdown cell");

  require(delete_cell(doc, 1U).has_value(), "delete_cell valid index");
  require(doc.cells.size() == 3U, "cell count back to 3");
  require(!delete_cell(doc, 3U).has_value(), "delete_cell rejects out-of-range");

  // Malformed & non-v4 rejection.
  require(!parse_ipynb("{not json").has_value(), "rejects invalid JSON");
  require(!parse_ipynb("[]").has_value(), "rejects non-object root");
  {
    auto v3 =
        parse_ipynb(R"({"nbformat":3,"nbformat_minor":0,"metadata":{},"cells":[]})");
    require(!v3.has_value() &&
                v3.error().detail ==
                    static_cast<std::int64_t>(JupyterErrorDetail::unsupported_nbformat),
            "rejects nbformat v3");
  }
  {
    auto v5 =
        parse_ipynb(R"({"nbformat":5,"nbformat_minor":0,"metadata":{},"cells":[]})");
    require(!v5.has_value() &&
                v5.error().detail ==
                    static_cast<std::int64_t>(JupyterErrorDetail::unsupported_nbformat),
            "rejects nbformat v5");
  }
  {
    auto v4f =
        parse_ipynb(R"({"nbformat":4.5,"nbformat_minor":0,"metadata":{},"cells":[]})");
    require(!v4f.has_value(), "rejects floating-point nbformat");
  }
  {
    auto bad_ct = parse_ipynb(
        R"({"nbformat":4,"nbformat_minor":5,"metadata":{},"cells":[{"cell_type":"bogus","source":""}]})");
    require(!bad_ct.has_value(), "rejects unknown cell_type");
  }
  {
    auto bad_out = parse_ipynb(
        R"({"nbformat":4,"nbformat_minor":5,"metadata":{},"cells":[{"cell_type":"code","source":"","outputs":[{"output_type":"bogus"}]}]})");
    require(!bad_out.has_value(), "rejects unknown output_type");
  }
}

// ---------------------------------------------------------------------------
// Test 2: Security Policy, Loopback Mock Jupyter REST + WebSocket v13 + FD Check
// ---------------------------------------------------------------------------

void test_jupyter_client_mock_server() {
  // Security policy: strictly refuse non-loopback plain http:// URLs!
  const std::array<std::string_view, 6U> refused_urls = {
      "http://example.com:8888", "http://192.168.1.50:8888",
      "http://10.0.0.1:8888",    "http://0.0.0.0:8888",
      "http://127.0.0.2:8888",   "http://[2001:db8::1]:8888",
  };
  for (const std::string_view url : refused_urls) {
    auto res = JupyterClient::create({.base_url = std::string{url}});
    require(!res.has_value() && res.error().detail ==
                                    static_cast<std::int64_t>(
                                        JupyterErrorDetail::non_loopback_http_refused),
            "non-loopback plain http:// must be strictly refused");
  }
  require(!JupyterClient::create({.base_url = "ws://127.0.0.1:8888"}).has_value(),
          "non-http(s) scheme refused");
  require(!JupyterClient::create(
               {.base_url = "http://127.0.0.1:8888", .api_token = "bad\r\nX: 1"})
               .has_value(),
          "token containing CRLF refused");

  // Allowed loopback plain http:// URLs parse cleanly.
  require(JupyterClient::create({.base_url = "http://127.0.0.1:8888"}).has_value(),
          "http://127.0.0.1 allowed");
  require(JupyterClient::create({.base_url = "http://localhost:8888/lab/"}).has_value(),
          "http://localhost with base path allowed");
  require(JupyterClient::create({.base_url = "http://[::1]:8888"}).has_value(),
          "http://[::1] allowed");

  const std::size_t baseline_fds = count_open_fds();
  const std::string secret_token = "bb-super-secret-token-9f8e7d6c";

  {
    MockJupyterServer server{secret_token};

    // Wrong token must fail with provider_auth and NEVER leak the token in diagnostics!
    {
      const std::string wrong_tok = "wrong-token-never-echo-me-xyz";
      auto bad_client_res = JupyterClient::create(
          {.base_url = server.base_url(), .api_token = wrong_tok});
      require(bad_client_res.has_value(), "client create succeeds for loopback");
      JupyterClient bad_client = std::move(bad_client_res).value();
      auto list_res = bad_client.list_kernels();
      require(!list_res.has_value() &&
                  list_res.error().code == ErrorCode::provider_auth,
              "wrong token fails with provider_auth");
      require(bad_client.last_error_detail().find(wrong_tok) == std::string_view::npos,
              "last_error_detail must NEVER emit API token");
    }

    std::string started_kernel_id;
    {
      auto client_res = JupyterClient::create(
          {.base_url = server.base_url(), .api_token = secret_token});
      require(client_res.has_value(), "client create succeeds");
      JupyterClient client = std::move(client_res).value();

      // Reject path-traversal kernel IDs before touching the network.
      require(!client.interrupt_kernel("../escape").has_value(),
              "path traversal kernel_id rejected");
      require(!client.shutdown_kernel("bad/id").has_value(),
              "slash in kernel_id rejected");

      // 1. list_kernels (chunked response).
      auto list1 = client.list_kernels();
      require(list1.has_value(), "list_kernels succeeds");
      require(list1.value().size() == 1U && list1.value()[0U].id == "kernel-existing-1",
              "list_kernels returns seeded kernel");

      // 2. start_kernel.
      auto started = client.start_kernel("python3");
      require(started.has_value(), "start_kernel succeeds");
      started_kernel_id = started.value().id;
      require(started.value().name == "python3", "started kernel name matches");

      // 3. execute_code (success: stream fragmented + ping/pong + execute_result +
      //    display_data + unrelated msg_id filtered).
      auto exec_ok = client.execute_code({.kernel_id = started_kernel_id,
                                          .code = "print('hi'); 42",
                                          .timeout = std::chrono::milliseconds{5000}});
      require(exec_ok.has_value(), "execute_code rich success path succeeds");
      const auto &res = exec_ok.value();
      require(res.status == "ok", "execute_reply status is ok");
      require(res.execution_count == std::optional<std::int64_t>{1},
              "execution_count is 1");
      require(res.outputs.size() == 3U,
              "collected stream + execute_result + display_data (unrelated filtered)");
      require(res.outputs[0U].output_type == NotebookOutputType::stream &&
                  res.outputs[0U].text.find("hello from kernel") != std::string::npos,
              "fragmented stream output collected intact");
      require(res.outputs[1U].output_type == NotebookOutputType::execute_result &&
                  res.outputs[1U].data[0U].data.string() == "42",
              "execute_result collected");
      require(res.outputs[2U].output_type == NotebookOutputType::display_data &&
                  res.outputs[2U].data[0U].mime_type == "image/png",
              "display_data collected");
      require(server.pong_verified_count() == 2U,
              "server verified both masked Pong replies (including mid-fragment Ping)");
      require(server.masked_request_count() >= 1U,
              "server verified client WebSocket frames were masked");

      // 4. execute_code (error path + execute_reply before status:idle).
      auto exec_err = client.execute_code({.kernel_id = started_kernel_id,
                                           .code = "1/0",
                                           .timeout = std::chrono::milliseconds{5000}});
      require(exec_err.has_value(),
              "execute_code returns structured kernel error result");
      require(exec_err.value().status == "error", "status is error");
      require(exec_err.value().error_name ==
                  std::optional<std::string>{"ZeroDivisionError"},
              "error_name captured");
      require(exec_err.value().outputs.size() == 1U &&
                  exec_err.value().outputs[0U].output_type == NotebookOutputType::error,
              "error output collected");

      // 5. execute_code bad Sec-WebSocket-Accept rejected!
      server.set_bad_ws_accept(true);
      auto bad_ws = client.execute_code({.kernel_id = started_kernel_id,
                                         .code = "1+1",
                                         .timeout = std::chrono::milliseconds{3000}});
      server.set_bad_ws_accept(false);
      require(!bad_ws.has_value() &&
                  bad_ws.error().detail == static_cast<std::int64_t>(
                                               JupyterErrorDetail::ws_handshake_failed),
              "invalid Sec-WebSocket-Accept must be rejected");

      // 6. execute_code bounded timeout!
      server.set_silent_ws(true);
      const auto t0 = std::chrono::steady_clock::now();
      auto timed_out = client.execute_code({.kernel_id = started_kernel_id,
                                            .code = "while True: pass",
                                            .timeout = std::chrono::milliseconds{200}});
      const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - t0)
                                  .count();
      server.set_silent_ws(false);
      require(!timed_out.has_value() &&
                  timed_out.error().detail ==
                      static_cast<std::int64_t>(JupyterErrorDetail::execution_timeout),
              "silent kernel hits bounded execution_timeout");
      require(elapsed_ms < 2500, "timeout returns promptly without hanging");

      // 7. interrupt_kernel.
      require(client.interrupt_kernel(started_kernel_id).has_value(),
              "interrupt_kernel succeeds");
      require(server.interrupt_count() == 1U, "server received interrupt POST");
    }

    // Consumer-only invariant: destroying JupyterClient MUST NOT shut down kernels!
    require(server.shutdown_count() == 0U,
            "destructor must NEVER shut down remote kernels");

    // 8. Explicit shutdown_kernel.
    {
      auto client_res = JupyterClient::create(
          {.base_url = server.base_url(), .api_token = secret_token});
      require(client_res.has_value(), "second client create succeeds");
      JupyterClient client = std::move(client_res).value();
      require(client.shutdown_kernel(started_kernel_id).has_value(),
              "explicit shutdown_kernel succeeds");
      require(server.shutdown_count() == 1U, "server received DELETE for kernel");
      auto list2 = client.list_kernels();
      require(list2.has_value() && list2.value().size() == 1U,
              "shut-down kernel removed from kernel list");
    }

    server.stop();
  }

  const std::size_t after_fds = count_open_fds();
  require(after_fds == baseline_fds,
          "zero leaked file descriptors after client + server");
}

// ---------------------------------------------------------------------------
// Test 3: Passive probe_jupyter_capabilities()
// ---------------------------------------------------------------------------

void test_probe_jupyter_capabilities() {
  const std::size_t baseline_fds = count_open_fds();

  // 1. Absent binary never fails.
  {
    const JupyterCapabilities absent = probe_jupyter_capabilities(
        {.executable_override = "/nonexistent/blackbird/jupyter-missing"});
    require(!absent.jupyter_available, "absent jupyter reports unavailable");
    require(absent.kernelspecs.empty(), "absent jupyter reports zero kernelspecs");
    require(!absent.diagnostic.empty(), "absent jupyter sets diagnostic");
  }

  // 2. Deterministic fake jupyter executable returning kernelspec JSON.
  {
    TempDir dir{"bb-jupyter-probe"};
    const fs::path fake_ok = dir.path() / "fake-jupyter";
    {
      std::ofstream out{fake_ok, std::ios::binary};
      require(out.good(), "write fake jupyter script");
      out << "#!/bin/sh\n"
             "cat <<'EOF'\n"
             "{\"kernelspecs\":{"
             "\"python3\":{\"resource_dir\":\"/opt/kernels/python3\","
             "\"spec\":{\"display_name\":\"Python 3\",\"language\":\"python\"}},"
             "\"ir\":{\"resource_dir\":\"/opt/kernels/ir\","
             "\"spec\":{\"display_name\":\"R\",\"language\":\"R\"}}"
             "}}\n"
             "EOF\n";
    }
    require(::chmod(fake_ok.c_str(), 0700) == 0, "chmod +x fake jupyter");

    const JupyterCapabilities caps =
        probe_jupyter_capabilities({.executable_override = fake_ok.string(),
                                    .timeout = std::chrono::milliseconds{3000}});
    require(caps.jupyter_available, "fake jupyter detected as available");
    require(caps.jupyter_path == fake_ok.string(), "jupyter_path recorded");
    require(caps.kernelspecs.size() == 2U, "two kernelspecs parsed");
    require(caps.kernelspecs[0U].name == "ir" && caps.kernelspecs[0U].language == "R",
            "kernelspecs sorted deterministically (ir first)");
    require(caps.kernelspecs[1U].name == "python3" &&
                caps.kernelspecs[1U].display_name == "Python 3" &&
                caps.kernelspecs[1U].resource_dir == "/opt/kernels/python3",
            "python3 kernelspec fields parsed");

    // 3. Hanging fake jupyter script bounded by timeout and cleanly reaped.
    const fs::path fake_hang = dir.path() / "fake-jupyter-hang";
    {
      std::ofstream out{fake_hang, std::ios::binary};
      require(out.good(), "write hanging fake jupyter script");
      out << "#!/bin/sh\nsleep 10\n";
    }
    require(::chmod(fake_hang.c_str(), 0700) == 0, "chmod +x hanging fake jupyter");

    const auto t0 = std::chrono::steady_clock::now();
    const JupyterCapabilities hung =
        probe_jupyter_capabilities({.executable_override = fake_hang.string(),
                                    .timeout = std::chrono::milliseconds{150}});
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0)
                                .count();
    require(hung.jupyter_available, "hanging binary still marks binary present");
    require(hung.kernelspecs.empty(), "hanging binary yields empty kernelspecs");
    require(hung.diagnostic.find("timed out") != std::string::npos,
            "timeout diagnostic recorded");
    require(elapsed_ms < 2000, "hanging probe terminated promptly");

    // 3b. Relative PATH entries (e.g. ".") must be ignored during passive PATH scan.
    const fs::path rel_dir = dir.path() / "untrusted-cwd";
    fs::create_directories(rel_dir);
    const fs::path rel_jupyter = rel_dir / "jupyter";
    {
      std::ofstream out{rel_jupyter, std::ios::binary};
      require(out.good(), "write untrusted relative jupyter script");
      out << "#!/bin/sh\necho '{\"kernelspecs\":{}}'\n";
    }
    require(::chmod(rel_jupyter.c_str(), 0700) == 0, "chmod +x relative jupyter");

    struct ScopedPathAndCwd {
      fs::path old_cwd;
      std::optional<std::string> old_path;
      ScopedPathAndCwd(const fs::path &next_cwd, const char *next_path)
          : old_cwd(fs::current_path()) {
        if (const char *cur = std::getenv("PATH")) {
          old_path = std::string{cur};
        }
        fs::current_path(next_cwd);
        (void)::setenv("PATH", next_path, 1);
      }
      ScopedPathAndCwd(const ScopedPathAndCwd &) = delete;
      ScopedPathAndCwd &operator=(const ScopedPathAndCwd &) = delete;
      ~ScopedPathAndCwd() {
        std::error_code ec;
        fs::current_path(old_cwd, ec);
        if (old_path.has_value()) {
          (void)::setenv("PATH", old_path->c_str(), 1);
        } else {
          (void)::unsetenv("PATH");
        }
      }
    };
    {
      ScopedPathAndCwd guard{rel_dir, ".:untrusted-cwd"};
      const JupyterCapabilities skipped =
          probe_jupyter_capabilities({.timeout = std::chrono::milliseconds{1000}});
      require(!skipped.jupyter_available,
              "relative PATH entries must never execute untrusted ./jupyter");
    }
  }

  // 4. Default host PATH probe (passes whether or not host has jupyter installed).
  {
    const JupyterCapabilities host_caps =
        probe_jupyter_capabilities({.timeout = std::chrono::milliseconds{2000}});
    if (host_caps.jupyter_available) {
      require(!host_caps.jupyter_path.empty(), "host jupyter path non-empty");
    }
  }

  require(count_open_fds() == baseline_fds,
          "zero leaked file descriptors after capability probes");
}

} // namespace

int main() {
  try {
    test_ipynb_engine_and_hygiene();
    test_jupyter_client_mock_server();
    test_probe_jupyter_capabilities();
    std::cout << "jupyter_notebook_test: ALL PASS\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "jupyter_notebook_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
