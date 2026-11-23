#include "blackbird/json.hpp"
#include "blackbird/lsp_client.hpp"
#include "blackbird/value.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <optional>
#include <poll.h>
#include <source_location>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

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
  if (!condition)
    fail_require(claim, loc);
}

std::size_t count_open_fds() {
  std::size_t count = 0;
  for (int fd = 0; fd < 1024; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1)
      ++count;
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

void write_file_bytes(const fs::path &path, std::string_view content) {
  fs::create_directories(path.parent_path());
  std::ofstream out{path, std::ios::binary | std::ios::trunc};
  require(out.good(), "open fixture file for write");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  require(out.good(), "write fixture file");
}

std::string read_file_bytes(const fs::path &path) {
  std::ifstream in{path, std::ios::binary};
  require(in.good(), "open fixture file for read");
  return std::string{std::istreambuf_iterator<char>{in},
                     std::istreambuf_iterator<char>{}};
}

bool write_raw_all(int fd, std::string_view data, bool one_byte_trickle = false) {
  std::size_t offset = 0;
  while (offset < data.size()) {
    const std::size_t chunk = one_byte_trickle ? 1U : (data.size() - offset);
    const ssize_t n = ::write(fd, data.data() + offset, chunk);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }
    if (n == 0)
      return false;
    offset += static_cast<std::size_t>(n);
  }
  return true;
}

bool write_lsp_frame(int fd, const Value &msg,
                     std::string_view header_name = "Content-Length",
                     bool one_byte_trickle = false) {
  auto body = dump_json(msg);
  if (!body.has_value())
    return false;
  std::string frame;
  frame.append(header_name);
  frame.append(": ");
  frame.append(std::to_string(body.value().size()));
  frame.append("\r\nContent-Type: application/vscode-jsonrpc; charset=utf-8\r\n\r\n");
  frame.append(body.value());
  return write_raw_all(fd, frame, one_byte_trickle);
}

std::optional<Value> read_lsp_frame(int fd, std::string &buf) {
  while (true) {
    const std::size_t sep = buf.find("\r\n\r\n");
    if (sep != std::string::npos) {
      const std::string headers = buf.substr(0, sep);
      std::size_t content_len = 0;
      bool found = false;
      std::size_t pos = 0;
      while (pos < headers.size()) {
        const std::size_t nl = headers.find("\r\n", pos);
        const std::string line = (nl == std::string::npos)
                                     ? headers.substr(pos)
                                     : headers.substr(pos, nl - pos);
        pos = (nl == std::string::npos) ? headers.size() : (nl + 2U);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
          std::string name = line.substr(0, colon);
          std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
          });
          if (name == "content-length") {
            content_len = std::stoull(line.substr(colon + 1U));
            found = true;
          }
        }
      }
      if (!found)
        return std::nullopt;
      buf.erase(0, sep + 4U);
      while (buf.size() < content_len) {
        std::array<char, 4096> tmp{};
        const ssize_t n = ::read(fd, tmp.data(), tmp.size());
        if (n < 0) {
          if (errno == EINTR)
            continue;
          return std::nullopt;
        }
        if (n == 0)
          return std::nullopt;
        buf.append(tmp.data(), static_cast<std::size_t>(n));
      }
      const std::string payload = buf.substr(0, content_len);
      buf.erase(0, content_len);
      auto parsed = parse_json(payload);
      if (!parsed.has_value())
        return std::nullopt;
      return std::move(parsed).value();
    }

    std::array<char, 4096> tmp{};
    const ssize_t n = ::read(fd, tmp.data(), tmp.size());
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return std::nullopt;
    }
    if (n == 0)
      return std::nullopt;
    buf.append(tmp.data(), static_cast<std::size_t>(n));
  }
}

Value make_range_val(std::uint32_t sl, std::uint32_t sc, std::uint32_t el,
                     std::uint32_t ec) {
  return Value::object({
      {"start",
       Value::object({{"line", Value{Number{static_cast<std::uint64_t>(sl)}}},
                      {"character", Value{Number{static_cast<std::uint64_t>(sc)}}}})},
      {"end",
       Value::object({{"line", Value{Number{static_cast<std::uint64_t>(el)}}},
                      {"character", Value{Number{static_cast<std::uint64_t>(ec)}}}})},
  });
}

Value make_rpc_result(const Value &id, Value result) {
  return Value::object({
      {"jsonrpc", Value{"2.0"}},
      {"id", id},
      {"result", std::move(result)},
  });
}

// ---------------------------------------------------------------------------
// Child helper modes for stdio_spawn tests (re-invoking this test binary)
// ---------------------------------------------------------------------------

int run_mock_stdio_clean() {
  std::string buf;
  while (auto msg = read_lsp_frame(STDIN_FILENO, buf)) {
    const Value *method = msg->find("method");
    const Value *id = msg->find("id");
    if (method == nullptr || !std::holds_alternative<std::string>(method->value()))
      continue;
    const std::string &m = method->string();
    if (m == "initialize" && id != nullptr) {
      bool has_numeric_pid = false;
      if (const Value *params = msg->find("params");
          params != nullptr && std::holds_alternative<Value::Object>(params->value())) {
        if (const Value *pid = params->find("processId");
            pid != nullptr && std::holds_alternative<Number>(pid->value())) {
          has_numeric_pid = true;
        }
      }
      Value result = Value::object({
          {"serverInfo",
           Value::object({{"name", Value{has_numeric_pid ? "mock-stdio" : "bad-pid"}},
                          {"version", Value{"1.0"}}})},
          {"capabilities", Value::object({
                               {"positionEncoding", Value{"utf-8"}},
                               {"hoverProvider", Value{true}},
                           })},
      });
      (void)write_lsp_frame(STDOUT_FILENO, make_rpc_result(*id, std::move(result)));
    } else if (m == "textDocument/hover" && id != nullptr) {
      Value result = Value::object({
          {"contents", Value::object({{"kind", Value{"plaintext"}},
                                      {"value", Value{"stdio hover ok"}}})},
      });
      (void)write_lsp_frame(STDOUT_FILENO, make_rpc_result(*id, std::move(result)));
    } else if (m == "shutdown" && id != nullptr) {
      (void)write_lsp_frame(STDOUT_FILENO, make_rpc_result(*id, Value{nullptr}));
    } else if (m == "exit") {
      return 0;
    }
  }
  return 0;
}

int run_mock_stdio_stuck() {
  // Ignore SIGTERM so client must escalate SIGTERM -> SIGKILL and reap cleanly.
  (void)::signal(SIGTERM, SIG_IGN);
  std::string buf;
  if (auto msg = read_lsp_frame(STDIN_FILENO, buf)) {
    const Value *id = msg->find("id");
    if (id != nullptr) {
      Value result = Value::object({
          {"capabilities", Value::object({{"positionEncoding", Value{"utf-8"}}})},
      });
      (void)write_lsp_frame(STDOUT_FILENO, make_rpc_result(*id, std::move(result)));
    }
  }
  while (true)
    ::pause();
}

// ---------------------------------------------------------------------------
// Test 1: Pure UTF-8 <-> UTF-16 & UTF-8 <-> LSP column conversions
// ---------------------------------------------------------------------------

void test_utf8_utf16_conversions() {
  // Line with:
  // "a" (1 byte, 1 utf16)
  // "é" U+00E9 (2 bytes, 1 utf16)
  // "中" U+4E2D (3 bytes, 1 utf16)
  // "🚀" U+1F680 (4 bytes, 2 utf16 - surrogate pair!)
  // "𝄞" U+1D11E (4 bytes, 2 utf16 - surrogate pair!)
  // "z" (1 byte, 1 utf16)
  const std::string line = "a\xC3\xA9\xE4\xB8\xAD\xF0\x9F\x9A\x80\xF0\x9D\x84\x9Ez";
  require(line.size() == 15U, "expected exact UTF-8 byte length 15");

  struct Pair {
    std::size_t utf8_byte;
    std::uint32_t utf16_col;
    std::uint32_t utf32_col;
  };
  const std::array<Pair, 7> boundaries{{
      {0U, 0U, 0U},
      {1U, 1U, 1U},
      {3U, 2U, 2U},
      {6U, 3U, 3U},
      {10U, 5U, 4U},
      {14U, 7U, 5U},
      {15U, 8U, 6U},
  }};

  for (const auto &b : boundaries) {
    auto to16 = utf8_byte_offset_to_utf16_column(line, b.utf8_byte);
    require(to16.has_value() && to16.value() == b.utf16_col,
            "utf8->utf16 boundary conversion");
    auto back8 = utf16_column_to_utf8_byte_offset(line, b.utf16_col);
    require(back8.has_value() && back8.value() == b.utf8_byte,
            "utf16->utf8 boundary conversion");

    auto to8_lsp =
        utf8_byte_offset_to_lsp_column(line, b.utf8_byte, LspPositionEncoding::utf8);
    require(to8_lsp.has_value() && to8_lsp.value() == b.utf8_byte,
            "utf8->lsp(utf8) identity");
    auto back8_lsp = lsp_column_to_utf8_byte_offset(
        line, static_cast<std::uint32_t>(b.utf8_byte), LspPositionEncoding::utf8);
    require(back8_lsp.has_value() && back8_lsp.value() == b.utf8_byte,
            "lsp(utf8)->utf8 identity");

    auto to32 =
        utf8_byte_offset_to_lsp_column(line, b.utf8_byte, LspPositionEncoding::utf32);
    require(to32.has_value() && to32.value() == b.utf32_col, "utf8->lsp(utf32)");
    auto back32 =
        lsp_column_to_utf8_byte_offset(line, b.utf32_col, LspPositionEncoding::utf32);
    require(back32.has_value() && back32.value() == b.utf8_byte, "lsp(utf32)->utf8");
  }

  // Empty line
  require(utf8_byte_offset_to_utf16_column("", 0U).value() == 0U, "empty utf8->utf16");
  require(utf16_column_to_utf8_byte_offset("", 0U).value() == 0U, "empty utf16->utf8");

  // Mid-codepoint UTF-8 offsets MUST be rejected
  require(!utf8_byte_offset_to_utf16_column(line, 2U).has_value(),
          "reject mid-2byte utf8 offset");
  require(!utf8_byte_offset_to_utf16_column(line, 7U).has_value(),
          "reject mid-4byte utf8 offset");
  require(
      !utf8_byte_offset_to_lsp_column(line, 7U, LspPositionEncoding::utf8).has_value(),
      "reject mid-4byte utf8 offset in utf8 mode");
  require(!utf8_byte_offset_to_utf16_column(line, 16U).has_value(),
          "reject out-of-bounds utf8 offset");

  // Mid-surrogate-pair UTF-16 columns MUST be rejected (col 4 splits 🚀, col 6 splits
  // 𝄞)
  require(!utf16_column_to_utf8_byte_offset(line, 4U).has_value(),
          "reject mid-surrogate utf16 column 4");
  require(!utf16_column_to_utf8_byte_offset(line, 6U).has_value(),
          "reject mid-surrogate utf16 column 6");
  require(!utf16_column_to_utf8_byte_offset(line, 9U).has_value(),
          "reject out-of-bounds utf16 column");

  // Invalid UTF-8 rejected
  const std::string bad_utf8{"\xFF\xFE"};
  require(!utf8_byte_offset_to_utf16_column(bad_utf8, 0U).has_value(),
          "reject invalid utf8 in utf8->utf16");
  require(!utf16_column_to_utf8_byte_offset(bad_utf8, 0U).has_value(),
          "reject invalid utf8 in utf16->utf8");
}

// ---------------------------------------------------------------------------
// Test 2: Strict file:// URI validation & workspace_root escape rejection
// ---------------------------------------------------------------------------

void test_workspace_uri_validation() {
  TempDir outer{"bb-lsp-uri-outer"};
  const fs::path ws = outer.path() / "ws";
  const fs::path sibling = outer.path() / "ws_sibling";
  const fs::path secret = outer.path() / "secret.txt";
  fs::create_directories(ws / "src");
  fs::create_directories(sibling);
  write_file_bytes(ws / "src" / "main.cpp", "int main() {}\n");
  write_file_bytes(ws / "src" / "space file.cpp", "int x = 1;\n");
  write_file_bytes(sibling / "other.cpp", "int y = 2;\n");
  write_file_bytes(secret, "TOP SECRET\n");

  fs::create_symlink(outer.path(), ws / "escape_dir");
  fs::create_symlink(secret, ws / "escape_file.txt");
  fs::create_symlink(outer.path() / "nonexistent_outside.txt", ws / "dangling_escape");

  // Valid round-trip
  auto main_uri = path_to_file_uri(ws / "src" / "main.cpp");
  require(main_uri.has_value(), "encode valid path to file:// URI");
  auto main_back = resolve_workspace_file_uri({ws, main_uri.value()});
  require(main_back.has_value() &&
              main_back.value() == fs::canonical(ws / "src" / "main.cpp"),
          "decode valid file:// URI");

  // Valid space encoding + localhost authority
  auto space_uri = path_to_file_uri(ws / "src" / "space file.cpp");
  require(space_uri.has_value() && space_uri.value().find("%20") != std::string::npos,
          "percent-encode space in file:// URI");
  auto space_back = resolve_workspace_file_uri({ws, space_uri.value()});
  require(space_back.has_value(), "decode percent-encoded space URI");

  const std::string localhost_uri =
      "file://localhost" + (ws / "src" / "main.cpp").string();
  require(resolve_workspace_file_uri({ws, localhost_uri}).has_value(),
          "allow localhost authority in file:// URI");

  // Rejections
  const std::vector<std::string> malicious_uris{
      "http://localhost/etc/passwd",
      "file:///etc/passwd",
      "file://evil.example" + (ws / "src" / "main.cpp").string(),
      "file://" + ws.string() + "/../secret.txt",
      "file://" + ws.string() + "/%2e%2e/secret.txt",
      "file://" + ws.string() + "/src/%2e%2e/%2e%2e/secret.txt",
      "file://" + ws.string() + "/src/main%00.cpp",
      "file://" + ws.string() + "/src/main%0a.cpp",
      "file://" + ws.string() + "/src/main%7f.cpp",
      "file://" + ws.string() + "/src/main.cpp?query=1",
      "file://" + ws.string() + "/src/main.cpp#frag",
      "file://" + ws.string() + "/src/main%ZZ.cpp",
      "file://" + (sibling / "other.cpp").string(),
      "file://" + (ws / "escape_dir" / "secret.txt").string(),
      "file://" + (ws / "escape_file.txt").string(),
      "file://" + (ws / "dangling_escape").string(),
  };
  for (const auto &bad : malicious_uris) {
    auto res = resolve_workspace_file_uri({ws, bad});
    require(!res.has_value(), "must reject escaped/malformed URI: " + bad);
  }
}

// ---------------------------------------------------------------------------
// Test 3: Full LSP protocol suite via in-process socketpair mock server
// ---------------------------------------------------------------------------

void test_full_lsp_protocol_and_rename_safety() {
  TempDir outer{"bb-lsp-proto"};
  const fs::path ws = outer.path() / "workspace";
  const fs::path outside_secret = outer.path() / "outside.cpp";
  fs::create_directories(ws / "src");

  const std::string main_content = "// emoji 🚀 greeting\n"
                                   "int greet_🚀_fn() { return 42; }\n"
                                   "int caller() { return greet_🚀_fn(); }\n";
  const std::string helper_content = "extern int greet_🚀_fn();\n"
                                     "int use_it() { return greet_🚀_fn(); }\n";

  const fs::path main_path = ws / "src" / "main.cpp";
  const fs::path helper_path = ws / "src" / "helper.cpp";
  write_file_bytes(main_path, main_content);
  write_file_bytes(helper_path, helper_content);
  write_file_bytes(outside_secret, "int secret = 1;\n");

  const std::string main_uri = path_to_file_uri(main_path).value();
  const std::string helper_uri = path_to_file_uri(helper_path).value();
  const std::string escape_uri = path_to_file_uri(outside_secret).value();

  std::array<int, 2> fds{-1, -1};
  require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0, "socketpair");

  std::atomic<int> server_saw_method_not_found{0};
  std::atomic<bool> server_saw_did_open{false};
  std::atomic<bool> server_saw_did_change{false};
  std::atomic<bool> server_saw_did_close{false};
  std::atomic<bool> server_saw_shutdown{false};
  std::atomic<bool> server_saw_exit{false};

  std::thread mock_server([&, server_fd = fds[1]]() {
    std::string buf;
    bool sent_server_requests = false;
    std::vector<Value> ooo_queue;

    while (auto msg = read_lsp_frame(server_fd, buf)) {
      // Check if this is a client response to our server-initiated requests.
      if (msg->find("method") == nullptr && msg->find("error") != nullptr) {
        const Value *err = msg->find("error");
        if (err != nullptr && std::holds_alternative<Value::Object>(err->value())) {
          const Value *code = err->find("code");
          if (code != nullptr && std::holds_alternative<Number>(code->value()) &&
              code->number().text() == "-32601") {
            server_saw_method_not_found.fetch_add(1);
          }
        }
        continue;
      }

      const Value *method_val = msg->find("method");
      const Value *id_val = msg->find("id");
      const Value *params_val = msg->find("params");
      if (method_val == nullptr ||
          !std::holds_alternative<std::string>(method_val->value()))
        continue;
      const std::string &method = method_val->string();

      if (method == "initialize" && id_val != nullptr) {
        // Test case-insensitive Content-Length header & trickle 1-byte delivery.
        Value result = Value::object({
            {"serverInfo", Value::object({{"name", Value{"blackbird-mock-lsp"}},
                                          {"version", Value{"0.9"}}})},
            {"capabilities",
             Value::object({
                 {"positionEncoding", Value{"utf-16"}},
                 {"definitionProvider", Value{true}},
                 {"referencesProvider", Value{true}},
                 {"hoverProvider", Value{true}},
                 {"documentSymbolProvider", Value{true}},
                 {"workspaceSymbolProvider", Value{true}},
                 {"callHierarchyProvider", Value{true}},
                 {"renameProvider", Value::object({{"prepareProvider", Value{true}}})},
             })},
        });
        (void)write_lsp_frame(server_fd, make_rpc_result(*id_val, std::move(result)),
                              "cOnTeNt-LeNgTh", true);
      } else if (method == "textDocument/didOpen") {
        server_saw_did_open.store(true);
        // Push both a valid workspace diagnostic AND an escaped diagnostic (must be
        // dropped).
        Value diag_ok = Value::object({
            {"jsonrpc", Value{"2.0"}},
            {"method", Value{"textDocument/publishDiagnostics"}},
            {"params",
             Value::object({
                 {"uri", Value{main_uri}},
                 {"version", Value{Number{std::int64_t{1}}}},
                 {"diagnostics", Value{Value::Array{Value::object({
                                     {"range", make_range_val(1, 4, 1, 14)},
                                     {"severity", Value{Number{std::uint64_t{2}}}},
                                     {"code", Value{"W001"}},
                                     {"source", Value{"mock-clangd"}},
                                     {"message", Value{"unused emoji greeting"}},
                                 })}}},
             })},
        });
        Value diag_bad = Value::object({
            {"jsonrpc", Value{"2.0"}},
            {"method", Value{"textDocument/publishDiagnostics"}},
            {"params", Value::object({
                           {"uri", Value{escape_uri}},
                           {"diagnostics", Value{Value::Array{}}},
                       })},
        });
        (void)write_lsp_frame(server_fd, diag_ok);
        (void)write_lsp_frame(server_fd, diag_bad);
      } else if (method == "textDocument/didChange") {
        server_saw_did_change.store(true);
      } else if (method == "textDocument/didClose") {
        server_saw_did_close.store(true);
      } else if (method == "textDocument/hover" && id_val != nullptr) {
        if (!sent_server_requests) {
          sent_server_requests = true;
          // Send 3 server-initiated requests (int id, string id, workspace/applyEdit)
          // BEFORE answering hover to verify zero deadlock and -32601 replies!
          (void)write_lsp_frame(server_fd,
                                Value::object({
                                    {"jsonrpc", Value{"2.0"}},
                                    {"id", Value{Number{std::int64_t{9001}}}},
                                    {"method", Value{"client/registerCapability"}},
                                    {"params", Value::object({})},
                                }));
          (void)write_lsp_frame(server_fd,
                                Value::object({
                                    {"jsonrpc", Value{"2.0"}},
                                    {"id", Value{"srv-cfg-1"}},
                                    {"method", Value{"workspace/configuration"}},
                                    {"params", Value::object({})},
                                }));
          (void)write_lsp_frame(server_fd,
                                Value::object({
                                    {"jsonrpc", Value{"2.0"}},
                                    {"id", Value{Number{std::int64_t{9002}}}},
                                    {"method", Value{"workspace/applyEdit"}},
                                    {"params", Value::object({})},
                                }));
        }
        Value hover_res = Value::object({
            {"contents", Value::object({
                             {"kind", Value{"markdown"}},
                             {"value", Value{"`int greet_🚀_fn()`"}},
                         })},
            {"range", make_range_val(1, 4, 1, 15)},
        });
        (void)write_lsp_frame(server_fd,
                              make_rpc_result(*id_val, std::move(hover_res)));
      } else if (method == "textDocument/definition" && id_val != nullptr) {
        // Check if position line == 99 to trigger path-escape URI test.
        bool trigger_escape = false;
        if (params_val != nullptr &&
            std::holds_alternative<Value::Object>(params_val->value())) {
          const Value *p = params_val->find("position");
          if (p != nullptr && std::holds_alternative<Value::Object>(p->value())) {
            const Value *l = p->find("line");
            if (l != nullptr && std::holds_alternative<Number>(l->value()) &&
                l->number().text() == "99") {
              trigger_escape = true;
            }
          }
        }
        Value def_res = Value{Value::Array{Value::object({
            {"targetUri", Value{trigger_escape ? escape_uri : main_uri}},
            {"targetRange", make_range_val(1, 0, 1, 32)},
            {"targetSelectionRange", make_range_val(1, 4, 1, 16)},
        })}};
        (void)write_lsp_frame(server_fd, make_rpc_result(*id_val, std::move(def_res)));
      } else if (method == "textDocument/references" && id_val != nullptr) {
        Value refs = Value{Value::Array{
            Value::object(
                {{"uri", Value{main_uri}}, {"range", make_range_val(1, 4, 1, 16)}}),
            Value::object(
                {{"uri", Value{helper_uri}}, {"range", make_range_val(1, 22, 1, 34)}}),
        }};
        (void)write_lsp_frame(server_fd, make_rpc_result(*id_val, std::move(refs)));
      } else if (method == "textDocument/documentSymbol" && id_val != nullptr) {
        Value child = Value::object({
            {"name", Value{"inner_var"}},
            {"detail", Value{"int"}},
            {"kind", Value{Number{std::uint64_t{13}}}},
            {"range", make_range_val(1, 20, 1, 29)},
            {"selectionRange", make_range_val(1, 20, 1, 29)},
        });
        Value sym = Value::object({
            {"name", Value{"greet_🚀_fn"}},
            {"detail", Value{"int ()"}},
            {"kind", Value{Number{std::uint64_t{12}}}},
            {"range", make_range_val(1, 0, 1, 32)},
            {"selectionRange", make_range_val(1, 4, 1, 16)},
            {"children", Value{Value::Array{std::move(child)}}},
        });
        (void)write_lsp_frame(
            server_fd, make_rpc_result(*id_val, Value{Value::Array{std::move(sym)}}));
      } else if (method == "workspace/symbol" && id_val != nullptr) {
        Value sym = Value::object({
            {"name", Value{"greet_🚀_fn"}},
            {"kind", Value{Number{std::uint64_t{12}}}},
            {"containerName", Value{"global"}},
            {"location", Value::object({
                             {"uri", Value{main_uri}},
                             {"range", make_range_val(1, 4, 1, 16)},
                         })},
        });
        (void)write_lsp_frame(
            server_fd, make_rpc_result(*id_val, Value{Value::Array{std::move(sym)}}));
      } else if (method == "textDocument/prepareCallHierarchy" && id_val != nullptr) {
        Value item = Value::object({
            {"name", Value{"greet_🚀_fn"}},
            {"kind", Value{Number{std::uint64_t{12}}}},
            {"detail", Value{"main.cpp"}},
            {"uri", Value{main_uri}},
            {"range", make_range_val(1, 0, 1, 32)},
            {"selectionRange", make_range_val(1, 4, 1, 16)},
            {"data", Value::object({{"opaqueToken", Value{"tok-42"}}})},
        });
        (void)write_lsp_frame(
            server_fd, make_rpc_result(*id_val, Value{Value::Array{std::move(item)}}));
      } else if (method == "callHierarchy/incomingCalls" && id_val != nullptr) {
        // Verify opaque data was preserved round-trip!
        bool data_ok = false;
        if (params_val != nullptr &&
            std::holds_alternative<Value::Object>(params_val->value())) {
          const Value *it = params_val->find("item");
          if (it != nullptr && std::holds_alternative<Value::Object>(it->value())) {
            const Value *d = it->find("data");
            if (d != nullptr && std::holds_alternative<Value::Object>(d->value())) {
              const Value *tok = d->find("opaqueToken");
              data_ok = tok != nullptr &&
                        std::holds_alternative<std::string>(tok->value()) &&
                        tok->string() == "tok-42";
            }
          }
        }
        Value incoming = Value::object({
            {"from", Value::object({
                         {"name", Value{data_ok ? "caller" : "BAD_DATA"}},
                         {"kind", Value{Number{std::uint64_t{12}}}},
                         {"uri", Value{main_uri}},
                         {"range", make_range_val(2, 0, 2, 38)},
                         {"selectionRange", make_range_val(2, 4, 2, 10)},
                     })},
            {"fromRanges", Value{Value::Array{make_range_val(2, 22, 2, 34)}}},
        });
        (void)write_lsp_frame(
            server_fd,
            make_rpc_result(*id_val, Value{Value::Array{std::move(incoming)}}));
      } else if (method == "callHierarchy/outgoingCalls" && id_val != nullptr) {
        Value outgoing = Value::object({
            {"to", Value::object({
                       {"name", Value{"use_it"}},
                       {"kind", Value{Number{std::uint64_t{12}}}},
                       {"uri", Value{helper_uri}},
                       {"range", make_range_val(1, 0, 1, 38)},
                       {"selectionRange", make_range_val(1, 4, 1, 10)},
                   })},
            {"fromRanges", Value{Value::Array{make_range_val(1, 22, 1, 34)}}},
        });
        (void)write_lsp_frame(
            server_fd,
            make_rpc_result(*id_val, Value{Value::Array{std::move(outgoing)}}));
      } else if (method == "textDocument/prepareRename" && id_val != nullptr) {
        Value prep = Value::object({
            {"range", make_range_val(1, 4, 1, 16)},
            {"placeholder", Value{"greet_🚀_fn"}},
        });
        (void)write_lsp_frame(server_fd, make_rpc_result(*id_val, std::move(prep)));
      } else if (method == "textDocument/rename" && id_val != nullptr) {
        std::string new_name;
        if (params_val != nullptr &&
            std::holds_alternative<Value::Object>(params_val->value())) {
          if (const Value *nn = params_val->find("newName");
              nn != nullptr && std::holds_alternative<std::string>(nn->value())) {
            new_name = nn->string();
          }
        }
        if (new_name == "escape_target") {
          // Server tries to smuggle an edit outside workspace_root -> MUST REJECT!
          Value evil = Value::object({
              {"changes", Value::object({
                              {escape_uri, Value{Value::Array{Value::object({
                                               {"range", make_range_val(0, 0, 0, 3)},
                                               {"newText", Value{"pwn"}},
                                           })}}},
                          })},
          });
          (void)write_lsp_frame(server_fd, make_rpc_result(*id_val, std::move(evil)));
        } else if (new_name == "overlap_target") {
          // Server sends overlapping edits -> MUST REJECT!
          Value overlap = Value::object({
              {"changes", Value::object({
                              {main_uri, Value{Value::Array{
                                             Value::object({
                                                 {"range", make_range_val(1, 4, 1, 12)},
                                                 {"newText", Value{"a"}},
                                             }),
                                             Value::object({
                                                 {"range", make_range_val(1, 8, 1, 16)},
                                                 {"newText", Value{"b"}},
                                             }),
                                         }}},
                          })},
          });
          (void)write_lsp_frame(server_fd,
                                make_rpc_result(*id_val, std::move(overlap)));
        } else {
          // Valid multi-file rename with UTF-16 columns across surrogate pair "🚀"!
          // In "int greet_🚀_fn() { return 42; }":
          //   "int " = 4 utf16 units
          //   "greet_" = 6 utf16 units
          //   "🚀" = 2 utf16 units (surrogate pair!)
          //   "_fn" = 3 utf16 units -> total 11 utf16 units -> [4, 15)
          // In "int caller() { return greet_🚀_fn(); }":
          //   "int caller() { return " = 22 utf16 units -> [22, 33)
          // In helper.cpp:
          //   line 0: "extern int " = 11 -> [11, 22)
          //   line 1: "int use_it() { return " = 22 -> [22, 33)
          // Send edits intentionally UNSORTED in main_uri to verify sorting!
          Value edit_plan = Value::object({
              {"documentChanges",
               Value{Value::Array{
                   Value::object({
                       {"textDocument", Value::object({{"uri", Value{main_uri}},
                                                       {"version", Value{nullptr}}})},
                       {"edits", Value{Value::Array{
                                     Value::object({
                                         {"range", make_range_val(2, 22, 2, 33)},
                                         {"newText", Value{new_name}},
                                     }),
                                     Value::object({
                                         {"range", make_range_val(1, 4, 1, 15)},
                                         {"newText", Value{new_name}},
                                     }),
                                 }}},
                   }),
                   Value::object({
                       {"textDocument", Value::object({{"uri", Value{helper_uri}},
                                                       {"version", Value{nullptr}}})},
                       {"edits", Value{Value::Array{
                                     Value::object({
                                         {"range", make_range_val(1, 22, 1, 33)},
                                         {"newText", Value{new_name}},
                                     }),
                                     Value::object({
                                         {"range", make_range_val(0, 11, 0, 22)},
                                         {"newText", Value{new_name}},
                                     }),
                                 }}},
                   }),
               }}},
          });
          (void)write_lsp_frame(server_fd,
                                make_rpc_result(*id_val, std::move(edit_plan)));
        }
      } else if (method == "custom/ooo" && id_val != nullptr) {
        // Buffer 4 pipelined requests (int & string IDs) and reply in reverse order!
        ooo_queue.push_back(Value::object({
            {"id", *id_val},
            {"params", params_val != nullptr ? *params_val : Value{nullptr}},
        }));
        if (ooo_queue.size() == 4U) {
          for (auto it = ooo_queue.rbegin(); it != ooo_queue.rend(); ++it) {
            const Value *qid = it->find("id");
            const Value *qp = it->find("params");
            if (qid != nullptr && qp != nullptr)
              (void)write_lsp_frame(server_fd, make_rpc_result(*qid, *qp));
          }
          ooo_queue.clear();
        }
      } else if (method == "shutdown" && id_val != nullptr) {
        server_saw_shutdown.store(true);
        (void)write_lsp_frame(server_fd, make_rpc_result(*id_val, Value{nullptr}));
      } else if (method == "exit") {
        server_saw_exit.store(true);
        break;
      }
    }
    (void)::close(server_fd);
  });

  {
    LspAttachedFdsConfig cfg{};
    cfg.workspace_root = ws;
    cfg.read_fd = fds[0];
    cfg.write_fd = fds[0];
    cfg.close_fds_on_destroy = true;
    cfg.allow_protocol_shutdown = true;

    auto client_res = LspClient::attach_fds(cfg);
    require(client_res.has_value(), "attach_fds succeeds");
    LspClient client = std::move(client_res).value();

    // 1. initialize (negotiates UTF-16, reads case-insensitive header via 1-byte
    // trickle!)
    auto init = client.initialize();
    require(init.has_value(), "initialize succeeds");
    require(init.value().server_name == "blackbird-mock-lsp", "serverInfo.name");
    require(client.position_encoding() == LspPositionEncoding::utf16,
            "negotiated utf-16 encoding");
    require(init.value().capabilities.rename_prepare_provider, "prepareProvider true");

    // 2. didOpen + publishDiagnostics cache + escaped diagnostic dropped
    require(client.did_open({main_path, "cpp", 1, main_content}).has_value(),
            "did_open");
    auto polled = client.poll_notifications(std::chrono::milliseconds{2000});
    require(polled.has_value() && polled.value() >= 1U, "polled publishDiagnostics");
    auto diag = client.cached_diagnostics(main_path);
    require(diag.has_value(), "cached diagnostics call succeeds");
    const auto &diag_opt = diag.value();
    if (!diag_opt.has_value())
      fail_require("cached diagnostics found");
    require(diag_opt->diagnostics.size() == 1U, "one diagnostic cached");
    require(diag_opt->diagnostics[0].code == "W001", "diagnostic code W001");
    require(client.dropped_diagnostics_count() == 1U,
            "escaped diagnostic URI dropped and counted");

    // 3. hover (also triggers 3 server-initiated requests; must reply -32601 without
    // deadlock)
    auto hov = client.hover({main_path, {1, 6}});
    require(hov.has_value(), "hover succeeds despite server reqs");
    const auto &hov_opt = hov.value();
    if (!hov_opt.has_value())
      fail_require("hover payload present");
    require(hov_opt->value == "`int greet_🚀_fn()`", "hover markdown value");
    require(client.rejected_server_request_count() == 3U,
            "client rejected 3 server-initiated requests");

    // 4. definition (valid + path-escape URI rejection)
    auto def = client.definition({main_path, {2, 24}});
    require(def.has_value() && def.value().size() == 1U,
            "definition returns 1 LocationLink");
    require(def.value()[0].path == fs::canonical(main_path),
            "definition canonical path");
    auto bad_def = client.definition({main_path, {99, 0}});
    require(!bad_def.has_value() && bad_def.error().code == ErrorCode::invalid_range,
            "definition rejects escaped file:// URI");

    // 5. references
    auto refs = client.references({main_path, {1, 6}, true});
    require(refs.has_value() && refs.value().size() == 2U,
            "references returns 2 locations");

    // 6. document_symbols (hierarchical)
    auto dsyms = client.document_symbols(main_path);
    require(dsyms.has_value() && dsyms.value().size() == 1U, "document_symbols size 1");
    require(dsyms.value()[0].name == "greet_🚀_fn", "top symbol name");
    require(dsyms.value()[0].children.size() == 1U &&
                dsyms.value()[0].children[0].name == "inner_var",
            "hierarchical child symbol preserved");

    // 7. workspace_symbols
    auto wsyms = client.workspace_symbols("greet");
    require(wsyms.has_value() && wsyms.value().size() == 1U,
            "workspace_symbols size 1");
    require(wsyms.value()[0].container_name == "global", "workspace symbol container");

    // 8. callHierarchy (prepare + incoming with opaque data round-trip + outgoing)
    auto ch_items = client.prepare_call_hierarchy({main_path, {1, 6}});
    require(ch_items.has_value() && ch_items.value().size() == 1U,
            "prepare_call_hierarchy");
    auto inc = client.incoming_calls(ch_items.value()[0]);
    require(inc.has_value() && inc.value().size() == 1U &&
                inc.value()[0].from.name == "caller",
            "incoming_calls preserved opaque data");
    auto out = client.outgoing_calls(ch_items.value()[0]);
    require(out.has_value() && out.value().size() == 1U &&
                out.value()[0].to.name == "use_it",
            "outgoing_calls");

    // 9. prepare_rename & rename -> LspWorkspaceEditPlan (ZERO DISK WRITES!)
    auto prep = client.prepare_rename({main_path, {1, 6}});
    require(prep.has_value(), "prepare_rename succeeds");
    const auto &prep_opt = prep.value();
    if (!prep_opt.has_value())
      fail_require("prepare_rename result present");
    require(prep_opt->placeholder == "greet_🚀_fn", "prepare_rename placeholder");

    auto plan = client.rename({main_path, {1, 6}, "hello_world_fn"});
    require(plan.has_value(), "rename returns structured LspWorkspaceEditPlan");
    require(plan.value().files.size() == 2U, "rename plan covers 2 workspace files");
    require(plan.value().total_edits == 4U, "rename plan has 4 total edits");
    require(plan.value().files[0].relative_path.generic_string() == "src/helper.cpp",
            "files sorted deterministically by relative path");
    require(plan.value().files[1].relative_path.generic_string() == "src/main.cpp",
            "second file is src/main.cpp");
    // Verify edits inside main.cpp were sorted ascending!
    require(plan.value().files[1].edits[0].range.start.line == 1U &&
                plan.value().files[1].edits[1].range.start.line == 2U,
            "edits sorted ascending");
    // Verify unified preview accurately replaced across UTF-16 surrogate pair!
    require(plan.value().unified_preview.find("-int greet_🚀_fn() { return 42; }\n") !=
                std::string::npos,
            "unified preview shows old emoji line");
    require(plan.value().unified_preview.find(
                "+int hello_world_fn() { return 42; }\n") != std::string::npos,
            "unified preview shows renamed line");
    require(plan.value().unified_preview.find(
                "--- a/src/helper.cpp\n+++ b/src/helper.cpp\n") != std::string::npos,
            "unified preview includes helper.cpp diff header");

    // CRITICAL AUDIT INVARIANT: verify ZERO disk writes!
    require(read_file_bytes(main_path) == main_content,
            "main.cpp on disk MUST remain completely untouched by rename()");
    require(read_file_bytes(helper_path) == helper_content,
            "helper.cpp on disk MUST remain completely untouched by rename()");

    // Verify rename rejects escaped URI and overlapping edits!
    auto evil_plan = client.rename({main_path, {1, 6}, "escape_target"});
    require(!evil_plan.has_value() &&
                evil_plan.error().code == ErrorCode::invalid_range,
            "rename rejects escaped file:// URI");
    require(read_file_bytes(outside_secret) == "int secret = 1;\n",
            "outside file untouched");

    auto overlap_plan = client.rename({main_path, {1, 6}, "overlap_target"});
    require(!overlap_plan.has_value() &&
                overlap_plan.error().code == ErrorCode::conflict,
            "rename rejects overlapping text edits");

    // 10. Out-of-order response correlation by integer AND string IDs
    const LspRequestId id_i1{std::int64_t{501}};
    const LspRequestId id_s1{std::string{"req-alpha"}};
    const LspRequestId id_i2{std::int64_t{502}};
    const LspRequestId id_s2{std::string{"req-beta"}};
    require(client.send_request_with_id(id_i1, "custom/ooo", Value{"one"}).has_value(),
            "send ooo int 1");
    require(client.send_request_with_id(id_s1, "custom/ooo", Value{"two"}).has_value(),
            "send ooo str 1");
    require(
        client.send_request_with_id(id_i2, "custom/ooo", Value{"three"}).has_value(),
        "send ooo int 2");
    require(client.send_request_with_id(id_s2, "custom/ooo", Value{"four"}).has_value(),
            "send ooo str 2");

    auto r_i1 = client.wait_for_response(id_i1);
    auto r_s1 = client.wait_for_response(id_s1);
    auto r_i2 = client.wait_for_response(id_i2);
    auto r_s2 = client.wait_for_response(id_s2);
    require(r_i1.has_value() && r_i1.value() == Value{"one"}, "ooo correlate int 501");
    require(r_s1.has_value() && r_s1.value() == Value{"two"},
            "ooo correlate str alpha");
    require(r_i2.has_value() && r_i2.value() == Value{"three"},
            "ooo correlate int 502");
    require(r_s2.has_value() && r_s2.value() == Value{"four"},
            "ooo correlate str beta");

    // 11. didChange + didClose
    require(
        client.did_change({main_path, 2, {{std::nullopt, main_content}}}).has_value(),
        "did_change");
    require(client.did_close(main_path).has_value(), "did_close");

    // 12. shutdown
    require(client.shutdown().has_value(), "shutdown succeeds");
  }

  mock_server.join();
  require(server_saw_did_open.load(), "server received didOpen");
  require(server_saw_did_change.load(), "server received didChange");
  require(server_saw_did_close.load(), "server received didClose");
  require(server_saw_shutdown.load(), "server received shutdown");
  require(server_saw_exit.load(), "server received exit");
  require(server_saw_method_not_found.load() == 3,
          "server received -32601 for all 3 server-initiated requests");
}

// ---------------------------------------------------------------------------
// Test 4: Malformed Content-Length, oversized payload, EOF, timeout recovery
// ---------------------------------------------------------------------------

void test_framing_faults_eof_and_timeout() {
  TempDir ws{"bb-lsp-faults"};

  auto run_raw_server_payload = [&](std::string raw_bytes, std::size_t max_payload,
                                    ErrorCode expected_code, std::string_view label) {
    std::array<int, 2> fds{-1, -1};
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0, "socketpair");
    std::thread srv([server_fd = fds[1], payload = std::move(raw_bytes)]() {
      std::string buf;
      (void)read_lsp_frame(server_fd, buf);
      if (!payload.empty())
        (void)write_raw_all(server_fd, payload);
      (void)::close(server_fd);
    });

    LspAttachedFdsConfig cfg{};
    cfg.workspace_root = ws.path();
    cfg.read_fd = fds[0];
    cfg.write_fd = fds[0];
    cfg.max_payload_bytes = max_payload;
    cfg.timeouts.request = std::chrono::milliseconds{500};
    auto client = LspClient::attach_fds(cfg);
    require(client.has_value(), "attach_fds for fault test");
    auto res = client.value().request_raw("test/fault", Value::object({}));
    require(!res.has_value() && res.error().code == expected_code, label);
    srv.join();
  };

  run_raw_server_payload("Content-Length: -5\r\n\r\n{}", 1024U, ErrorCode::corrupt,
                         "reject negative Content-Length");
  run_raw_server_payload("Content-Length: abc\r\n\r\n{}", 1024U, ErrorCode::corrupt,
                         "reject non-numeric Content-Length");
  run_raw_server_payload("Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 1024U,
                         ErrorCode::corrupt, "reject duplicate Content-Length");
  run_raw_server_payload("X-Other: 1\r\n\r\n{}", 1024U, ErrorCode::corrupt,
                         "reject missing Content-Length");
  run_raw_server_payload("Content-Length: 20000000\r\n\r\n", kLspDefaultMaxPayloadBytes,
                         ErrorCode::capacity,
                         "reject >16 MiB oversized Content-Length");
  run_raw_server_payload("Content-Length: 2048\r\n\r\n", 1024U, ErrorCode::capacity,
                         "reject >configured max_payload_bytes");
  run_raw_server_payload("", 1024U, ErrorCode::incomplete,
                         "clean EOF recovery on abrupt server close");
  run_raw_server_payload("Content-Length: 50\r\n\r\n{\"partial\":", 1024U,
                         ErrorCode::incomplete, "clean truncated payload EOF recovery");

  // Timeout recovery: server reads request and stalls without responding.
  {
    std::array<int, 2> fds{-1, -1};
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0,
            "socketpair timeout");
    std::atomic<bool> stop_server{false};
    std::thread srv([server_fd = fds[1], &stop_server]() {
      std::string buf;
      (void)read_lsp_frame(server_fd, buf);
      while (!stop_server.load())
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
      (void)::close(server_fd);
    });

    LspAttachedFdsConfig cfg{};
    cfg.workspace_root = ws.path();
    cfg.read_fd = fds[0];
    cfg.write_fd = fds[0];
    cfg.timeouts.request = std::chrono::milliseconds{120};
    auto client = LspClient::attach_fds(cfg);
    require(client.has_value(), "attach_fds timeout");
    const int fd_flags = ::fcntl(fds[0], F_GETFL);
    require(fd_flags >= 0 && (fd_flags & O_NONBLOCK) != 0,
            "attach_fds configures O_NONBLOCK on attached descriptors");
    auto res = client.value().request_raw("test/stall", Value::object({}));
    require(!res.has_value() && res.error().code == ErrorCode::io &&
                res.error().detail == ETIMEDOUT,
            "stalled server triggers ETIMEDOUT");
    stop_server.store(true);
    srv.join();
  }

  // Mid-payload timeout recovery: partial JSON body must NOT desync framing!
  {
    const fs::path diag_file = ws.path() / "partial.cpp";
    write_file_bytes(diag_file, "int p = 0;\n");
    const std::string diag_uri = path_to_file_uri(diag_file).value();
    const Value notif = Value::object({
        {"jsonrpc", Value{"2.0"}},
        {"method", Value{"textDocument/publishDiagnostics"}},
        {"params", Value::object({
                       {"uri", Value{diag_uri}},
                       {"diagnostics",
                        Value{Value::Array{Value::object({
                            {"range", make_range_val(0, 0, 0, 3)},
                            {"severity", Value{Number{std::uint64_t{1}}}},
                            {"code", Value{"E_PARTIAL"}},
                            {"message", Value{"recovered after mid-payload timeout"}},
                        })}}},
                   })},
    });
    const std::string body = dump_json(notif).value();
    const std::string header =
        "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";

    std::array<int, 2> fds{-1, -1};
    require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds.data()) == 0,
            "socketpair mid-payload");
    std::atomic<bool> send_rest{false};
    std::atomic<bool> done_with_srv{false};
    std::thread srv([server_fd = fds[1], header, body, &send_rest, &done_with_srv]() {
      // Deliver full header + only first 10 bytes of JSON body, then pause.
      (void)write_raw_all(server_fd, header);
      (void)write_raw_all(server_fd, std::string_view{body}.substr(0, 10U));
      while (!send_rest.load())
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
      (void)write_raw_all(server_fd, std::string_view{body}.substr(10U));
      while (!done_with_srv.load())
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
      (void)::close(server_fd);
    });
    struct ThreadJoinGuard {
      std::atomic<bool> &release;
      std::atomic<bool> &done;
      std::thread &worker;
      ~ThreadJoinGuard() {
        release.store(true);
        done.store(true);
        if (worker.joinable())
          worker.join();
      }
    } join_guard{send_rest, done_with_srv, srv};

    LspAttachedFdsConfig cfg{};
    cfg.workspace_root = ws.path();
    cfg.read_fd = fds[0];
    cfg.write_fd = fds[0];
    auto client = LspClient::attach_fds(cfg);
    require(client.has_value(), "attach_fds mid-payload");

    // First poll times out mid-payload; framing & connection MUST stay intact!
    auto p1 = client.value().poll_notifications(std::chrono::milliseconds{40});
    require(p1.has_value() && p1.value() == 0U, "mid-payload poll times out cleanly");
    require(client.value().is_open(),
            "connection stays open after mid-payload timeout");

    // Release remaining payload bytes; next poll MUST decode the complete frame!
    send_rest.store(true);
    auto p2 = client.value().poll_notifications(std::chrono::milliseconds{500});
    require(p2.has_value() && p2.value() == 1U,
            "completed frame decoded cleanly after mid-payload timeout");
    require(client.value().is_open(), "connection remains open after recovery");
    auto diag = client.value().cached_diagnostics(diag_file);
    require(diag.has_value(), "cached_diagnostics succeeds after recovery");
    const auto &diag_opt = diag.value();
    if (!diag_opt.has_value())
      fail_require("recovered diagnostic present in cache");
    require(diag_opt->diagnostics.size() == 1U &&
                diag_opt->diagnostics[0].code == "E_PARTIAL",
            "recovered diagnostic payload matches exact notification");
  }
}

// ---------------------------------------------------------------------------
// Test 5: Consumer-only external Unix & TCP loopback socket daemons
// ---------------------------------------------------------------------------

struct SharedDaemonStats {
  std::atomic<int> sessions_served{0};
  std::atomic<bool> saw_unexpected_exit{false};
  std::atomic<bool> saw_non_null_process_id{false};
};

void serve_shared_daemon_two_sessions(int listen_fd, SharedDaemonStats &stats) {
  for (int i = 0; i < 2; ++i) {
    const int conn = ::accept(listen_fd, nullptr, nullptr);
    if (conn < 0)
      break;
    stats.sessions_served.fetch_add(1);
    std::string buf;
    while (auto msg = read_lsp_frame(conn, buf)) {
      const Value *m = msg->find("method");
      const Value *id = msg->find("id");
      if (m == nullptr || !std::holds_alternative<std::string>(m->value()))
        continue;
      if (m->string() == "shutdown" || m->string() == "exit") {
        stats.saw_unexpected_exit.store(true);
        break;
      }
      if (m->string() == "initialize" && id != nullptr) {
        const Value *params = msg->find("params");
        if (params == nullptr ||
            !std::holds_alternative<Value::Object>(params->value())) {
          stats.saw_non_null_process_id.store(true);
        } else {
          const Value *pid = params->find("processId");
          if (pid == nullptr || !std::holds_alternative<std::nullptr_t>(pid->value()))
            stats.saw_non_null_process_id.store(true);
        }
        Value result = Value::object({
            {"capabilities", Value::object({{"positionEncoding", Value{"utf-8"}}})},
        });
        (void)write_lsp_frame(conn, make_rpc_result(*id, std::move(result)));
      }
    }
    (void)::close(conn);
  }
  (void)::close(listen_fd);
}

void test_external_unix_and_tcp_daemons_never_terminated() {
  TempDir ws{"bb-lsp-ext"};

  // 1. External Unix domain socket daemon
  {
    const fs::path sock_path = ws.path() / "shared.sock";
    const int lfd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    require(lfd >= 0, "create AF_UNIX listener");
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const std::string sp = sock_path.string();
    require(sp.size() < sizeof(addr.sun_path), "unix socket path length");
    std::memcpy(addr.sun_path, sp.data(), sp.size());
    require(::bind(lfd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0,
            "bind unix socket");
    require(::listen(lfd, 4) == 0, "listen unix socket");

    SharedDaemonStats stats;
    std::thread daemon(serve_shared_daemon_two_sessions, lfd, std::ref(stats));

    for (int round = 0; round < 2; ++round) {
      LspUnixSocketConfig cfg{};
      cfg.workspace_root = ws.path();
      cfg.socket_path = sock_path;
      auto client = LspClient::attach_unix_socket(cfg);
      require(client.has_value(), "attach_unix_socket succeeds");
      require(!client.value().owns_process(), "unix socket client does not own daemon");
      auto init = client.value().initialize();
      require(init.has_value(), "unix socket initialize succeeds");
      require(client.value().position_encoding() == LspPositionEncoding::utf8,
              "negotiated utf-8 over unix socket");
      require(client.value().shutdown().has_value(), "unix socket consumer shutdown");
    }

    daemon.join();
    require(stats.sessions_served.load() == 2,
            "external unix daemon survived first client & served second");
    require(!stats.saw_unexpected_exit.load(),
            "external unix daemon NEVER received shutdown/exit");
    require(!stats.saw_non_null_process_id.load(),
            "external unix daemon received processId == null");
  }

  // 2. External TCP loopback daemon + reject non-loopback host
  {
    LspTcpLoopbackConfig bad_cfg{};
    bad_cfg.workspace_root = ws.path();
    bad_cfg.host = "8.8.8.8";
    bad_cfg.port = 9999;
    require(!LspClient::attach_tcp_loopback(bad_cfg).has_value(),
            "reject non-loopback TCP host");

    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    require(lfd >= 0, "create TCP loopback listener");
    int one = 1;
    (void)::setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    require(::bind(lfd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0,
            "bind TCP loopback");
    require(::listen(lfd, 4) == 0, "listen TCP loopback");
    socklen_t len = sizeof(addr);
    require(::getsockname(lfd, reinterpret_cast<sockaddr *>(&addr), &len) == 0,
            "getsockname TCP loopback");
    const std::uint16_t port = ntohs(addr.sin_port);
    require(port != 0U, "ephemeral TCP loopback port");

    SharedDaemonStats stats;
    std::thread daemon(serve_shared_daemon_two_sessions, lfd, std::ref(stats));

    for (int round = 0; round < 2; ++round) {
      LspTcpLoopbackConfig cfg{};
      cfg.workspace_root = ws.path();
      cfg.host = "127.0.0.1";
      cfg.port = port;
      auto client = LspClient::attach_tcp_loopback(cfg);
      require(client.has_value(), "attach_tcp_loopback succeeds");
      require(!client.value().owns_process(), "tcp client does not own daemon");
      require(client.value().initialize().has_value(), "tcp initialize succeeds");
      require(client.value().shutdown().has_value(), "tcp consumer shutdown");
    }

    daemon.join();
    require(stats.sessions_served.load() == 2,
            "external TCP daemon survived first client & served second");
    require(!stats.saw_unexpected_exit.load(),
            "external TCP daemon NEVER received shutdown/exit");
    require(!stats.saw_non_null_process_id.load(),
            "external TCP daemon received processId == null");
  }
}

// ---------------------------------------------------------------------------
// Test 6: stdio_spawn (clean shutdown->exit AND SIGTERM->SIGKILL stuck child)
// ---------------------------------------------------------------------------

void test_stdio_spawn_lifecycle(const fs::path &self_exe) {
  TempDir ws{"bb-lsp-spawn"};
  const fs::path src_file = ws.path() / "a.cpp";
  write_file_bytes(src_file, "int a = 1;\n");

  // Clean stdio_spawn lifecycle
  {
    LspStdioSpawnConfig cfg{};
    cfg.workspace_root = ws.path();
    cfg.executable = self_exe;
    cfg.arguments = {"--mock-lsp-clean"};
    auto client = LspClient::spawn_stdio(cfg);
    require(client.has_value(), "spawn_stdio clean succeeds");
    require(client.value().owns_process(), "stdio_spawn owns child");
    auto init = client.value().initialize();
    require(init.has_value() && init.value().server_name == "mock-stdio",
            "stdio_spawn initialize sends numeric processId");
    auto hov = client.value().hover({src_file, {0, 4}});
    require(hov.has_value(), "stdio_spawn hover succeeds");
    const auto &hov_opt = hov.value();
    if (!hov_opt.has_value())
      fail_require("stdio_spawn hover payload present");
    require(hov_opt->value == "stdio hover ok", "stdio_spawn hover");
    require(client.value().shutdown().has_value(), "stdio_spawn clean shutdown");
  }

  // Stuck child ignoring SIGTERM: must escalate to SIGKILL and reap cleanly
  {
    LspStdioSpawnConfig cfg{};
    cfg.workspace_root = ws.path();
    cfg.executable = self_exe;
    cfg.arguments = {"--mock-lsp-stuck"};
    cfg.timeouts.request = std::chrono::milliseconds{150};
    cfg.timeouts.shutdown_grace = std::chrono::milliseconds{50};
    cfg.timeouts.term_grace = std::chrono::milliseconds{50};
    auto client = LspClient::spawn_stdio(cfg);
    require(client.has_value(), "spawn_stdio stuck succeeds");
    require(client.value().initialize().has_value(), "stuck child initialize");
    // Destructor / disconnect must SIGTERM -> SIGKILL and reap without hanging.
    client.value().disconnect();
    require(!client.value().is_open(), "stuck child disconnected and reaped");
  }
}

// ---------------------------------------------------------------------------
// Test 7: Passive clangd availability probe (optional smoke, never fails if absent)
// ---------------------------------------------------------------------------

std::optional<fs::path> find_clangd_passively() {
  const std::array<const char *, 3> candidates{
      "/opt/homebrew/opt/llvm/bin/clangd",
      "/usr/local/opt/llvm/bin/clangd",
      "/usr/bin/clangd",
  };
  for (const char *path : candidates) {
    if (::access(path, X_OK) == 0)
      return fs::path{path};
  }
  return std::nullopt;
}

void test_passive_clangd_smoke() {
  const auto clangd = find_clangd_passively();
  if (!clangd.has_value()) {
    std::cout << "[info] clangd not present; skipping optional live smoke\n";
    return;
  }

  TempDir ws{"bb-lsp-clangd"};
  const fs::path cpp_file = ws.path() / "sample.cpp";
  const std::string code = "int sample_add(int a, int b) { return a + b; }\n";
  write_file_bytes(cpp_file, code);

  LspStdioSpawnConfig cfg{};
  cfg.workspace_root = ws.path();
  cfg.executable = clangd.value();
  cfg.arguments = {"--background-index=0", "--log=error"};
  cfg.timeouts.request = std::chrono::milliseconds{5000};

  auto client = LspClient::spawn_stdio(cfg);
  if (!client.has_value()) {
    std::cout << "[info] clangd spawn skipped (" << clangd.value().string() << ")\n";
    return;
  }

  auto init = client.value().initialize();
  if (init.has_value()) {
    (void)client.value().did_open({cpp_file, "cpp", 1, code});
    auto syms = client.value().document_symbols(cpp_file);
    std::cout << "[info] passive clangd smoke (" << init.value().server_name
              << "): encoding="
              << (client.value().position_encoding() == LspPositionEncoding::utf8
                      ? "utf-8"
                      : "utf-16")
              << " symbols=" << (syms.has_value() ? syms.value().size() : 0U) << '\n';
  }
  (void)client.value().shutdown();
}

} // namespace

int main(int argc, char **argv) {
  if (argc >= 2 && std::string_view{argv[1]} == "--mock-lsp-clean")
    return run_mock_stdio_clean();
  if (argc >= 2 && std::string_view{argv[1]} == "--mock-lsp-stuck")
    return run_mock_stdio_stuck();

  try {
    const fs::path self_exe = fs::canonical(fs::path{argv[0]});
    const std::size_t fds_before = count_open_fds();

    test_utf8_utf16_conversions();
    test_workspace_uri_validation();
    test_full_lsp_protocol_and_rename_safety();
    test_framing_faults_eof_and_timeout();
    test_external_unix_and_tcp_daemons_never_terminated();
    test_stdio_spawn_lifecycle(self_exe);
    test_passive_clangd_smoke();

    const std::size_t fds_after = count_open_fds();
    require(fds_after == fds_before,
            "zero leaked file descriptors across all LSP tests (before=" +
                std::to_string(fds_before) + ", after=" + std::to_string(fds_after) +
                ")");

    std::cout << "lsp_client_test: ALL CHECKS PASSED (fds=" << fds_after << ")\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "lsp_client_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
