#include "blackbird/os_sandbox.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace {

using namespace blackbird::sandbox;

void require(bool condition, std::string_view claim) {
  if (!condition) {
    throw std::runtime_error(std::string{claim});
  }
}

struct TempDir {
  std::filesystem::path root;

  TempDir() {
    std::string tmpl =
        (std::filesystem::temp_directory_path() / "bb-os-sandbox-test-XXXXXX").string();
    char *created = ::mkdtemp(tmpl.data());
    require(created != nullptr, "mkdtemp for sandbox test fixture");
    root = std::filesystem::canonical(created);
  }

  ~TempDir() {
    if (std::uncaught_exceptions() != 0) {
      std::cerr << "retained failed sandbox fixture: " << root << '\n';
      return;
    }
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
  }
};

void write_text_file(const std::filesystem::path &path, std::string_view content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out{path, std::ios::binary | std::ios::trunc};
  require(out.good(), "open fixture file for write: " + path.string());
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  require(out.good(), "write fixture file: " + path.string());
}

std::string read_text_file(const std::filesystem::path &path) {
  std::ifstream in{path, std::ios::binary};
  require(in.good(), "open fixture file for read: " + path.string());
  return std::string{std::istreambuf_iterator<char>{in},
                     std::istreambuf_iterator<char>{}};
}

struct LoopbackServer {
  int fd = -1;
  std::uint16_t port = 0U;

  LoopbackServer() {
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, "create loopback tcp listener socket");
    int one = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    require(::bind(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) == 0,
            "bind loopback tcp listener");
    require(::listen(fd, 8) == 0, "listen loopback tcp listener");
    socklen_t len = sizeof(addr);
    require(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0,
            "getsockname loopback tcp listener");
    port = ntohs(addr.sin_port);
    require(port != 0U, "ephemeral loopback port non-zero");
  }

  ~LoopbackServer() {
    if (fd >= 0) {
      (void)::close(fd);
    }
  }
};

// Child helper invoked via `os_sandbox_test --probe-net <port> <tcp|udp>`.
int run_child_net_probe(std::uint16_t port, std::string_view proto) {
  if (port == 0U) {
    std::cerr << "invalid port\n";
    return 2;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(port);

  if (proto == "tcp") {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
      std::cout << "socket_errno=" << errno << '\n';
      return (errno == EPERM || errno == EACCES) ? 10 : 11;
    }
    const int rc =
        ::connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    const int saved = errno;
    (void)::close(fd);
    if (rc != 0) {
      std::cout << "connect_errno=" << saved << '\n';
      return (saved == EPERM || saved == EACCES) ? 10 : 12;
    }
    std::cout << "tcp_connected\n";
    return 0;
  }

  if (proto == "udp") {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
      std::cout << "socket_errno=" << errno << '\n';
      return (errno == EPERM || errno == EACCES) ? 10 : 11;
    }
    const char payload[] = "ping";
    const ssize_t rc =
        ::sendto(fd, payload, sizeof(payload) - 1U, 0,
                 reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    const int saved = errno;
    (void)::close(fd);
    if (rc < 0) {
      std::cout << "sendto_errno=" << saved << '\n';
      return (saved == EPERM || saved == EACCES) ? 10 : 12;
    }
    std::cout << "udp_sent\n";
    return 0;
  }

  return 3;
}

void test_capabilities_and_profile_parsing() {
  const auto caps = probe_os_sandbox_capabilities();
  require(caps.available, "OS sandbox must be available on this host");
  require(caps.supports_network_airgap, "host must support network airgap");
  require(!caps.caveats.empty(), "capabilities must include honest caveats");
#if defined(__APPLE__)
  require(caps.platform == "macos", "platform must be macos");
  require(caps.backend_name == "seatbelt", "backend must be seatbelt on macOS");
  require(caps.landlock_abi_version == 0, "landlock ABI must be 0 on macOS");
#elif defined(__linux__)
  require(caps.platform == "linux", "platform must be linux");
  require(caps.backend_name == "landlock+seccomp",
          "backend must be landlock+seccomp on Linux");
  require(caps.landlock_abi_version >= 1, "landlock ABI >= 1 on Linux");
#endif

  require(sandbox_profile_name(SandboxProfile::none) == "black-flag",
          "none profile name");
  require(sandbox_profile_name(SandboxProfile::guarded) == "guarded",
          "guarded profile name");
  require(sandbox_profile_name(SandboxProfile::sandboxed) == "sandboxed",
          "sandboxed profile name");
  require(sandbox_profile_name(SandboxProfile::airgap) == "airgap",
          "airgap profile name");
  require(parse_sandbox_profile("black-flag") == SandboxProfile::none,
          "parse black-flag");
  require(parse_sandbox_profile("none") == SandboxProfile::none, "parse none");
  require(parse_sandbox_profile("guarded") == SandboxProfile::guarded, "parse guarded");
  require(parse_sandbox_profile("sandboxed") == SandboxProfile::sandboxed,
          "parse sandboxed");
  require(parse_sandbox_profile("airgap") == SandboxProfile::airgap, "parse airgap");
  require(!parse_sandbox_profile("bogus").has_value(), "reject unknown profile");
}

void test_sbpl_escaping_and_generation() {
  {
    auto escaped = escape_sbpl_string(R"(/tmp/a"b\c)");
    require(escaped.has_value(), "valid string with quote and backslash escapes");
    require(escaped.value() == R"(/tmp/a\"b\\c)",
            "quote and backslash properly escaped");
  }
  {
    std::string with_nul{"/tmp/ok"};
    with_nul.push_back('\0');
    with_nul.append("tail");
    auto escaped = escape_sbpl_string(with_nul);
    require(!escaped.has_value(), "NUL byte must be rejected");
    require(sandbox_error_of(escaped.error()) == SandboxError::control_char_in_path,
            "NUL error detail");
  }
  {
    auto escaped = escape_sbpl_string("/tmp/line\nbreak");
    require(!escaped.has_value(), "newline control char must be rejected");
    require(sandbox_error_of(escaped.error()) == SandboxError::control_char_in_path,
            "newline error detail");
  }
  {
    auto escaped = escape_sbpl_string("/tmp/del\x7f");
    require(!escaped.has_value(), "DEL control char must be rejected");
    require(sandbox_error_of(escaped.error()) == SandboxError::control_char_in_path,
            "DEL error detail");
  }

  TempDir fx;
  const auto ws = fx.root / "ws";
  const auto tmp = fx.root / "tmp";
  const auto home = fx.root / "home";
  const auto secret = fx.root / "secret\"dir";
  std::filesystem::create_directories(ws);
  std::filesystem::create_directories(tmp);
  std::filesystem::create_directories(home);
  std::filesystem::create_directories(secret);

  SandboxSpec spec;
  spec.profile = SandboxProfile::guarded;
  spec.workspace_root = ws;
  spec.tmp_dir = tmp;
  spec.home_dir = home;
  spec.denied_paths = {secret};
  spec.deny_workspace_dotenv = true;
  spec.include_default_denied_paths = true;

  auto guarded_sbpl = build_macos_seatbelt_profile(spec);
  require(guarded_sbpl.has_value(), "build guarded SBPL profile");
  const std::string &g = guarded_sbpl.value();
  require(g.find("(version 1)") != std::string::npos, "guarded version 1");
  require(g.find("(allow default)") != std::string::npos, "guarded allow default");
  require(g.find("(deny file-write* (subpath \"/\"))") != std::string::npos,
          "guarded denies root write");
  require(g.find("com.apple.coreservices.launchservicesd") != std::string::npos,
          "guarded denies LaunchServices");
  require(g.find("com.apple.pasteboard.1") != std::string::npos,
          "guarded denies pasteboard");
  require(g.find(".git/hooks") != std::string::npos, "guarded denies .git/hooks");
  require(g.find(R"(secret\"dir)") != std::string::npos,
          "guarded escapes quotes in denied_paths");
  require(g.find(".ssh") != std::string::npos, "guarded includes default .ssh deny");
  require(g.find("blackbird/auth") != std::string::npos,
          "guarded includes blackbird/auth deny");
  require(g.find(R"(\.env)") != std::string::npos, "guarded includes .env regex deny");
  require(g.find("example|sample|template") != std::string::npos,
          "guarded allows .env.example/sample/template");

  // Control char in denied path must fail closed!
  {
    SandboxSpec bad = spec;
    bad.denied_paths.push_back(std::filesystem::path{"/tmp/bad\npath"});
    auto bad_res = build_macos_seatbelt_profile(bad);
    require(!bad_res.has_value(), "control char in denied path rejected");
    require(sandbox_error_of(bad_res.error()) == SandboxError::control_char_in_path,
            "control char error detail");
  }

  spec.profile = SandboxProfile::sandboxed;
  auto sandboxed_sbpl = build_macos_seatbelt_profile(spec);
  require(sandboxed_sbpl.has_value(), "build sandboxed SBPL profile");
  require(sandboxed_sbpl.value().find("(deny default)") != std::string::npos,
          "sandboxed uses deny default");
  require(sandboxed_sbpl.value().find("(deny network-outbound)") != std::string::npos,
          "sandboxed denies network-outbound");

  spec.profile = SandboxProfile::airgap;
  auto airgap_sbpl = build_macos_seatbelt_profile(spec);
  require(airgap_sbpl.has_value(), "build airgap SBPL profile");
  require(airgap_sbpl.value().find("(deny default)") != std::string::npos,
          "airgap uses deny default");
  require(airgap_sbpl.value().find("(deny network*)") != std::string::npos,
          "airgap denies network*");
}

void test_real_kernel_enforcement(const std::filesystem::path &self_exe) {
  TempDir fx;
  const auto ws = fx.root / "workspace";
  const auto tmp = fx.root / "tmp";
  const auto home = fx.root / "home";
  const auto secret_dir = fx.root / "secret_dir";
  const auto outside_dir = fx.root / "outside_dir";

  std::filesystem::create_directories(ws / ".git" / "hooks");
  std::filesystem::create_directories(tmp);
  std::filesystem::create_directories(home / ".ssh");
  std::filesystem::create_directories(secret_dir);
  std::filesystem::create_directories(outside_dir);

  write_text_file(ws / "hello.txt", "workspace-ok\n");
  write_text_file(ws / ".env", "DB_PASS=super-secret-env\n");
  write_text_file(ws / ".env.example", "DB_PASS=placeholder\n");
  write_text_file(secret_dir / "secret.txt", "TOP-SECRET-KEY-MATERIAL\n");
  write_text_file(home / ".ssh" / "id_ed25519", "SSH-PRIVATE-KEY\n");
  write_text_file(outside_dir / "outside.txt", "outside-readonly-data\n");

  const auto symlink_to_secret = ws / "symlink_to_secret";
  std::filesystem::create_symlink(secret_dir / "secret.txt", symlink_to_secret);

  LoopbackServer server;
  const std::string port_str = std::to_string(server.port);

  SandboxSpec base_spec;
  base_spec.workspace_root = ws;
  base_spec.tmp_dir = tmp;
  base_spec.home_dir = home;
  base_spec.denied_paths = {secret_dir};
  base_spec.extra_read_paths = {self_exe.parent_path()};
  base_spec.deny_workspace_dotenv = true;
  base_spec.include_default_denied_paths = true;

  // 1. GUARDED: workspace RW works; secret_dir, symlink_to_secret, .ssh, outside write,
  //    .git/hooks write, and .env are all blocked by the OS kernel!
  {
    SandboxSpec guarded = base_spec;
    guarded.profile = SandboxProfile::guarded;

    // 1a. Workspace read + write succeeds.
    {
      auto res = run_sandboxed_child_probe(guarded,
                                           {"/bin/sh", "-c",
                                            "cat \"" + (ws / "hello.txt").string() +
                                                "\" && printf 'written' > \"" +
                                                (ws / "created.txt").string() + "\""});
      require(res.has_value(), "guarded workspace rw probe executed");
      require(!res.value().sandbox_apply_failed, "guarded sandbox applied cleanly");
      require(res.value().exit_code == 0,
              "guarded allows workspace rw: " + res.value().output);
      require(res.value().output.find("workspace-ok") != std::string::npos,
              "guarded read workspace file");
      require(read_text_file(ws / "created.txt") == "written",
              "guarded wrote workspace file");
    }

    // 1b. Direct secret_dir read FAILS at kernel boundary.
    {
      auto res = run_sandboxed_child_probe(
          guarded, {"/bin/cat", (secret_dir / "secret.txt").string()});
      require(res.has_value(), "guarded secret cat probe executed");
      require(!res.value().sandbox_apply_failed, "guarded applied for secret check");
      require(res.value().exit_code != 0, "guarded MUST deny secret_dir read");
      require(res.value().output.find("TOP-SECRET-KEY-MATERIAL") == std::string::npos,
              "secret contents must never leak");
    }

    // 1c. Symlink inside workspace pointing to secret_dir FAILS at kernel boundary!
    {
      auto res =
          run_sandboxed_child_probe(guarded, {"/bin/cat", symlink_to_secret.string()});
      require(res.has_value(), "guarded symlink escape probe executed");
      require(!res.value().sandbox_apply_failed, "guarded applied for symlink check");
      require(res.value().exit_code != 0, "guarded MUST deny symlink_to_secret escape");
      require(res.value().output.find("TOP-SECRET-KEY-MATERIAL") == std::string::npos,
              "symlink secret contents must never leak");
    }

    // 1d. Default home secret (~/.ssh/id_ed25519) FAILS at kernel boundary!
    {
      auto res = run_sandboxed_child_probe(
          guarded, {"/bin/cat", (home / ".ssh" / "id_ed25519").string()});
      require(res.has_value(), "guarded home .ssh probe executed");
      require(!res.value().sandbox_apply_failed, "guarded applied for .ssh check");
      require(res.value().exit_code != 0, "guarded MUST deny home .ssh read");
      require(res.value().output.find("SSH-PRIVATE-KEY") == std::string::npos,
              "ssh key must never leak");
    }

    // 1e. Write to outside_dir FAILS at kernel boundary!
    {
      auto res = run_sandboxed_child_probe(
          guarded, {"/bin/sh", "-c",
                    "printf 'pwn' > \"" + (outside_dir / "pwn").string() + "\""});
      require(res.has_value(), "guarded outside write probe executed");
      require(!res.value().sandbox_apply_failed,
              "guarded applied for outside write check");
      require(res.value().exit_code != 0, "guarded MUST deny write outside workspace");
      require(!std::filesystem::exists(outside_dir / "pwn"),
              "outside_dir/pwn must not exist");
    }

#if defined(__APPLE__)
    // 1f. Write to workspace/.git/hooks FAILS at kernel boundary on macOS Seatbelt!
    {
      auto res = run_sandboxed_child_probe(
          guarded, {"/bin/sh", "-c",
                    "printf '#!/bin/sh\n' > \"" +
                        (ws / ".git" / "hooks" / "pre-commit").string() + "\""});
      require(res.has_value(), "guarded .git/hooks write probe executed");
      require(!res.value().sandbox_apply_failed, "guarded applied for .git/hooks");
      require(res.value().exit_code != 0, "guarded MUST deny .git/hooks write");
    }

    // 1g. Workspace .env denied while .env.example allowed on macOS Seatbelt!
    {
      auto env_res =
          run_sandboxed_child_probe(guarded, {"/bin/cat", (ws / ".env").string()});
      require(env_res.has_value(), "guarded .env read probe executed");
      require(!env_res.value().sandbox_apply_failed, "guarded applied for .env");
      require(env_res.value().exit_code != 0, "guarded MUST deny workspace .env");
      require(env_res.value().output.find("super-secret-env") == std::string::npos,
              ".env contents must not leak");

      auto ex_res = run_sandboxed_child_probe(
          guarded, {"/bin/cat", (ws / ".env.example").string()});
      require(ex_res.has_value(), "guarded .env.example read probe executed");
      require(!ex_res.value().sandbox_apply_failed, "guarded applied for .env.example");
      require(ex_res.value().exit_code == 0,
              "guarded MUST allow workspace .env.example: " + ex_res.value().output);
      require(ex_res.value().output.find("placeholder") != std::string::npos,
              ".env.example content readable");
    }
#endif
  }

  // 2. SANDBOXED: strict deny-default — workspace RW works, outside_dir READ fails,
  //    outbound TCP fails!
  {
    SandboxSpec sandboxed = base_spec;
    sandboxed.profile = SandboxProfile::sandboxed;

    {
      auto res = run_sandboxed_child_probe(
          sandboxed, {"/bin/sh", "-c",
                      "printf 'sandboxed-ok' > \"" + (ws / "sandboxed.txt").string() +
                          "\" && cat \"" + (ws / "sandboxed.txt").string() + "\""});
      require(res.has_value(), "sandboxed workspace rw probe executed");
      require(!res.value().sandbox_apply_failed, "sandboxed applied cleanly");
      require(res.value().exit_code == 0,
              "sandboxed allows workspace rw: " + res.value().output);
      require(res.value().output.find("sandboxed-ok") != std::string::npos,
              "sandboxed workspace output matches");
    }

    {
      auto res = run_sandboxed_child_probe(
          sandboxed, {"/bin/cat", (outside_dir / "outside.txt").string()});
      require(res.has_value(), "sandboxed outside read probe executed");
      require(!res.value().sandbox_apply_failed,
              "sandboxed applied for outside read check");
      require(res.value().exit_code != 0, "sandboxed MUST deny outside_dir read");
      require(res.value().output.find("outside-readonly-data") == std::string::npos,
              "outside_dir data must not leak under sandboxed");
    }

    {
      auto res = run_sandboxed_child_probe(
          sandboxed, {self_exe.string(), "--probe-net", port_str, "tcp"});
      require(res.has_value(), "sandboxed tcp probe executed");
      require(!res.value().sandbox_apply_failed, "sandboxed applied for tcp check");
      require(res.value().exit_code == 10,
              "sandboxed MUST deny outbound TCP with EPERM/EACCES, got exit=" +
                  std::to_string(res.value().exit_code) + " out=" + res.value().output);
    }
  }

  // 3. AIRGAP: TCP & UDP blocked at kernel boundary (EPERM/EACCES), while workspace RW
  //    continues to work!
  {
    SandboxSpec airgap = base_spec;
    airgap.profile = SandboxProfile::airgap;

    {
      auto res = run_sandboxed_child_probe(
          airgap, {"/bin/sh", "-c",
                   "printf 'airgap-ok' > \"" + (ws / "airgap.txt").string() +
                       "\" && cat \"" + (ws / "airgap.txt").string() + "\""});
      require(res.has_value(), "airgap workspace rw probe executed");
      require(!res.value().sandbox_apply_failed, "airgap applied cleanly");
      require(res.value().exit_code == 0,
              "airgap allows workspace rw: " + res.value().output);
      require(res.value().output.find("airgap-ok") != std::string::npos,
              "airgap workspace output matches");
    }

    {
      auto tcp_res = run_sandboxed_child_probe(
          airgap, {self_exe.string(), "--probe-net", port_str, "tcp"});
      require(tcp_res.has_value(), "airgap tcp probe executed");
      require(!tcp_res.value().sandbox_apply_failed, "airgap applied for tcp check");
      require(tcp_res.value().exit_code == 10,
              "airgap MUST block TCP with EPERM/EACCES, got exit=" +
                  std::to_string(tcp_res.value().exit_code) +
                  " out=" + tcp_res.value().output);
    }

    {
      auto udp_res = run_sandboxed_child_probe(
          airgap, {self_exe.string(), "--probe-net", port_str, "udp"});
      require(udp_res.has_value(), "airgap udp probe executed");
      require(!udp_res.value().sandbox_apply_failed, "airgap applied for udp check");
      require(udp_res.value().exit_code == 10,
              "airgap MUST block UDP with EPERM/EACCES, got exit=" +
                  std::to_string(udp_res.value().exit_code) +
                  " out=" + udp_res.value().output);
    }
  }

  // 4. NONE (black-flag): zero restrictions — child accesses secret, symlink,
  //    outside_dir write, and loopback TCP normally!
  {
    SandboxSpec black_flag = base_spec;
    black_flag.profile = SandboxProfile::none;

    {
      auto res = run_sandboxed_child_probe(
          black_flag, {"/bin/cat", (secret_dir / "secret.txt").string()});
      require(res.has_value(), "black-flag secret cat executed");
      require(!res.value().sandbox_apply_failed, "black-flag apply succeeds");
      require(res.value().exit_code == 0, "black-flag allows secret_dir read");
      require(res.value().output.find("TOP-SECRET-KEY-MATERIAL") != std::string::npos,
              "black-flag reads secret");
    }

    {
      auto res = run_sandboxed_child_probe(
          black_flag,
          {"/bin/sh", "-c",
           "printf 'bf-ok' > \"" + (outside_dir / "allowed.txt").string() + "\""});
      require(res.has_value(), "black-flag outside write executed");
      require(res.value().exit_code == 0, "black-flag allows outside write");
      require(read_text_file(outside_dir / "allowed.txt") == "bf-ok",
              "black-flag wrote outside_dir");
    }

    {
      auto res = run_sandboxed_child_probe(
          black_flag, {self_exe.string(), "--probe-net", port_str, "tcp"});
      require(res.has_value(), "black-flag tcp probe executed");
      require(res.value().exit_code == 0,
              "black-flag allows loopback TCP: " + res.value().output);
      require(res.value().output.find("tcp_connected") != std::string::npos,
              "black-flag tcp connected");
    }
  }

  // 5. FAIL-CLOSED: invalid workspace_root must fail closed (NEVER run unsandboxed).
  // 5. FAIL-CLOSED: invalid workspace_root and "/" workspace must fail closed
  //    (NEVER silently run unsandboxed).
  {
    SandboxSpec broken = base_spec;
    broken.profile = SandboxProfile::guarded;
    broken.workspace_root = fx.root / "does_not_exist";
    auto res = run_sandboxed_child_probe(
        broken, {"/bin/sh", "-c",
                 "printf 'escaped' > \"" +
                     (outside_dir / "failclosed_escape").string() + "\""});
    require(res.has_value(), "fail-closed probe returns structured result");
    require(res.value().sandbox_apply_failed,
            "broken spec MUST report sandbox_apply_failed");
    require(res.value().sandbox_error == SandboxError::canonicalize_failed,
            "broken workspace_root reports canonicalize_failed");
    require(!std::filesystem::exists(outside_dir / "failclosed_escape"),
            "child MUST NOT execute command when sandbox apply fails");
  }
  {
    SandboxSpec root_ws = base_spec;
    root_ws.profile = SandboxProfile::guarded;
    root_ws.workspace_root = "/";
    auto res = build_macos_seatbelt_profile(root_ws);
    require(!res.has_value(), "root '/' workspace must be rejected");
    require(sandbox_error_of(res.error()) == SandboxError::invalid_spec,
            "root '/' workspace returns invalid_spec");
  }
  {
    SandboxSpec root_tmp = base_spec;
    root_tmp.profile = SandboxProfile::guarded;
    root_tmp.tmp_dir = "/";
    auto res = build_macos_seatbelt_profile(root_tmp);
    require(!res.has_value(), "root '/' tmp_dir must be rejected");
    require(sandbox_error_of(res.error()) == SandboxError::invalid_spec,
            "root '/' tmp_dir returns invalid_spec");

    auto child_res = run_sandboxed_child_probe(
        root_tmp,
        {"/bin/sh", "-c",
         "printf 'escaped' > \"" + (outside_dir / "root_tmp_escape").string() + "\""});
    require(child_res.has_value(), "root tmp_dir child probe returns result");
    require(child_res.value().sandbox_apply_failed,
            "root '/' tmp_dir MUST fail closed in child");
    require(child_res.value().sandbox_error == SandboxError::invalid_spec,
            "root '/' tmp_dir child error detail is invalid_spec");
    require(!std::filesystem::exists(outside_dir / "root_tmp_escape"),
            "root '/' tmp_dir must never execute child");
  }
  {
    const auto symlink_to_root = fx.root / "symlink_to_root";
    std::filesystem::create_symlink("/", symlink_to_root);

    SandboxSpec root_extra = base_spec;
    root_extra.profile = SandboxProfile::sandboxed;
    root_extra.extra_read_paths.push_back("/");
    auto res = build_macos_seatbelt_profile(root_extra);
    require(!res.has_value(), "root '/' extra_read_paths must be rejected");
    require(sandbox_error_of(res.error()) == SandboxError::invalid_spec,
            "root '/' extra_read_paths returns invalid_spec");

    SandboxSpec symlink_root_extra = base_spec;
    symlink_root_extra.profile = SandboxProfile::sandboxed;
    symlink_root_extra.extra_read_paths.push_back(symlink_to_root);
    auto sym_res = build_macos_seatbelt_profile(symlink_root_extra);
    require(!sym_res.has_value(),
            "symlink-to-root in extra_read_paths must be rejected");
    require(sandbox_error_of(sym_res.error()) == SandboxError::invalid_spec,
            "symlink-to-root extra_read_paths returns invalid_spec");

    SandboxSpec root_home = base_spec;
    root_home.profile = SandboxProfile::guarded;
    root_home.home_dir = "/";
    auto home_res = build_macos_seatbelt_profile(root_home);
    require(!home_res.has_value(), "explicit root '/' home_dir must be rejected");
    require(sandbox_error_of(home_res.error()) == SandboxError::invalid_spec,
            "explicit root '/' home_dir returns invalid_spec");
  }

  // 6. Symlinked workspace_root canonicalizes via realpath() so child writes work.
  {
    const auto ws_alias = fx.root / "ws_symlink_alias";
    std::filesystem::create_symlink(ws, ws_alias);
    SandboxSpec aliased = base_spec;
    aliased.profile = SandboxProfile::guarded;
    aliased.workspace_root = ws_alias;
    auto res = run_sandboxed_child_probe(
        aliased,
        {"/bin/sh", "-c",
         "printf 'alias-ok' > \"" + (ws_alias / "alias_written.txt").string() + "\""});
    require(res.has_value(), "aliased workspace probe executed");
    require(!res.value().sandbox_apply_failed, "aliased workspace sandbox applied");
    require(res.value().exit_code == 0,
            "symlinked workspace_root canonicalizes and allows write: " +
                res.value().output);
    require(read_text_file(ws / "alias_written.txt") == "alias-ok",
            "aliased workspace write landed in canonical workspace");
  }
}

int count_open_fds() {
  int open_count = 0;
  for (int fd = 0; fd < 256; ++fd) {
    if (::fcntl(fd, F_GETFD) != -1) {
      ++open_count;
    }
  }
  return open_count;
}

} // namespace

int main(int argc, char **argv) {
  if (argc == 4 && std::string_view{argv[1]} == "--probe-net") {
    const unsigned long parsed = std::strtoul(argv[2], nullptr, 10);
    if (parsed == 0UL || parsed > 65535UL) {
      ::_exit(2);
    }
    const int rc = run_child_net_probe(static_cast<std::uint16_t>(parsed), argv[3]);
    std::cout.flush();
    std::cerr.flush();
    // Skip atexit LeakSanitizer ptrace() scan inside the seccomp-jailed child
    // (seccomp intentionally blocks ptrace); parent process still runs full LSan.
    ::_exit(rc);
  }
  try {
    const std::filesystem::path self_exe = std::filesystem::canonical(argv[0]);
    const int fds_before = count_open_fds();
    test_capabilities_and_profile_parsing();
    test_sbpl_escaping_and_generation();
    test_real_kernel_enforcement(self_exe);
    const int fds_after = count_open_fds();
    require(fds_after == fds_before,
            "zero FD leaks across sandbox tests (before=" + std::to_string(fds_before) +
                ", after=" + std::to_string(fds_after) + ")");
    std::cout << "os_sandbox_test: ALL PASSED (0 FD leaks)\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "os_sandbox_test FAILED: " << ex.what() << '\n';
    return 1;
  }
}
