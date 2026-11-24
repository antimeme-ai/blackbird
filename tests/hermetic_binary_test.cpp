#include "blackbird/embedded_resources.hpp"
#include "blackbird/provider_profile.hpp"
#include "blackbird/saas_packs.hpp"
#include "blackbird/sprite.hpp"
#include "blackbird/tui_lua.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <source_location>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern char **environ;

namespace {

using namespace blackbird;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;

[[noreturn]] void fail(std::string_view message,
                       std::source_location loc = std::source_location::current()) {
  std::ostringstream out;
  out << loc.file_name() << ':' << loc.line() << ": " << message;
  throw std::runtime_error(out.str());
}

void require(bool condition, std::string_view message,
             std::source_location loc = std::source_location::current()) {
  if (!condition)
    fail(message, loc);
}

struct TempDir {
  fs::path path;
  TempDir() {
    std::string pattern = (fs::temp_directory_path() / "bb-hermetic-XXXXXX").string();
    if (!::mkdtemp(pattern.data()))
      fail("mkdtemp failed");
    path = fs::canonical(pattern);
    fs::permissions(path, fs::perms::owner_all, fs::perm_options::replace);
  }
  ~TempDir() {
    if (std::uncaught_exceptions() != 0) {
      std::cerr << "Preserved hermetic test workspace: " << path << '\n';
      return;
    }
    std::error_code ec;
    fs::remove_all(path, ec);
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
};

struct CommandSpec {
  fs::path executable;
  fs::path cwd;
  fs::path home;
  std::vector<std::string> args;
  std::vector<std::string> extra_env;
};

struct CommandResult {
  int exit_code = -1;
  std::string output;
};

std::vector<std::string> clean_env(const fs::path &home,
                                   const std::vector<std::string> &extra) {
  std::vector<std::string> env;
  for (char **entry = environ; *entry != nullptr; ++entry) {
    const std::string_view text{*entry};
    if (text.starts_with("BLACKBIRD_") || text.starts_with("ARCO_") ||
        text.starts_with("HOME=") || text.starts_with("XDG_"))
      continue;
    env.emplace_back(text);
  }
  env.push_back("HOME=" + home.string());
  env.push_back("XDG_CONFIG_HOME=" + (home / "config").string());
  env.push_back("XDG_DATA_HOME=" + (home / "data").string());
  env.push_back("XDG_STATE_HOME=" + (home / "state").string());
  env.insert(env.end(), extra.begin(), extra.end());
  return env;
}

CommandResult run_isolated(const CommandSpec &spec) {
  int pipe_fd[2]{-1, -1};
  require(::pipe(pipe_fd) == 0, "pipe failed");
  for (const int fd : pipe_fd)
    require(::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "cloexec failed");

  std::vector<std::string> argv_storage;
  argv_storage.push_back(spec.executable.string());
  argv_storage.insert(argv_storage.end(), spec.args.begin(), spec.args.end());
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (auto &s : argv_storage)
    argv.push_back(s.data());
  argv.push_back(nullptr);

  auto env_storage = clean_env(spec.home, spec.extra_env);
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (auto &s : env_storage)
    envp.push_back(s.data());
  envp.push_back(nullptr);

  const pid_t pid = ::fork();
  require(pid >= 0, "fork failed");
  if (pid == 0) {
    if (::chdir(spec.cwd.c_str()) != 0)
      _exit(125);
    const int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
      (void)::dup2(devnull, STDIN_FILENO);
      if (devnull > 2)
        (void)::close(devnull);
    }
    (void)::dup2(pipe_fd[1], STDOUT_FILENO);
    (void)::dup2(pipe_fd[1], STDERR_FILENO);
    ::execve(spec.executable.c_str(), argv.data(), envp.data());
    _exit(126);
  }
  (void)::close(pipe_fd[1]);

  std::string output;
  std::array<char, 4096> buf{};
  const auto deadline = Clock::now() + std::chrono::seconds{30};
  for (;;) {
    const auto remaining =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
    if (remaining.count() <= 0) {
      (void)::kill(pid, SIGKILL);
      int status = 0;
      (void)::waitpid(pid, &status, 0);
      (void)::close(pipe_fd[0]);
      fail("child timed out: " + output);
    }
    pollfd pfd{pipe_fd[0], POLLIN, 0};
    const int ready =
        ::poll(&pfd, 1, static_cast<int>(std::min<long long>(remaining.count(), 200)));
    if (ready > 0) {
      const ssize_t n = ::read(pipe_fd[0], buf.data(), buf.size());
      if (n > 0) {
        output.append(buf.data(), static_cast<std::size_t>(n));
        continue;
      }
      if (n == 0)
        break;
      if (errno == EINTR)
        continue;
      break;
    }
  }
  (void)::close(pipe_fd[0]);

  int status = 0;
  while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  const int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  return {code, std::move(output)};
}

std::string run_tui_graphics_pty(const CommandSpec &spec) {
  const int master = ::posix_openpt(O_RDWR | O_NOCTTY);
  require(master >= 0 && ::grantpt(master) == 0 && ::unlockpt(master) == 0,
          "posix_openpt failed");
  const char *slave_name = ::ptsname(master);
  require(slave_name != nullptr, "ptsname failed");
  const int slave = ::open(slave_name, O_RDWR | O_NOCTTY);
  require(slave >= 0, "open pty slave failed");

  winsize ws{};
  ws.ws_row = 30;
  ws.ws_col = 100;
  require(::ioctl(slave, TIOCSWINSZ, &ws) == 0, "TIOCSWINSZ failed");

  std::vector<std::string> argv_storage;
  argv_storage.push_back(spec.executable.string());
  argv_storage.insert(argv_storage.end(), spec.args.begin(), spec.args.end());
  std::vector<char *> argv;
  argv.reserve(argv_storage.size() + 1U);
  for (auto &s : argv_storage)
    argv.push_back(s.data());
  argv.push_back(nullptr);

  auto env_storage = clean_env(spec.home, spec.extra_env);
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (auto &s : env_storage)
    envp.push_back(s.data());
  envp.push_back(nullptr);

  const pid_t pid = ::fork();
  require(pid >= 0, "fork pty failed");
  if (pid == 0) {
    (void)::close(master);
    if (::setsid() < 0)
      _exit(124);
    (void)::ioctl(slave, TIOCSCTTY, 0);
    (void)::dup2(slave, STDIN_FILENO);
    (void)::dup2(slave, STDOUT_FILENO);
    (void)::dup2(slave, STDERR_FILENO);
    if (slave > 2)
      (void)::close(slave);
    if (::chdir(spec.cwd.c_str()) != 0)
      _exit(125);
    ::execve(spec.executable.c_str(), argv.data(), envp.data());
    _exit(126);
  }
  (void)::close(slave);

  std::string captured;
  std::array<char, 65536> buf{};
  bool sent_quit = false;
  const auto deadline = Clock::now() + std::chrono::seconds{20};
  int status = 0;
  bool exited = false;
  while (Clock::now() < deadline) {
    pollfd pfd{master, POLLIN, 0};
    const int ready = ::poll(&pfd, 1, 50);
    if (ready > 0) {
      const ssize_t n = ::read(master, buf.data(), buf.size());
      if (n > 0) {
        captured.append(buf.data(), static_cast<std::size_t>(n));
        if (!sent_quit && captured.find("Workflow reloads") != std::string::npos) {
          constexpr std::string_view quit_cmd = "/quit\r";
          (void)::write(master, quit_cmd.data(), quit_cmd.size());
          sent_quit = true;
        }
      } else if (n == 0 || (n < 0 && errno == EIO)) {
        break;
      }
    }
    if (::waitpid(pid, &status, WNOHANG) == pid) {
      exited = true;
      break;
    }
  }
  if (!exited) {
    if (!sent_quit) {
      constexpr std::string_view quit_cmd = "/quit\r";
      (void)::write(master, quit_cmd.data(), quit_cmd.size());
    }
    const auto grace = Clock::now() + std::chrono::seconds{5};
    while (Clock::now() < grace) {
      pollfd pfd{master, POLLIN, 0};
      if (::poll(&pfd, 1, 50) > 0) {
        const ssize_t n = ::read(master, buf.data(), buf.size());
        if (n > 0)
          captured.append(buf.data(), static_cast<std::size_t>(n));
      }
      if (::waitpid(pid, &status, WNOHANG) == pid) {
        exited = true;
        break;
      }
    }
  }
  if (!exited) {
    (void)::kill(pid, SIGKILL);
    (void)::waitpid(pid, &status, 0);
  }
  (void)::close(master);
  require(exited && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "hermetic TUI PTY exit failed");
  return captured;
}

void test_embedded_in_process() {
  // 1. Embedded provider profiles validate and match expected count.
  const auto profiles = embedded_provider_profiles();
  require(profiles.size() == 11U, "must embed all 11 shipped provider profiles");
  const auto loaded_profiles = load_embedded_profile_set();
  require(loaded_profiles.has_value(), "load_embedded_profile_set must succeed");
  require(loaded_profiles->shipped.size() == 10U,
          "embedded profile set must have 1 conservative + 10 shipped profiles");

  // 2. Embedded turn.lua & results.lua compile cleanly.
  require(!embedded_turn_workflow().empty(), "embedded turn.lua must be non-empty");
  require(!embedded_results_instrument().empty(),
          "embedded results.lua must be non-empty");
  const auto inst =
      tui::lua::Script::create(std::string{embedded_results_instrument()});
  require(inst.has_value(), "embedded results.lua must compile cleanly in Lua 5.5.1");

  // 3. Embedded 7 SaaS packs load without any directory on disk.
  require(embedded_saas_packs().size() == 7U, "must embed all 7 SaaS packs");
  SaasPackHost host{SaasHostConfig{}};
  const auto loaded_packs = host.load_builtin_packs(fs::path{});
  require(loaded_packs.has_value() && loaded_packs.value().size() == 7U,
          "SaasPackHost::load_builtin_packs({}) must load all 7 embedded packs");
  for (const char *svc :
       {"linear", "slack", "gmail", "gcal", "notion", "github", "discord"}) {
    require(host.find_pack_id(svc).has_value(),
            std::string{"missing embedded SaaS pack: "} + svc);
  }

  // 4. Embedded SR-71 PNG carries valid PNG magic signature and encodes cleanly
  //    into Kitty Graphics chunked inline t=d base64 4096-byte frames.
  const auto png = embedded_sr71_png();
  require(png.size() > 10000U, "embedded SR-71 PNG must be non-empty");
  constexpr std::array<unsigned char, 8> kPngMagic{0x89, 0x50, 0x4e, 0x47,
                                                   0x0d, 0x0a, 0x1a, 0x0a};
  for (std::size_t i = 0; i < kPngMagic.size(); ++i) {
    require(std::to_integer<unsigned char>(png[i]) == kPngMagic[i],
            "embedded SR-71 PNG header mismatch");
  }
  const std::string kitty_inline = blackbird_graphics_load_inline();
  require(kitty_inline.starts_with("\x1b_Ga=t,f=100,t=d,i=72171,q=2,m=1;"),
          "inline Kitty payload must start with chunked t=d header");
  require(kitty_inline.find("\x1b_Gm=0;") != std::string::npos,
          "inline Kitty payload must terminate with m=0 chunk");
  // Parse every APC chunk and verify 4096-byte chunking + exact base64 length.
  std::size_t pos = 0U;
  std::size_t chunk_count = 0U;
  std::size_t total_b64 = 0U;
  bool saw_final = false;
  while (pos < kitty_inline.size()) {
    const std::size_t semi = kitty_inline.find(';', pos);
    const std::size_t st = kitty_inline.find("\x1b\\", semi);
    require(semi != std::string::npos && st != std::string::npos,
            "malformed Kitty APC frame");
    const std::string_view header =
        std::string_view{kitty_inline}.substr(pos, semi - pos);
    const std::size_t payload_len = st - (semi + 1U);
    if (header.ends_with("m=0")) {
      require(payload_len <= 4096U && payload_len > 0U,
              "final Kitty chunk size out of range");
      saw_final = true;
    } else {
      require(header.ends_with("m=1"), "non-final Kitty chunk must set m=1");
      require(payload_len == 4096U, "non-final Kitty chunk must be 4096 bytes");
    }
    total_b64 += payload_len;
    ++chunk_count;
    pos = st + 2U;
  }
  require(saw_final && chunk_count > 100U, "expected multi-chunk Kitty transmission");
  require(total_b64 == ((png.size() + 2U) / 3U) * 4U,
          "chunked base64 payload size must match embedded SR-71 PNG exactly");
}

void test_standalone_binary(const fs::path &blackbird_bin) {
  TempDir tmp;
  const fs::path standalone_dir = tmp.path / "isolated_bin";
  const fs::path empty_cwd = tmp.path / "empty_cwd";
  const fs::path home = tmp.path / "home";
  fs::create_directories(standalone_dir);
  fs::create_directories(empty_cwd);
  fs::create_directories(home);
  fs::permissions(home, fs::perms::owner_all, fs::perm_options::replace);

  // Copy ONLY the blackbird executable, renamed to bb_standalone.
  const fs::path standalone = standalone_dir / "bb_standalone";
  fs::copy_file(blackbird_bin, standalone, fs::copy_options::overwrite_existing);
  fs::permissions(standalone, fs::perms::owner_all, fs::perm_options::replace);

  // 1. Embedded provider profiles load from empty dir with exact digests.
  const auto embedded_set = load_embedded_profile_set();
  require(embedded_set.has_value(), "oracle embedded profile set");
  {
    const auto res =
        run_isolated({standalone, empty_cwd, home, {"--profile-digests"}, {}});
    require(res.exit_code == 0, "--profile-digests failed: " + res.output);
    require(res.output.find("set-shipped builtin:profiles/providers") !=
                std::string::npos,
            "expected builtin:profiles/providers in --profile-digests: " + res.output);
    require(res.output.find("set-digest " + embedded_set->digest) != std::string::npos,
            "set-digest mismatch: " + res.output);
    require(res.output.find("set-content-digest " + embedded_set->content_digest) !=
                std::string::npos,
            "set-content-digest mismatch: " + res.output);
  }

  // 2. Default workflow resolves to portable `builtin:turn.lua` and persists on reopen.
  const fs::path session1 = tmp.path / "session1";
  {
    const auto res =
        run_isolated({standalone,
                      empty_cwd,
                      home,
                      {"--plain", "--session", session1.string(), "--once", "/session"},
                      {}});
    require(res.exit_code == 0, "fresh hermetic session failed: " + res.output);
    require(res.output.find("\"workflow\":\"builtin:turn.lua\"") != std::string::npos,
            "fresh session must use builtin:turn.lua: " + res.output);
  }
  {
    const auto res =
        run_isolated({standalone,
                      empty_cwd,
                      home,
                      {"--plain", "--session", session1.string(), "--once", "/session"},
                      {}});
    require(res.exit_code == 0, "reopened hermetic session failed: " + res.output);
    require(res.output.find("\"workflow\":\"builtin:turn.lua\"") != std::string::npos,
            "reopened session must preserve builtin:turn.lua: " + res.output);
  }

  // 3. Multicall `--internal-job-runner` dispatch works directly AND via real PTY exec!
  {
    const auto res =
        run_isolated({standalone, empty_cwd, home, {"--internal-job-runner"}, {}});
    require(res.exit_code == 127,
            "--internal-job-runner with missing args must exit 127, got " +
                std::to_string(res.exit_code));
  }
  {
    const fs::path pty_session = tmp.path / "session_pty";
    const auto res = run_isolated(
        {standalone,
         empty_cwd,
         home,
         {"--plain", "--session", pty_session.string(), "--once",
          R"(/lua local r = blackbird.call('exec', {argv={'/bin/sh','-c','printf HERMETIC_PTY_VERIFIED'}, pty=true, timeout_seconds=10}); assert(r.exit_code == 0, 'pty exit_code'); assert(string.find(r.output or '', 'HERMETIC_PTY_VERIFIED', 1, true), 'pty output missing'); print('STANDALONE_PTY_OK'))"},
         {}});
    require(res.exit_code == 0, "hermetic PTY exec failed: " + res.output);
    require(res.output.find("STANDALONE_PTY_OK") != std::string::npos,
            "hermetic PTY exec missing verification marker: " + res.output);
  }

  // 4. Multicall `--internal-archive` dispatch works with ZERO sibling
  // blackbird-archive.
  {
    const fs::path arch_sess = tmp.path / "archive_session";
    const fs::path arch_dest = tmp.path / "archive_dest";
    const auto cfg_res = run_isolated(
        {standalone,
         empty_cwd,
         home,
         {"--internal-archive", "configure", arch_sess.string(), arch_dest.string()},
         {}});
    require(cfg_res.exit_code == 0,
            "--internal-archive configure failed: " + cfg_res.output);
    require(fs::is_regular_file(arch_sess / "trace-archive.bbm"),
            "--internal-archive configure did not write trace-archive.bbm");
  }

  // 5. Real TUI startup from empty dir loads embedded results.lua cleanly.
  {
    const fs::path tui_session = tmp.path / "session_tui";
    const std::string pty_out =
        run_tui_graphics_pty({standalone,
                              empty_cwd,
                              home,
                              {"--session", tui_session.string()},
                              {"BLACKBIRD_GRAPHICS=off", "TERM=xterm-256color"}});
    require(pty_out.find("Instrument source unavailable") == std::string::npos,
            "TUI must load embedded results.lua without error");
    require(pty_out.find("Workflow reloads") != std::string::npos,
            "TUI must render startup screen cleanly from empty dir");
  }
}

} // namespace

int main(int argc, char **argv) {
  try {
    fs::path binary;
    if (argc > 1) {
      binary = argv[1];
    } else {
#ifdef BLACKBIRD_BINARY_PATH
      binary = BLACKBIRD_BINARY_PATH;
#else
      fail("usage: hermetic_binary_test <path-to-blackbird>");
#endif
    }
    require(fs::is_regular_file(binary),
            "blackbird binary not found: " + binary.string());
    test_embedded_in_process();
    test_standalone_binary(binary);
    std::cout << "PASS hermetic_binary_test\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "FAIL hermetic_binary_test: " << e.what() << '\n';
    return 1;
  }
}
