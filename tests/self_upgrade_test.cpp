#include "blackbird/self_upgrade.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <openssl/evp.h>
#include <set>
#include <source_location>
#include <spawn.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void require(bool condition, const char *message,
             std::source_location loc = std::source_location::current()) {
  if (!condition) {
    std::ostringstream oss;
    oss << g_stage << " (" << loc.file_name() << ":" << loc.line() << "): " << message;
    throw std::runtime_error(oss.str());
  }
}

template <typename T>
T must(Result<T> res, const char *context,
       std::source_location loc = std::source_location::current()) {
  if (!res.has_value()) {
    std::ostringstream oss;
    oss << g_stage << " [" << context << "] (" << loc.file_name() << ":" << loc.line()
        << "): " << error_name(res.error().code) << " (detail=" << res.error().detail
        << ")";
    throw std::runtime_error(oss.str());
  }
  return std::move(res).value();
}

struct TempDir {
  std::filesystem::path path;

  explicit TempDir(const char *prefix) {
    const char *base = std::getenv("TMPDIR");
    const std::filesystem::path root = (base != nullptr && base[0] != '\0')
                                           ? std::filesystem::path{base}
                                           : std::filesystem::path{"/tmp"};
    std::string tmpl = (root / (std::string{prefix} + "-XXXXXX")).string();
    char *created = ::mkdtemp(tmpl.data());
    require(created != nullptr, "mkdtemp failed");
    path = std::filesystem::path{created};
  }
  TempDir(const TempDir &) = delete;
  TempDir &operator=(const TempDir &) = delete;
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

void write_text_file(const std::filesystem::path &path, std::string_view content,
                     mode_t mode = 0644) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  require(!ec, "create_directories failed");
  std::ofstream ofs{path, std::ios::binary | std::ios::trunc};
  require(ofs.good(), "failed to open file for write");
  ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
  ofs.close();
  require(ofs.good(), "failed to write file");
  require(::chmod(path.c_str(), mode) == 0, "chmod failed");
}

std::string sha256_file_hex(const std::filesystem::path &path) {
  std::ifstream ifs{path, std::ios::binary};
  require(ifs.good(), "open file for sha256 failed");
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  require(ctx != nullptr, "EVP_MD_CTX_new failed");
  require(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1,
          "EVP_DigestInit_ex failed");
  std::array<char, 8192> buf{};
  while (ifs.good()) {
    ifs.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    const auto n = ifs.gcount();
    if (n > 0) {
      require(EVP_DigestUpdate(ctx, buf.data(), static_cast<std::size_t>(n)) == 1,
              "EVP_DigestUpdate failed");
    }
  }
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
  unsigned int len = 0;
  require(EVP_DigestFinal_ex(ctx, digest.data(), &len) == 1 && len == 32U,
          "EVP_DigestFinal_ex failed");
  EVP_MD_CTX_free(ctx);

  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64U);
  for (std::size_t i = 0; i < 32U; ++i) {
    out.push_back(kHex[(digest[i] >> 4U) & 0x0FU]);
    out.push_back(kHex[digest[i] & 0x0FU]);
  }
  return out;
}

struct TarCreateSpec {
  std::filesystem::path cwd;
  std::filesystem::path archive_out;
  std::vector<std::string> members;
};

void run_tar_create(const TarCreateSpec &spec) {
  std::vector<std::string> args_storage = {
      "/usr/bin/tar", "-czf", spec.archive_out.string(), "-C", spec.cwd.string(),
  };
  for (const auto &m : spec.members) {
    args_storage.push_back(m);
  }
  std::vector<char *> argv;
  argv.reserve(args_storage.size() + 1U);
  for (auto &a : args_storage) {
    argv.push_back(a.data());
  }
  argv.push_back(nullptr);

  std::vector<std::string> env_storage = {"PATH=/usr/bin:/bin", "LC_ALL=C",
                                          "COPYFILE_DISABLE=1"};
  std::vector<char *> envp;
  envp.reserve(env_storage.size() + 1U);
  for (auto &e : env_storage) {
    envp.push_back(e.data());
  }
  envp.push_back(nullptr);

  pid_t pid = -1;
  const int rc =
      ::posix_spawn(&pid, "/usr/bin/tar", nullptr, nullptr, argv.data(), envp.data());
  require(rc == 0 && pid > 0, "posix_spawn tar create failed");
  int status = 0;
  require(::waitpid(pid, &status, 0) == pid, "waitpid tar create failed");
  require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "tar create exited non-zero");
}

struct FixtureOptions {
  std::string version = "v0.2.0";
  std::string commit = "newcommit123";
  std::string mock_script = "#!/bin/sh\n"
                            "if [ \"${1:-}\" = \"--version\" ]; then\n"
                            "  printf 'blackbird newcommit123 (test)\\n'\n"
                            "  exit 0\n"
                            "fi\n"
                            "exit 0\n";
  bool include_symlink = false;
  bool include_safe_lib_symlink = false;
  bool include_unsafe_lib_symlink = false;
  bool tamper_sums = false;
  bool tamper_tarball_after_hash = false;
};

struct FixtureRelease {
  std::filesystem::path mirror_dir;
  std::string base_url;
  std::string tarball_name;
  std::string sha256;
  std::uint64_t size_bytes = 0;
};

FixtureRelease build_fixture_release(const std::filesystem::path &root,
                                     const std::string &target,
                                     const FixtureOptions &opts) {
  const std::filesystem::path stage_root = root / "stage";
  const std::filesystem::path mirror_dir = root / "mirror";
  std::error_code ec;
  std::filesystem::create_directories(stage_root, ec);
  std::filesystem::create_directories(mirror_dir, ec);
  require(!ec, "create fixture dirs failed");

  const std::string stem = "blackbird-" + opts.version + "-" + target;
  const std::filesystem::path payload_dir = stage_root / stem;
  write_text_file(payload_dir / "bin" / "blackbird", opts.mock_script, 0755);
  write_text_file(payload_dir / "MANIFEST",
                  "tag=" + opts.version + "\ncommit=" + opts.commit + "\n", 0644);
  if (opts.include_symlink) {
    const std::filesystem::path evil_link = payload_dir / "bin" / "evil-link";
    require(::symlink("/etc/passwd", evil_link.c_str()) == 0,
            "create fixture symlink failed");
  }
  if (opts.include_safe_lib_symlink) {
    write_text_file(payload_dir / "lib" / "libfoo.so.1.0", "ELF_MOCK_LIB", 0755);
    const std::filesystem::path soname_link = payload_dir / "lib" / "libfoo.so.1";
    require(::symlink("libfoo.so.1.0", soname_link.c_str()) == 0,
            "create safe lib symlink failed");
  }
  if (opts.include_unsafe_lib_symlink) {
    std::filesystem::create_directories(payload_dir / "lib", ec);
    require(!ec, "create lib dir failed");
    const std::filesystem::path bad_lib_link = payload_dir / "lib" / "evil";
    require(::symlink("../bin/blackbird", bad_lib_link.c_str()) == 0,
            "create unsafe lib symlink failed");
  }

  const std::string tarball_name = stem + ".tar.gz";
  const std::filesystem::path tarball_path = mirror_dir / tarball_name;
  run_tar_create(TarCreateSpec{stage_root, tarball_path, {stem}});

  const std::string sha = sha256_file_hex(tarball_path);
  const std::uint64_t size_bytes = std::filesystem::file_size(tarball_path, ec);
  require(!ec && size_bytes > 0U, "fixture tarball size failed");

  std::ostringstream manifest;
  manifest << "{\n"
           << "  \"version\": \"" << opts.version << "\",\n"
           << "  \"commit\": \"" << opts.commit << "\",\n"
           << "  \"assets\": [\n"
           << "    {\n"
           << "      \"target\": \"" << target << "\",\n"
           << "      \"filename\": \"" << tarball_name << "\",\n"
           << "      \"sha256\": \"" << sha << "\",\n"
           << "      \"size_bytes\": " << size_bytes << "\n"
           << "    }\n"
           << "  ]\n"
           << "}\n";
  write_text_file(mirror_dir / "release-manifest.json", manifest.str(), 0644);

  std::string sums_sha = sha;
  if (opts.tamper_sums) {
    sums_sha[0] = (sums_sha[0] == 'a') ? 'b' : 'a';
  }
  write_text_file(mirror_dir / "SHA256SUMS.txt", sums_sha + "  " + tarball_name + "\n",
                  0644);

  if (opts.tamper_tarball_after_hash) {
    // Flip a byte inside the tarball while preserving exact file size.
    std::fstream fs{tarball_path, std::ios::in | std::ios::out | std::ios::binary};
    require(fs.good(), "open tarball to tamper failed");
    fs.seekg(-1, std::ios::end);
    char last = 0;
    fs.read(&last, 1);
    last = static_cast<char>(last ^ 0xFF);
    fs.seekp(-1, std::ios::end);
    fs.write(&last, 1);
    fs.close();
    require(fs.good(), "tamper write failed");
  }

  FixtureRelease out;
  out.mirror_dir = mirror_dir;
  out.base_url = "file://" + mirror_dir.string();
  out.tarball_name = tarball_name;
  out.sha256 = sha;
  out.size_bytes = size_bytes;
  return out;
}

void build_traversal_tarball_fixture(const std::filesystem::path &root,
                                     const std::string &target) {
  const std::filesystem::path mirror_dir = root / "mirror";
  std::error_code ec;
  std::filesystem::create_directories(mirror_dir, ec);
  require(!ec, "create traversal mirror dir failed");

  const std::string version = "v0.9.9";
  const std::string stem = "blackbird-" + version + "-" + target;
  const std::string tarball_name = stem + ".tar.gz";
  const std::filesystem::path tarball_path = mirror_dir / tarball_name;

  // Use python3 tarfile to craft a deterministic tarball containing a "../escape"
  // entry.
  const std::filesystem::path script = root / "make_traversal.py";
  std::ostringstream py;
  py << "import io, tarfile\n"
     << "with tarfile.open(" << "\"" << tarball_path.string() << "\", 'w:gz') as tf:\n"
     << "    info = tarfile.TarInfo(name='../escape.txt')\n"
     << "    data = b'pwned'\n"
     << "    info.size = len(data)\n"
     << "    tf.addfile(info, io.BytesIO(data))\n";
  write_text_file(script, py.str(), 0644);

  std::vector<std::string> args_storage = {"/usr/bin/python3", script.string()};
  std::vector<char *> argv = {args_storage[0].data(), args_storage[1].data(), nullptr};
  std::vector<std::string> env_storage = {"PATH=/usr/bin:/bin", "LC_ALL=C"};
  std::vector<char *> envp = {env_storage[0].data(), env_storage[1].data(), nullptr};

  pid_t pid = -1;
  const int rc = ::posix_spawn(&pid, "/usr/bin/python3", nullptr, nullptr, argv.data(),
                               envp.data());
  require(rc == 0 && pid > 0, "spawn python3 for traversal fixture failed");
  int status = 0;
  require(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
              WEXITSTATUS(status) == 0,
          "python3 traversal fixture script failed");

  const std::string sha = sha256_file_hex(tarball_path);
  const std::uint64_t size_bytes = std::filesystem::file_size(tarball_path, ec);
  require(!ec && size_bytes > 0U, "traversal tarball size failed");

  std::ostringstream manifest;
  manifest << "{\n"
           << "  \"version\": \"" << version << "\",\n"
           << "  \"commit\": \"badcommit\",\n"
           << "  \"assets\": [\n"
           << "    {\n"
           << "      \"target\": \"" << target << "\",\n"
           << "      \"filename\": \"" << tarball_name << "\",\n"
           << "      \"sha256\": \"" << sha << "\",\n"
           << "      \"size_bytes\": " << size_bytes << "\n"
           << "    }\n"
           << "  ]\n"
           << "}\n";
  write_text_file(mirror_dir / "release-manifest.json", manifest.str(), 0644);
  write_text_file(mirror_dir / "SHA256SUMS.txt", sha + "  " + tarball_name + "\n",
                  0644);
}

std::string read_link_str(const std::filesystem::path &path) {
  std::array<char, 4096> buf{};
  const ssize_t n = ::readlink(path.c_str(), buf.data(), buf.size() - 1U);
  require(n > 0, "readlink failed");
  return std::string{buf.data(), static_cast<std::size_t>(n)};
}

void test_happy_path_and_idempotency(const std::string &target) {
  g_stage = "test_happy_path_and_idempotency";
  TempDir tmp{"bb-upgrade-happy"};
  const auto fixture = build_fixture_release(tmp.path, target, FixtureOptions{});
  const std::filesystem::path prefix = tmp.path / "prefix";

  UpgradeConfig cfg;
  cfg.version = "latest";
  cfg.base_url = fixture.base_url;
  cfg.prefix = prefix;
  cfg.no_ask = true;
  cfg.current_version_string = "blackbird oldcommit000 (test)";

  std::set<UpgradeStage> stages_seen;
  std::vector<std::string> rendered_lines;
  const auto res =
      must(perform_upgrade(cfg,
                           [&](const UpgradeProgress &p) {
                             stages_seen.insert(p.stage);
                             rendered_lines.push_back(format_upgrade_progress_line(p));
                           }),
           "happy perform_upgrade");

  require(res.upgraded, "expected upgraded == true");
  require(!res.already_up_to_date, "expected already_up_to_date == false");
  require(!res.cancelled_by_user, "expected cancelled_by_user == false");
  require(res.check.latest_version == "v0.2.0", "latest_version mismatch");
  require(res.check.latest_commit == "newcommit123", "latest_commit mismatch");
  require(res.check.expected_sha256 == fixture.sha256, "expected_sha256 mismatch");
  require(res.installed_version_output == "blackbird newcommit123 (test)",
          "smoke version output mismatch");
  require(std::filesystem::is_symlink(prefix / "lib" / "blackbird" / "current"),
          "current symlink missing");
  require(std::filesystem::is_symlink(prefix / "bin" / "blackbird"),
          "bin/blackbird symlink missing");
  require(read_link_str(prefix / "bin" / "blackbird") ==
              "../lib/blackbird/current/bin/blackbird",
          "bin/blackbird target mismatch");
  require(std::filesystem::is_regular_file(prefix / "bin" / "blackbird"),
          "bin/blackbird target not resolvable regular file");

  // Verify all 6 execution stages + complete were emitted.
  require(stages_seen.contains(UpgradeStage::checking), "missing checking stage");
  require(stages_seen.contains(UpgradeStage::downloading), "missing downloading stage");
  require(stages_seen.contains(UpgradeStage::verifying), "missing verifying stage");
  require(stages_seen.contains(UpgradeStage::extracting), "missing extracting stage");
  require(stages_seen.contains(UpgradeStage::smoke_testing),
          "missing smoke_testing stage");
  require(stages_seen.contains(UpgradeStage::installing), "missing installing stage");
  require(stages_seen.contains(UpgradeStage::complete), "missing complete stage");
  require(!rendered_lines.empty(), "expected formatted progress lines");
  bool saw_bar = false;
  for (const auto &line : rendered_lines) {
    if (line.find("[2/6]") != std::string::npos &&
        line.find('%') != std::string::npos) {
      saw_bar = true;
    }
  }
  require(saw_bar, "expected downloading progress bar line");

  // Re-running must detect installed release-manifest.json and report
  // already_up_to_date.
  const auto res2 = must(perform_upgrade(cfg), "second perform_upgrade");
  require(!res2.upgraded, "second run must not upgrade");
  require(res2.already_up_to_date, "second run must report already_up_to_date");
  require(res2.check.current_version == "v0.2.0", "current_version not detected");
  require(res2.check.current_commit == "newcommit123", "current_commit not detected");
}

void test_permission_gate_deny_and_approve(const std::string &target) {
  g_stage = "test_permission_gate_deny_and_approve";
  TempDir tmp{"bb-upgrade-prompt"};
  const auto fixture = build_fixture_release(tmp.path, target, FixtureOptions{});
  const std::filesystem::path prefix = tmp.path / "prefix";

  UpgradeConfig cfg;
  cfg.version = "latest";
  cfg.base_url = fixture.base_url;
  cfg.prefix = prefix;
  cfg.no_ask = false;

  bool saw_prompt_stage = false;
  bool saw_download_stage = false;
  std::string summary_text;
  const auto denied = must(perform_upgrade(
                               cfg,
                               [&](const UpgradeProgress &p) {
                                 if (p.stage == UpgradeStage::prompt) {
                                   saw_prompt_stage = true;
                                 }
                                 if (p.stage == UpgradeStage::downloading) {
                                   saw_download_stage = true;
                                 }
                               },
                               [&](const UpgradeCheckResult &chk) {
                                 summary_text =
                                     format_upgrade_prompt_summary(chk, prefix);
                                 return false;
                               }),
                           "denied perform_upgrade");

  require(denied.cancelled_by_user, "expected cancelled_by_user == true");
  require(!denied.upgraded, "denied upgrade must not set upgraded");
  require(saw_prompt_stage, "expected prompt stage emitted");
  require(!saw_download_stage, "denied upgrade must NOT download");
  require(!std::filesystem::exists(prefix), "denied upgrade must NOT touch prefix");
  require(summary_text.find("v0.2.0") != std::string::npos,
          "prompt summary missing version");
  require(summary_text.find(fixture.sha256) != std::string::npos,
          "prompt summary missing sha256");

  // Now approve via confirm callback -> must succeed!
  bool confirm_called = false;
  const auto approved = must(perform_upgrade(cfg, {},
                                             [&](const UpgradeCheckResult &chk) {
                                               confirm_called = true;
                                               return chk.latest_version == "v0.2.0";
                                             }),
                             "approved perform_upgrade");

  require(confirm_called, "confirm callback was not invoked");
  require(approved.upgraded, "approved upgrade must succeed");
  require(!approved.cancelled_by_user, "approved upgrade must not be cancelled");
  require(std::filesystem::is_symlink(prefix / "bin" / "blackbird"),
          "approved upgrade missing bin/blackbird");
}

void test_tampered_tarball_sha256(const std::string &target) {
  g_stage = "test_tampered_tarball_sha256";
  TempDir tmp{"bb-upgrade-tamper"};
  const std::filesystem::path prefix = tmp.path / "prefix";

  // Install a known-good v0.1.0 first.
  FixtureOptions v1;
  v1.version = "v0.1.0";
  v1.commit = "goodv1";
  v1.mock_script = "#!/bin/sh\nprintf 'blackbird goodv1 (test)\\n'\n";
  const auto good_fix = build_fixture_release(tmp.path / "v1", target, v1);

  UpgradeConfig cfg1;
  cfg1.base_url = good_fix.base_url;
  cfg1.prefix = prefix;
  cfg1.no_ask = true;
  const auto installed_v1 = must(perform_upgrade(cfg1), "install v1");
  const std::string orig_current_target =
      read_link_str(prefix / "lib" / "blackbird" / "current");

  // Attempt upgrade to tampered v0.2.0.
  FixtureOptions bad;
  bad.version = "v0.2.0";
  bad.commit = "badv2";
  bad.tamper_tarball_after_hash = true;
  const auto bad_fix = build_fixture_release(tmp.path / "v2", target, bad);

  UpgradeConfig cfg2;
  cfg2.base_url = bad_fix.base_url;
  cfg2.prefix = prefix;
  cfg2.no_ask = true;
  const auto res = perform_upgrade(cfg2);
  require(!res.has_value(), "tampered tarball must fail");
  require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
  require(read_link_str(prefix / "lib" / "blackbird" / "current") ==
              orig_current_target,
          "existing current symlink was modified on tampered tarball");
  require(std::filesystem::exists(installed_v1.generation_dir),
          "previous generation dir was disturbed");
}

void test_mismatched_sums_vs_manifest(const std::string &target) {
  g_stage = "test_mismatched_sums_vs_manifest";
  TempDir tmp{"bb-upgrade-mismatch"};
  FixtureOptions opts;
  opts.tamper_sums = true;
  const auto fix = build_fixture_release(tmp.path, target, opts);
  const std::filesystem::path prefix = tmp.path / "prefix";

  UpgradeConfig cfg;
  cfg.base_url = fix.base_url;
  cfg.prefix = prefix;
  cfg.no_ask = true;

  bool downloaded = false;
  const auto res = perform_upgrade(cfg, [&](const UpgradeProgress &p) {
    if (p.stage == UpgradeStage::downloading) {
      downloaded = true;
    }
  });
  require(!res.has_value(), "mismatched SHA256SUMS vs manifest must fail");
  require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
  require(!downloaded, "must fail BEFORE downloading tarball");
}

void test_malicious_tarballs_rejected_before_extraction(const std::string &target) {
  g_stage = "test_malicious_tarballs_rejected_before_extraction";

  // Case A: Symlink inside tarball.
  {
    TempDir tmp{"bb-upgrade-symlink"};
    FixtureOptions opts;
    opts.include_symlink = true;
    const auto fix = build_fixture_release(tmp.path, target, opts);
    const std::filesystem::path prefix = tmp.path / "prefix";

    UpgradeConfig cfg;
    cfg.base_url = fix.base_url;
    cfg.prefix = prefix;
    cfg.no_ask = true;

    bool smoke_ran = false;
    const auto res = perform_upgrade(cfg, [&](const UpgradeProgress &p) {
      if (p.stage == UpgradeStage::smoke_testing) {
        smoke_ran = true;
      }
    });
    require(!res.has_value(), "symlink tarball must be rejected");
    require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
    require(!smoke_ran, "symlink tarball must be rejected before smoke test");
    require(!std::filesystem::exists(prefix / "lib" / "blackbird" / "current"),
            "current symlink must not exist after symlink rejection");
  }

  // Case B: "../escape.txt" path traversal entry.
  {
    TempDir tmp{"bb-upgrade-traversal"};
    build_traversal_tarball_fixture(tmp.path, target);
    const std::filesystem::path prefix = tmp.path / "prefix";

    UpgradeConfig cfg;
    cfg.base_url = "file://" + (tmp.path / "mirror").string();
    cfg.prefix = prefix;
    cfg.no_ask = true;

    const auto res = perform_upgrade(cfg);
    require(!res.has_value(), "traversal tarball must be rejected");
    require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
    require(!std::filesystem::exists(tmp.path / "escape.txt"),
            "traversal entry must not be extracted");
  }
  // Case C: Unsafe relative symlink inside lib/ pointing outside lib/
  // (../bin/blackbird).
  {
    TempDir tmp{"bb-upgrade-bad-lib-symlink"};
    FixtureOptions opts;
    opts.include_unsafe_lib_symlink = true;
    const auto fix = build_fixture_release(tmp.path, target, opts);
    const std::filesystem::path prefix = tmp.path / "prefix";

    UpgradeConfig cfg;
    cfg.base_url = fix.base_url;
    cfg.prefix = prefix;
    cfg.no_ask = true;

    const auto res = perform_upgrade(cfg);
    require(!res.has_value(), "unsafe lib/ symlink must be rejected");
    require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
  }

  // Case D: Safe intra-directory SONAME symlink inside <stem>/lib/ (Linux release
  // parity).
  {
    TempDir tmp{"bb-upgrade-safe-lib-symlink"};
    FixtureOptions opts;
    opts.include_safe_lib_symlink = true;
    const auto fix = build_fixture_release(tmp.path, target, opts);
    const std::filesystem::path prefix = tmp.path / "prefix";

    UpgradeConfig cfg;
    cfg.base_url = fix.base_url;
    cfg.prefix = prefix;
    cfg.no_ask = true;

    const auto res = must(perform_upgrade(cfg), "safe lib SONAME symlink upgrade");
    require(res.upgraded, "safe lib SONAME symlink upgrade should succeed");
    const std::filesystem::path installed_link =
        res.generation_dir / "lib" / "libfoo.so.1";
    require(std::filesystem::is_symlink(installed_link),
            "safe lib SONAME symlink must be preserved in generation");
    require(read_link_str(installed_link) == "libfoo.so.1.0",
            "safe lib SONAME symlink target mismatch");
  }

  // Case E: Tarball containing CR ('\r') inside member filename must be rejected.
  {
    TempDir tmp{"bb-upgrade-cr-tar"};
    const std::filesystem::path mirror_dir = tmp.path / "mirror";
    std::error_code ec;
    std::filesystem::create_directories(mirror_dir, ec);
    require(!ec, "create cr mirror dir failed");
    const std::string version = "v0.9.8";
    const std::string stem = "blackbird-" + version + "-" + target;
    const std::string tarball_name = stem + ".tar.gz";
    const std::filesystem::path tarball_path = mirror_dir / tarball_name;

    const std::filesystem::path script = tmp.path / "make_cr.py";
    std::ostringstream py;
    py << "import io, tarfile\n"
       << "with tarfile.open(\"" << tarball_path.string() << "\", 'w:gz') as tf:\n"
       << "    info = tarfile.TarInfo(name='" << stem << "/bad\\r')\n"
       << "    data = b'x'\n"
       << "    info.size = len(data)\n"
       << "    tf.addfile(info, io.BytesIO(data))\n";
    write_text_file(script, py.str(), 0644);

    std::vector<std::string> args_storage = {"/usr/bin/python3", script.string()};
    std::vector<char *> argv = {args_storage[0].data(), args_storage[1].data(),
                                nullptr};
    std::vector<std::string> env_storage = {"PATH=/usr/bin:/bin", "LC_ALL=C"};
    std::vector<char *> envp = {env_storage[0].data(), env_storage[1].data(), nullptr};
    pid_t pid = -1;
    require(::posix_spawn(&pid, "/usr/bin/python3", nullptr, nullptr, argv.data(),
                          envp.data()) == 0 &&
                pid > 0,
            "spawn python3 for CR fixture failed");
    int status = 0;
    require(::waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
                WEXITSTATUS(status) == 0,
            "python3 CR fixture failed");

    const std::string sha = sha256_file_hex(tarball_path);
    const std::uint64_t size_bytes = std::filesystem::file_size(tarball_path, ec);
    require(!ec && size_bytes > 0U, "CR tarball size failed");
    std::ostringstream manifest;
    manifest << "{\n  \"version\": \"" << version
             << "\",\n  \"commit\": \"crbad\",\n  \"assets\": [{\n"
             << "    \"target\": \"" << target << "\",\n"
             << "    \"filename\": \"" << tarball_name << "\",\n"
             << "    \"sha256\": \"" << sha << "\",\n"
             << "    \"size_bytes\": " << size_bytes << "\n  }]\n}\n";
    write_text_file(mirror_dir / "release-manifest.json", manifest.str(), 0644);
    write_text_file(mirror_dir / "SHA256SUMS.txt", sha + "  " + tarball_name + "\n",
                    0644);

    UpgradeConfig cfg;
    cfg.base_url = "file://" + mirror_dir.string();
    cfg.prefix = tmp.path / "prefix";
    cfg.no_ask = true;
    const auto res = perform_upgrade(cfg);
    require(!res.has_value(), "CR filename tarball must be rejected");
    require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
  }
}

void test_banner_commit_already_up_to_date(const std::string &target) {
  g_stage = "test_banner_commit_already_up_to_date";
  TempDir tmp{"bb-upgrade-banner"};
  const auto fixture = build_fixture_release(tmp.path, target, FixtureOptions{});
  const std::filesystem::path prefix = tmp.path / "empty-prefix";

  UpgradeConfig cfg;
  cfg.base_url = fixture.base_url;
  cfg.prefix = prefix;
  cfg.no_ask = true;
  // Matches fixture commit "newcommit123" with no installed manifest on disk.
  cfg.current_version_string = "blackbird newcommit123 (lua 5.5.1, Release)";

  bool downloaded = false;
  const auto res = must(perform_upgrade(cfg,
                                        [&](const UpgradeProgress &p) {
                                          if (p.stage == UpgradeStage::downloading) {
                                            downloaded = true;
                                          }
                                        }),
                        "banner commit matching latest");
  require(!res.upgraded, "matching banner commit must not upgrade");
  require(res.already_up_to_date,
          "matching banner commit must report already_up_to_date");
  require(!downloaded, "matching banner commit must not download tarball");
  require(res.check.current_commit == "newcommit123", "current_commit mismatch");
}

void test_unsafe_urls_and_versions() {
  g_stage = "test_unsafe_urls_and_versions";

  // Version validation.
  require(must(valid_upgrade_version("latest"), "latest"), "latest should be valid");
  require(must(valid_upgrade_version("v1.2.3"), "v1.2.3"), "v1.2.3 should be valid");
  require(must(valid_upgrade_version("v0.1.0-rc.1_arm"), "rc"),
          "v0.1.0-rc.1_arm should be valid");
  require(!must(valid_upgrade_version("../evil"), "dotdot"), "../evil must be invalid");
  require(!must(valid_upgrade_version("v1;rm"), "semi"), "v1;rm must be invalid");
  require(!must(valid_upgrade_version("v1..2"), "v1..2"), "v1..2 must be invalid");
  require(!must(valid_upgrade_version("v1/2"), "slash"), "v1/2 must be invalid");
  require(!must(valid_upgrade_version("1.2.3"), "no-v"), "1.2.3 must be invalid");
  require(!must(valid_upgrade_version(""), "empty"), "empty must be invalid");

  // Unsafe URL schemes, whitespace/newlines, query/fragment/userinfo, empty host.
  const std::vector<std::string> bad_urls = {
      "http://example.com/releases",
      "ftp://example.com/releases",
      "https://example.com/with space",
      "https://example.com/with\nnewline",
      "https://example.com/with\ttab",
      "https://user@example.com/releases",
      "https://example.com/releases?foo=bar",
      "https://example.com/releases#frag",
      "https:///leading-slash",
      "https://example.com/a/../b",
      "file:///tmp/../etc",
      "file://relative/path",
      "https://",
  };
  for (const auto &bad_url : bad_urls) {
    UpgradeConfig cfg;
    cfg.base_url = bad_url;
    const auto resolved = resolve_upgrade_base_url(cfg);
    require(!resolved.has_value(), "unsafe URL must be rejected");
  }

  // Unsafe version through resolve_upgrade_base_url.
  {
    UpgradeConfig cfg;
    cfg.version = "v1;rm";
    require(!resolve_upgrade_base_url(cfg).has_value(),
            "unsafe version must fail resolve_upgrade_base_url");
  }

  // Sanitization check & large-uint64 overflow safety on format_upgrade_progress_line.
  UpgradeProgress prog;
  prog.stage = UpgradeStage::checking;
  prog.step_index = 1;
  prog.step_total = 6;
  prog.message = "hi\x1b[31mred\x1b[0m\nworld";
  const std::string line = format_upgrade_progress_line(prog);
  require(line.find('\x1b') == std::string::npos,
          "ESC not stripped from progress line");
  require(line.find('\n') == std::string::npos,
          "newline not stripped from progress line");

  UpgradeProgress big_prog;
  big_prog.stage = UpgradeStage::downloading;
  big_prog.step_index = 2;
  big_prog.step_total = 6;
  big_prog.bytes_total = std::numeric_limits<std::uint64_t>::max();
  big_prog.bytes_done = big_prog.bytes_total / 2ULL;
  big_prog.message = "big";
  const std::string big_line = format_upgrade_progress_line(big_prog);
  require(big_line.find("50%") != std::string::npos,
          "uint64_t progress percentage overflowed");
}

void test_smoke_check_failure_preserves_existing(const std::string &target) {
  g_stage = "test_smoke_check_failure_preserves_existing";
  TempDir tmp{"bb-upgrade-smoke-fail"};
  const std::filesystem::path prefix = tmp.path / "prefix";

  // Install working v0.1.0 first.
  FixtureOptions v1;
  v1.version = "v0.1.0";
  v1.commit = "goodv1";
  v1.mock_script = "#!/bin/sh\nprintf 'blackbird goodv1 (test)\\n'\n";
  const auto fix1 = build_fixture_release(tmp.path / "v1", target, v1);

  UpgradeConfig cfg1;
  cfg1.base_url = fix1.base_url;
  cfg1.prefix = prefix;
  cfg1.no_ask = true;
  (void)must(perform_upgrade(cfg1), "install v1 before smoke fail");
  const std::string orig_current =
      read_link_str(prefix / "lib" / "blackbird" / "current");

  // Upgrade to v0.2.0 whose mock binary exits 1 on --version.
  FixtureOptions v2;
  v2.version = "v0.2.0";
  v2.commit = "brokenv2";
  v2.mock_script = "#!/bin/sh\necho 'broken binary' >&2\nexit 1\n";
  const auto fix2 = build_fixture_release(tmp.path / "v2", target, v2);

  UpgradeConfig cfg2;
  cfg2.base_url = fix2.base_url;
  cfg2.prefix = prefix;
  cfg2.no_ask = true;
  const auto res = perform_upgrade(cfg2);
  require(!res.has_value(), "broken binary smoke check must fail");
  require(res.error().code == ErrorCode::corrupt, "expected ErrorCode::corrupt");
  require(read_link_str(prefix / "lib" / "blackbird" / "current") == orig_current,
          "current symlink changed despite smoke failure");

  // Verify failed generation directory was cleaned up (only 1 generation remains).
  std::size_t gen_count = 0;
  for (const auto &entry :
       std::filesystem::directory_iterator(prefix / "lib" / "blackbird" / "releases")) {
    if (entry.is_directory()) {
      ++gen_count;
    }
  }
  require(gen_count == 1U, "failed generation directory was not cleaned up");
}

} // namespace

int main() {
  try {
    const auto target = must(detect_upgrade_target(), "detect_upgrade_target");
    require(target.triplet == "darwin-arm64" || target.triplet == "linux-x86_64",
            "unexpected host target triplet");

    test_happy_path_and_idempotency(target.triplet);
    test_permission_gate_deny_and_approve(target.triplet);
    test_tampered_tarball_sha256(target.triplet);
    test_mismatched_sums_vs_manifest(target.triplet);
    test_malicious_tarballs_rejected_before_extraction(target.triplet);
    test_banner_commit_already_up_to_date(target.triplet);
    test_unsafe_urls_and_versions();
    test_smoke_check_failure_preserves_existing(target.triplet);

    std::cout << "self_upgrade_test: all checks passed (" << target.triplet << ")\n";
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "FAIL: " << ex.what() << "\n";
    return 1;
  }
}
