#include "blackbird/archive_catalog.hpp"
#include "blackbird/coding.hpp"
#include "blackbird/command_jobs.hpp"
#include "blackbird/context.hpp"
#include "blackbird/json.hpp"
#include "blackbird/raw_reader.hpp"
#include "blackbird/raw_storage.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;
namespace {
void require(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
template <class T> T make_id(unsigned char n) {
  IdentityBytes bytes{};
  bytes[0] = std::byte{n};
  return unwrap(T::from_bytes(bytes));
}
template <class T> T read_field(ByteView bytes, std::size_t offset) {
  require(offset + sizeof(T) <= bytes.size(), "truncated raw field");
  T value{};
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return value;
}
struct TempDir {
  std::filesystem::path path;
  explicit TempDir(const char *prefix) {
    std::string pattern = std::string{"/tmp/"} + prefix + "-XXXXXX";
    char *created = ::mkdtemp(pattern.data());
    require(created != nullptr, "mkdtemp failed");
    path = created;
  }
  ~TempDir() {
    std::error_code error;
    std::filesystem::remove_all(path, error);
  }
};
struct RawSummary {
  std::uint64_t total_records = 0;
  std::uint64_t total_bytes = 0;
  std::uint64_t site_3007 = 0;
  std::uint64_t site_3008 = 0;
  std::uint64_t site_3009 = 0;
  std::uint64_t site_3206 = 0;
  std::uint64_t site_3208 = 0;
  std::uint64_t site_2002 = 0;
  std::uint64_t site_2046 = 0;
  std::uint64_t site_2022 = 0;
  std::size_t max_3008_bytes = 0;
  std::size_t max_3009_bytes = 0;
  std::set<IdentityBytes> command_launch_lanes;
  bool saw_64k_write = false;
  bool saw_64k_read = false;
};
RawSummary scan_raw(const std::filesystem::path &directory) {
  const auto runs = unwrap(discover_raw_runs(directory.string()));
  require(runs.size() == 1, "expected one raw run");
  auto reader = unwrap(RawRunReader::open((directory / "raw" / runs[0].name).string()));
  std::vector<std::byte> storage(2 * 1024 * 1024);
  RawSummary summary;
  while (const auto row = unwrap(reader->read(storage))) {
    ++summary.total_records;
    summary.total_bytes += row->raw.size();
    const auto site = read_field<std::uint32_t>(row->raw, 4);
    switch (site) {
    case 3007:
      ++summary.site_3007;
      break;
    case 3008: {
      ++summary.site_3008;
      summary.max_3008_bytes = std::max(summary.max_3008_bytes, row->raw.size());
      const auto returned = read_field<ssize_t>(row->raw, 40);
      if (returned == 65536)
        summary.saw_64k_read = true;
      break;
    }
    case 3009: {
      ++summary.site_3009;
      summary.max_3009_bytes = std::max(summary.max_3009_bytes, row->raw.size());
      const auto count = read_field<std::size_t>(row->raw, 69);
      if (count == 65536)
        summary.saw_64k_write = true;
      break;
    }
    case 3206:
      ++summary.site_3206;
      break;
    case 3208:
      ++summary.site_3208;
      break;
    case 2046:
      ++summary.site_2046;
      break;
    case 2022:
      ++summary.site_2022;
      break;
    case 2002:
      ++summary.site_2002;
      summary.command_launch_lanes.insert(row->origin.lane);
      break;
    default:
      break;
    }
  }
  return summary;
}

void test_raw_storage_metadata() {
  TempDir dir{"bb-amp-storage"};
  {
    auto runtime =
        unwrap(RawRuntime::open(dir.path.string(), make_id<EnvironmentId>(1)));
    auto lane = unwrap(runtime->prepare_thread());
    RawThreadBinding binding{lane};
    auto owner = unwrap(RawProductStorageOwner::prepare());
    auto directory = unwrap(NativeJournalDirectory::open(dir.path.string(), owner));
    auto file = unwrap(directory.create_exclusive("payload"));
    std::vector<std::byte> payload(65536, std::byte{0x5a});
    std::size_t written = 0;
    while (written < payload.size())
      written += unwrap(file->write_at(written, ByteView{payload}.subspan(written)));
    std::vector<std::byte> back(65536);
    std::size_t done = 0;
    while (done < back.size())
      done += unwrap(file->read_at(done, MutableByteView{back}.subspan(done)));
    require(back == payload, "file round-trip bytes match");
  }
  const auto summary = scan_raw(dir.path);
  require(summary.saw_64k_write && summary.saw_64k_read,
          "metadata records preserve exact 65536 write/read counts");
  require(summary.max_3008_bytes <= 96 && summary.max_3009_bytes <= 96,
          "RED: 3008/3009 copied literal 64 KiB file payload into raw/events");
  require(summary.total_bytes < 16384,
          "RED: raw storage overhead for one 64 KiB write+read exceeded 16 KiB");
}

void test_archive_catalog_merge() {
  TempDir dir{"bb-amp-catalog"};
  const JournalHeader h{make_id<EnvironmentId>(2),
                        make_id<AuditStreamId>(3),
                        1,
                        {1024 * 1024, 4 * 1024 * 1024},
                        std::nullopt};
  const JournalCursor cursor{h.journal, 2001, 1000000};
  std::vector<ArchiveEntry> entries;
  entries.reserve(1600);
  for (std::uint64_t i = 0; i < 1600; ++i) {
    RecoveryKey key{};
    key[0] = std::byte{6};
    key[38] = static_cast<std::byte>(i >> 8);
    key[39] = static_cast<std::byte>(i & 255);
    entries.push_back({key,
                       {h.environment, h.journal, FrameKind::semantic, i + 1, 1,
                        144 + i * 48, 16, 17}});
  }
  {
    auto directory = unwrap(NativeJournalDirectory::open(dir.path.string()));
    unwrap(ArchiveCatalog::publish(directory, "catalog", h, cursor, entries));
  }
  std::vector<ArchiveEntry> delta;
  // Insert a key strictly before entries[0], replace 16 existing keys, and
  // insert a key strictly after entries.back() to cover all two-pointer paths.
  {
    RecoveryKey before_key{};
    before_key[0] = std::byte{5};
    delta.push_back(
        {before_key,
         {h.environment, h.journal, FrameKind::semantic, 1900, 1, 90000, 16, 555}});
  }
  for (std::uint64_t i = 0; i < 16; ++i) {
    auto fresh = entries[i * 100];
    fresh.record.frame_checksum = 777 + static_cast<std::uint32_t>(i);
    delta.push_back(fresh);
  }
  {
    RecoveryKey after_key{};
    after_key[0] = std::byte{7};
    delta.push_back(
        {after_key,
         {h.environment, h.journal, FrameKind::semantic, 1901, 1, 90048, 16, 888}});
  }
  {
    auto runtime =
        unwrap(RawRuntime::open(dir.path.string(), make_id<EnvironmentId>(2)));
    auto lane = unwrap(runtime->prepare_thread());
    RawThreadBinding binding{lane};
    auto owner = unwrap(RawProductStorageOwner::prepare());
    auto directory = unwrap(NativeJournalDirectory::open(dir.path.string(), owner));
    auto catalog = unwrap(ArchiveCatalog::open(directory, "catalog", h, cursor, 4000));
    const auto merged_count = unwrap(ArchiveCatalog::publish_merge(
        directory, "merged", h, cursor, catalog.get(), delta));
    require(merged_count == 1602, "exact merged entry count");
    auto merged = unwrap(ArchiveCatalog::open(directory, "merged", h, cursor, 4000));
    require(unwrap(merged->find(delta.front().key)) == delta.front().record,
            "merged prepended key exact");
    require(unwrap(merged->find(delta[6].key)) == delta[6].record,
            "merged replacement key exact");
    require(unwrap(merged->find(delta.back().key)) == delta.back().record,
            "merged appended key exact");
    require(unwrap(merged->find(entries[1599].key)) == entries[1599].record,
            "merged retained key exact");
  }
  const auto summary = scan_raw(dir.path);
  require(summary.site_3007 <= 64,
          "RED: publish_merge performed per-entry 96-byte pread storm");
  require(summary.site_3206 <= 32 && summary.site_3208 == 0,
          "RED: publish_merge emitted per-entry 3206/3208 storm");
  require(summary.total_bytes < 65536, "RED: publish_merge raw bytes exceeded 64 KiB");
}

void test_command_idle_spin() {
  TempDir dir{"bb-amp-spin"};
  {
    auto runtime =
        unwrap(RawRuntime::open(dir.path.string(), make_id<EnvironmentId>(3)));
    auto lane = unwrap(runtime->prepare_thread());
    RawThreadBinding binding{lane};
    CommandJobs jobs;
    const std::string sleep_id(32, 'a');
    jobs.start(
        sleep_id,
        Value::object({{"argv", Value{Value::Array{Value{"/bin/sleep"}, Value{"1.2"}}}},
                       {"timeout_seconds", Value{Number{10}}}}));
    const auto pump = [&] {
      for (const auto &event : jobs.drain())
        if (event.bytes)
          jobs.retained(event.job_id, event.offset + event.bytes->size());
        else
          jobs.settled(event.job_id, event.result);
    };
    (void)jobs.wait(sleep_id, {10000, 4096, false}, pump, [] { return false; });

    // Stop latency check: stopping a quiet 10s sleep wakes promptly (<250ms).
    const std::string stop_id(32, 'b');
    jobs.start(
        stop_id,
        Value::object({{"argv", Value{Value::Array{Value{"/bin/sleep"}, Value{"10"}}}},
                       {"timeout_seconds", Value{Number{15}}}}));
    std::this_thread::sleep_for(std::chrono::milliseconds{300});
    const auto start_stop = std::chrono::steady_clock::now();
    jobs.stop_all();
    (void)jobs.wait(stop_id, {5000, 4096, false}, pump, [] { return false; });
    const auto stop_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - start_stop)
                             .count();
    require(stop_ms < 250, "stop wakeup stayed prompt under idle poll backoff");

    // Deadline-timeout check: a child ignoring SIGTERM must not spin poll(..., 0)
    // during the 200ms SIGTERM->SIGKILL grace window after deadline expiry.
    const std::string timeout_id(32, 'd');
    jobs.start(
        timeout_id,
        Value::object({{"argv", Value{Value::Array{Value{"/bin/sh"}, Value{"-c"},
                                                   Value{"trap '' TERM; sleep 5"}}}},
                       {"timeout_seconds", Value{Number{1}}}}));
    (void)jobs.wait(timeout_id, {5000, 4096, false}, pump, [] { return false; });
    jobs.shutdown();
    pump();
  }
  const auto summary = scan_raw(dir.path);
  require(summary.site_2046 <= 80,
          "RED: CommandJobs spun on poll timeout during quiet sleep or deadline stop");
}

void test_command_lane_reuse() {
  TempDir dir{"bb-amp-lanes"};
  {
    auto runtime =
        unwrap(RawRuntime::open(dir.path.string(), make_id<EnvironmentId>(4)));
    auto lane = unwrap(runtime->prepare_thread());
    RawThreadBinding binding{lane};
    CommandJobs jobs;
    const auto pump = [&] {
      for (const auto &event : jobs.drain())
        if (event.bytes)
          jobs.retained(event.job_id, event.offset + event.bytes->size());
        else
          jobs.settled(event.job_id, event.result);
    };
    for (unsigned i = 0; i < 12; ++i) {
      std::string id(30, 'c');
      const char hex[] = "0123456789abcdef";
      id.push_back(hex[(i >> 4) & 15]);
      id.push_back(hex[i & 15]);
      jobs.start(
          id, Value::object({{"argv", Value{Value::Array{Value{"/bin/sh"}, Value{"-c"},
                                                         Value{"exit 0"}}}},
                             {"timeout_seconds", Value{Number{10}}}}));
      (void)jobs.wait(id, {5000, 4096, false}, pump, [] { return false; });
      pump();
    }
    jobs.shutdown();
    pump();
  }
  const auto summary = scan_raw(dir.path);
  require(summary.site_2002 == 12, "all 12 sequential jobs recorded launch events");
  require(!summary.command_launch_lanes.empty() &&
              summary.command_launch_lanes.size() <= 2,
          "RED: sequential CommandJobs allocated a fresh raw lane per command");
}

class SeventyStepProvider final : public CodingProvider {
public:
  unsigned calls = 0;
  Value respond(const Value &,
                const std::function<void(std::string_view)> &capture) override {
    ++calls;
    Value response;
    if (calls <= 70) {
      response = Value::object(
          {{"output", Value{Value::Array{Value::object(
                          {{"type", Value{"function_call"}},
                           {"name", Value{"context_stats"}},
                           {"call_id", Value{"step-" + std::to_string(calls)}},
                           {"arguments", Value::object({})}})}}}});
    } else {
      response = Value::object(
          {{"output",
            Value{Value::Array{Value::object(
                {{"type", Value{"message"}},
                 {"role", Value{"assistant"}},
                 {"content", Value{Value::Array{Value::object(
                                 {{"type", Value{"output_text"}},
                                  {"text", Value{"Completed 70 steps"}}})}}}})}}}});
    }
    capture(unwrap(dump_json(response)));
    return response;
  }
};

void test_unbounded_turn_steps() {
  TempDir dir{"bb-amp-steps"};
  const JournalHeader header{make_id<EnvironmentId>(5),
                             make_id<AuditStreamId>(6),
                             1,
                             {8 * 1024 * 1024, 24 * 1024 * 1024},
                             std::nullopt};
  auto root = unwrap(
      RetainedState::create(std::make_unique<NativeJournalDirectory>(unwrap(
                                NativeJournalDirectory::open(dir.path.string()))),
                            "audit", header, {128 * 1024 * 1024, 10000}));
  AuditLog log{*root};
  ContextStore context{log};
  SeventyStepProvider provider;
  CodingEngine engine{log, context, provider, "test-model"};
  const auto workflow = std::string{BLACKBIRD_SOURCE_DIR} + "/programs/turn.lua";
  const auto source = read_file(workflow);
  engine.turn({.prompt = "Run 70 steps", .program = source});
  require(provider.calls == 71,
          "RED: turn.lua aborted before completing 70 tool rounds");
}
} // namespace

int main(int argc, char **argv) {
  const std::string_view selected = argc >= 2 ? std::string_view{argv[1]} : "all";
  const std::pair<std::string_view, void (*)()> cases[]{
      {"raw_storage_metadata", test_raw_storage_metadata},
      {"archive_catalog_merge", test_archive_catalog_merge},
      {"command_idle_spin", test_command_idle_spin},
      {"command_lane_reuse", test_command_lane_reuse},
      {"unbounded_turn_steps", test_unbounded_turn_steps},
  };
  bool failed = false;
  for (const auto &[name, fn] : cases) {
    if (selected != "all" && selected != name)
      continue;
    try {
      fn();
      std::cout << "PASS " << name << '\n';
    } catch (const std::exception &e) {
      std::cerr << "FAIL " << name << ": " << e.what() << '\n';
      failed = true;
    } catch (const Error &e) {
      std::cerr << "FAIL " << name << ": " << error_name(e.code) << " (" << e.detail
                << ")\n";
      failed = true;
    }
  }
  return failed ? 1 : 0;
}
