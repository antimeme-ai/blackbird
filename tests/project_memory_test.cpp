#include "blackbird/json.hpp"
#include "blackbird/project_memory.hpp"

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace blackbird;

namespace {

const char *g_stage = "startup";

void check(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}

template <class T> T must(Result<T> result, const char *context) {
  if (!result.has_value()) {
    throw std::runtime_error(std::string{context} + ": " +
                             error_name(result.error().code) + " (" +
                             std::to_string(result.error().detail) + ")");
  }
  return std::move(result).value();
}

void write_file_bytes(const std::filesystem::path &path, std::string_view content) {
  std::filesystem::create_directories(path.parent_path());
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  check(out.good(), "failed to open temp file for writing");
  out.write(content.data(), static_cast<std::streamsize>(content.size()));
  out.flush();
  check(out.good(), "failed to write temp file");
}

void test_sha256_and_validators(const std::filesystem::path &base) {
  g_stage = "sha256_and_validators";
  // Standard FIPS 180-4 test vectors.
  check(memory_sha256_hex("") ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256 empty vector mismatch");
  check(memory_sha256_hex("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256 abc vector mismatch");
  check(memory_sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha256 448-bit vector mismatch");

  // Enum roundtrips.
  for (const auto kind :
       {MemoryKind::decision, MemoryKind::invariant, MemoryKind::handoff,
        MemoryKind::finding, MemoryKind::friction, MemoryKind::preference}) {
    const auto name = memory_kind_name(kind);
    check(!name.empty(), "kind name empty");
    check(must(parse_memory_kind(name), "parse kind") == kind,
          "kind roundtrip mismatch");
  }
  check(!parse_memory_kind("unknown").has_value(), "unknown kind accepted");

  for (const auto freshness :
       {MemoryFreshness::unchecked, MemoryFreshness::unpinned, MemoryFreshness::fresh,
        MemoryFreshness::stale, MemoryFreshness::missing_source}) {
    const auto name = memory_freshness_name(freshness);
    check(!name.empty(), "freshness name empty");
    check(must(parse_memory_freshness(name), "parse freshness") == freshness,
          "freshness roundtrip mismatch");
  }
  check(!parse_memory_freshness("bogus").has_value(), "unknown freshness accepted");

  // ID and actor validators.
  check(valid_memory_id("mem-1") && valid_memory_id("mem-4294967296"),
        "valid memory ids rejected");
  check(!valid_memory_id("mem-0") && !valid_memory_id("mem-01") &&
            !valid_memory_id("mem-") && !valid_memory_id("mem--1") &&
            !valid_memory_id("x-1") && !valid_memory_id(""),
        "invalid memory ids accepted");
  check(valid_memory_actor("memory") && valid_memory_actor("agent_1-a"),
        "valid actors rejected");
  check(!valid_memory_actor("") && !valid_memory_actor("-lead") &&
            !valid_memory_actor("Upper") && !valid_memory_actor("a/b") &&
            !valid_memory_actor(std::string(kMemoryMaxActorLength + 1, 'a')),
        "invalid actors accepted");
  check(default_project_memory_dir(base) == base / ".blackbird" / "memory",
        "default_project_memory_dir mismatch");
}

void test_directory_security(const std::filesystem::path &base) {
  g_stage = "directory_security";
  const auto store_dir = base / "nested" / "mem-store";
  auto store = must(ProjectMemoryStore::open(store_dir), "open nested memory store");
  check(store.root() == store_dir, "store root mismatch");

  struct stat st{};
  check(::lstat(store_dir.c_str(), &st) == 0, "lstat store dir failed");
  check(S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700,
        "store directory is not 0700");

  // Reject symlink as store root.
  const auto link_dir = base / "symlink-store";
  check(::symlink(store_dir.c_str(), link_dir.c_str()) == 0, "symlink failed");
  check(!ProjectMemoryStore::open(link_dir).has_value(), "symlink root accepted");

  // Reject permissive existing directory.
  const auto world_dir = base / "permissive-store";
  check(::mkdir(world_dir.c_str(), mode_t{0755}) == 0, "mkdir 0755 failed");
  check(::chmod(world_dir.c_str(), mode_t{0755}) == 0, "chmod 0755 failed");
  const auto perm_res = ProjectMemoryStore::open(world_dir);
  check(!perm_res.has_value() && perm_res.error().code == ErrorCode::io,
        "0755 store dir accepted");

  // Reject empty or '..' store root.
  check(!ProjectMemoryStore::open(std::filesystem::path{}).has_value(),
        "empty store root accepted");
  check(!ProjectMemoryStore::open(base / ".." / "escape").has_value(),
        "'..' store root accepted");

  // Move semantics transfer ownership cleanly.
  ProjectMemoryStore moved = std::move(store);
  check(must(moved.recent(), "recent on moved").empty(), "empty recent not empty");
}

void test_record_recall_ranking_and_supersedes(const std::filesystem::path &base) {
  g_stage = "record_recall_ranking_and_supersedes";
  auto store = must(ProjectMemoryStore::open(base / "ranking"), "open ranking store");

  // Record entries with carefully distinct title (3x), tag (2x), body (1x) hits.
  MemoryRecordRequest body_req{};
  body_req.kind = MemoryKind::finding;
  body_req.title = "General notes about storage";
  body_req.body = "We observed flock serialization prevents torn appends.";
  body_req.tags = {"storage"};
  body_req.actor = "worker-a";
  body_req.session_id = "sess-100";
  const auto m1 = must(store.record(std::move(body_req)), "record m1 (body hit)");
  check(m1.id == "mem-1" && m1.created_ns > 0 && !m1.superseded_by.has_value(),
        "m1 metadata mismatch");

  MemoryRecordRequest tag_req{};
  tag_req.kind = MemoryKind::invariant;
  tag_req.title = "Append durability guarantee";
  tag_req.body = "Every record ends with newline and fsync.";
  tag_req.tags = {"flock", "durability"};
  tag_req.actor = "worker-b";
  const auto m2 = must(store.record(std::move(tag_req)), "record m2 (tag hit)");
  check(m2.id == "mem-2", "m2 id mismatch");

  MemoryRecordRequest title_req{};
  title_req.kind = MemoryKind::decision;
  title_req.title = "Adopt flock lockfile for concurrency";
  title_req.body = "Lock file coordinates multi-process writes.";
  title_req.tags = {"concurrency"};
  title_req.actor = "architect";
  const auto m3 = must(store.record(std::move(title_req)), "record m3 (title hit)");
  check(m3.id == "mem-3", "m3 id mismatch");

  // Exact tie-breaker test: newer entry with identical score ranks first.
  MemoryRecordRequest tie_req{};
  tie_req.kind = MemoryKind::decision;
  tie_req.title = "Flock lock ordering";
  tie_req.body = "Always acquire lock before replay.";
  tie_req.tags = {"concurrency"};
  tie_req.actor = "architect";
  const auto m4 = must(store.record(std::move(tie_req)), "record m4 (title tie)");
  check(m4.id == "mem-4", "m4 id mismatch");

  // Recall for "flock": m4 (3, newest) > m3 (3) > m2 (2) > m1 (1).
  MemoryRecallQuery q{};
  q.query = "flock";
  const auto hits = must(store.recall(q), "recall flock");
  check(hits.size() == 4, "expected 4 flock hits");
  check(hits[0].entry.id == "mem-4" && hits[0].score == 3, "rank 0 mismatch");
  check(hits[1].entry.id == "mem-3" && hits[1].score == 3, "rank 1 mismatch");
  check(hits[2].entry.id == "mem-2" && hits[2].score == 2, "rank 2 mismatch");
  check(hits[3].entry.id == "mem-1" && hits[3].score == 1, "rank 3 mismatch");
  check(hits[0].freshness == MemoryFreshness::unpinned,
        "unpinned entry freshness mismatch");

  // Filter by kind and tag.
  MemoryRecallQuery filtered{};
  filtered.query = "flock";
  filtered.kind = MemoryKind::invariant;
  filtered.tag = "DURABILITY";
  const auto inv_hits = must(store.recall(filtered), "recall filtered");
  check(inv_hits.size() == 1 && inv_hits[0].entry.id == "mem-2",
        "kind/tag filter mismatch");

  // Supersede m3 with m5.
  MemoryRecordRequest sup_req{};
  sup_req.kind = MemoryKind::decision;
  sup_req.title = "Adopt flock lockfile with crash sentinel";
  sup_req.body = "Supersedes earlier decision by adding trailing-fragment sentinel.";
  sup_req.tags = {"concurrency"};
  sup_req.actor = "architect";
  sup_req.supersedes = "mem-3";
  const auto m5 = must(store.record(std::move(sup_req)), "record m5 superseding m3");
  check(m5.id == "mem-5" && m5.supersedes == std::optional<std::string>{"mem-3"},
        "m5 supersedes mismatch");

  // get("mem-3") must expose derived superseded_by == "mem-5".
  const auto fetched_m3 = must(store.get("mem-3"), "get mem-3");
  check(fetched_m3.has_value() &&
            fetched_m3->superseded_by == std::optional<std::string>{"mem-5"},
        "derived superseded_by missing on get");
  check(!must(store.get("mem-999"), "get missing").has_value(),
        "missing id returned entry");
  check(!store.get("bad-id").has_value(), "invalid id accepted on get");

  // Default recall hides superseded mem-3; include_superseded=true reveals it.
  const auto active_hits = must(store.recall(q), "recall active flock");
  for (const auto &hit : active_hits)
    check(hit.entry.id != "mem-3", "superseded mem-3 leaked into default recall");
  check(active_hits.size() == 4 && active_hits[0].entry.id == "mem-5",
        "active hits after supersede mismatch");

  MemoryRecallQuery q_all = q;
  q_all.include_superseded = true;
  const auto all_hits = must(store.recall(q_all), "recall include_superseded");
  check(all_hits.size() == 5, "include_superseded did not return all 5 hits");
  bool saw_m3 = false;
  for (const auto &hit : all_hits) {
    if (hit.entry.id == "mem-3") {
      saw_m3 = true;
      check(hit.entry.superseded_by == std::optional<std::string>{"mem-5"},
            "superseded_by missing in recall hit");
    }
  }
  check(saw_m3, "mem-3 missing with include_superseded=true");

  // recent() hides superseded by default, reveals when requested.
  const auto rec_active = must(store.recent(16, false), "recent active");
  check(rec_active.size() == 4 && rec_active[0].id == "mem-5" &&
            rec_active[1].id == "mem-4",
        "recent active order mismatch");
  const auto rec_all = must(store.recent(16, true), "recent all");
  check(rec_all.size() == 5 && rec_all[2].id == "mem-3", "recent all order mismatch");

  // Double-supersede of mem-3 must be rejected with ErrorCode::conflict.
  MemoryRecordRequest double_sup{};
  double_sup.kind = MemoryKind::decision;
  double_sup.title = "Conflicting supersede";
  double_sup.body = "Attempts to supersede already superseded mem-3.";
  double_sup.actor = "architect";
  double_sup.supersedes = "mem-3";
  const auto conflict_res = store.record(std::move(double_sup));
  check(!conflict_res.has_value() && conflict_res.error().code == ErrorCode::conflict,
        "double supersede was not rejected with conflict");

  // Superseding non-existent target fails with invalid_identity.
  MemoryRecordRequest missing_sup{};
  missing_sup.kind = MemoryKind::decision;
  missing_sup.title = "Missing target supersede";
  missing_sup.body = "Targets mem-404.";
  missing_sup.actor = "architect";
  missing_sup.supersedes = "mem-404";
  const auto missing_res = store.record(std::move(missing_sup));
  check(!missing_res.has_value() &&
            missing_res.error().code == ErrorCode::invalid_identity,
        "superseding nonexistent id was accepted");

  // Validation rejections on title/body bounds.
  MemoryRecordRequest empty_title{};
  empty_title.title = "";
  empty_title.body = "ok";
  empty_title.actor = "worker";
  check(!store.record(std::move(empty_title)).has_value(), "empty title accepted");

  MemoryRecordRequest big_body{};
  big_body.title = "ok";
  big_body.body.assign(kMemoryMaxBodyBytes + 1, 'x');
  big_body.actor = "worker";
  const auto cap_res = store.record(std::move(big_body));
  check(!cap_res.has_value() && cap_res.error().code == ErrorCode::capacity,
        "oversized body accepted");

  // to_value / to_json roundtrip sanity.
  const auto json_entry = must(to_json(m5), "to_json entry");
  const auto parsed_entry = must(parse_json(json_entry), "parse_json entry");
  check(parsed_entry.find("id") != nullptr &&
            parsed_entry.find("id")->string() == "mem-5",
        "to_json entry id mismatch");
  const auto json_hits = must(to_json(all_hits), "to_json hits");
  const auto parsed_hits = must(parse_json(json_hits), "parse_json hits");
  check(parsed_hits.array().size() == 5, "to_json hits array size mismatch");
}

void test_honest_freshness_verification(const std::filesystem::path &base) {
  g_stage = "honest_freshness_verification";
  const auto repo = base / "repo-freshness";
  const auto tracked = repo / "src" / "engine.cpp";
  write_file_bytes(tracked, "int version = 1;\n");

  auto store =
      must(ProjectMemoryStore::open(base / "mem-freshness"), "open freshness store");

  // Record a finding pinned to the real temp file (auto-hashing via repo_root).
  MemoryRecordRequest pinned_req{};
  pinned_req.kind = MemoryKind::finding;
  pinned_req.title = "Engine version constant";
  pinned_req.body = "Engine version is currently 1 in src/engine.cpp.";
  pinned_req.tags = {"engine"};
  pinned_req.actor = "memory";
  pinned_req.sources = {MemorySourcePin{"src/engine.cpp", ""}};
  pinned_req.repo_root = repo;
  const auto pinned = must(store.record(std::move(pinned_req)), "record pinned");
  check(pinned.sources.size() == 1 &&
            pinned.sources[0].sha256 == memory_sha256_hex("int version = 1;\n"),
        "auto-computed sha256 mismatch");

  // Record an unpinned entry for comparison.
  MemoryRecordRequest unpinned_req{};
  unpinned_req.kind = MemoryKind::preference;
  unpinned_req.title = "Engine formatting preference";
  unpinned_req.body = "Prefer concise engine helpers.";
  unpinned_req.actor = "memory";
  (void)must(store.record(std::move(unpinned_req)), "record unpinned");

  // Without verify_root: pinned entry is unchecked (never falsely fresh!), unpinned is
  // unpinned.
  MemoryRecallQuery q_unverified{};
  q_unverified.query = "engine";
  const auto unverified_hits = must(store.recall(q_unverified), "recall unverified");
  check(unverified_hits.size() == 2, "expected 2 unverified hits");
  for (const auto &hit : unverified_hits) {
    if (hit.entry.id == pinned.id)
      check(hit.freshness == MemoryFreshness::unchecked,
            "pinned entry without verify_root must be unchecked");
    else
      check(hit.freshness == MemoryFreshness::unpinned,
            "unpinned entry must be unpinned");
  }

  // With verify_root before modification: pinned -> fresh, unpinned -> unpinned.
  MemoryRecallQuery q_verified{};
  q_verified.query = "engine";
  q_verified.verify_root = repo;
  const auto fresh_hits = must(store.recall(q_verified), "recall fresh");
  check(fresh_hits.size() == 2, "expected 2 fresh hits");
  for (const auto &hit : fresh_hits) {
    if (hit.entry.id == pinned.id)
      check(hit.freshness == MemoryFreshness::fresh, "unmodified pin must be fresh");
    else
      check(hit.freshness == MemoryFreshness::unpinned,
            "unpinned entry must remain unpinned");
  }

  // Modify 1 byte of the pinned file -> stale!
  write_file_bytes(tracked, "int version = 2;\n");
  const auto stale_hits = must(store.recall(q_verified), "recall stale");
  for (const auto &hit : stale_hits) {
    if (hit.entry.id == pinned.id)
      check(hit.freshness == MemoryFreshness::stale,
            "1-byte modified pin must be stale");
  }

  // Delete the pinned file -> missing_source!
  check(std::filesystem::remove(tracked), "failed to delete tracked file");
  const auto missing_hits = must(store.recall(q_verified), "recall missing_source");
  for (const auto &hit : missing_hits) {
    if (hit.entry.id == pinned.id)
      check(hit.freshness == MemoryFreshness::missing_source,
            "deleted pin must be missing_source");
  }
}

void test_path_containment_and_symlink_escapes(const std::filesystem::path &base) {
  g_stage = "path_containment_and_symlink_escapes";
  const auto repo = base / "repo-contain";
  const auto outside = base / "outside-secret.txt";
  write_file_bytes(outside, "top-secret-payload\n");
  const std::string outside_sha = memory_sha256_hex("top-secret-payload\n");

  const auto inside_file = repo / "docs" / "note.txt";
  write_file_bytes(inside_file, "top-secret-payload\n");

  const auto outside_dir = base / "outside-dir";
  write_file_bytes(outside_dir / "nested.txt", "nested-secret\n");

  // Plant a leaf symlink and an intermediate directory symlink inside repo.
  const auto leaf_link = repo / "docs" / "escape-leaf.txt";
  check(::symlink(outside.c_str(), leaf_link.c_str()) == 0,
        "failed to create leaf symlink");
  const auto dir_link = repo / "linkdir";
  check(::symlink(outside_dir.c_str(), dir_link.c_str()) == 0,
        "failed to create dir symlink");

  auto store =
      must(ProjectMemoryStore::open(base / "mem-contain"), "open containment store");

  // 1. Reject '..' traversal on record (both with and without repo_root).
  MemoryRecordRequest dotdot_req{};
  dotdot_req.kind = MemoryKind::finding;
  dotdot_req.title = "Traversal attempt";
  dotdot_req.body = "Tries to pin ../outside-secret.txt";
  dotdot_req.actor = "tester";
  dotdot_req.sources = {MemorySourcePin{"../outside-secret.txt", ""}};
  dotdot_req.repo_root = repo;
  const auto dotdot_res = store.record(std::move(dotdot_req));
  check(!dotdot_res.has_value() && dotdot_res.error().code == ErrorCode::invalid_range,
        "'..' pin accepted on record");

  // 2. Reject absolute path outside repo_root on record.
  MemoryRecordRequest abs_escape_req{};
  abs_escape_req.kind = MemoryKind::finding;
  abs_escape_req.title = "Absolute escape";
  abs_escape_req.body = "Tries to pin absolute outside file";
  abs_escape_req.actor = "tester";
  abs_escape_req.sources = {MemorySourcePin{outside.string(), ""}};
  abs_escape_req.repo_root = repo;
  const auto abs_res = store.record(std::move(abs_escape_req));
  check(!abs_res.has_value() && abs_res.error().code == ErrorCode::invalid_range,
        "absolute outside pin accepted on record");

  // 3. Reject leaf symlink and directory symlink on record.
  MemoryRecordRequest leaf_sym_req{};
  leaf_sym_req.kind = MemoryKind::finding;
  leaf_sym_req.title = "Leaf symlink";
  leaf_sym_req.body = "Tries to pin leaf symlink";
  leaf_sym_req.actor = "tester";
  leaf_sym_req.sources = {MemorySourcePin{"docs/escape-leaf.txt", ""}};
  leaf_sym_req.repo_root = repo;
  const auto leaf_sym_res = store.record(std::move(leaf_sym_req));
  check(!leaf_sym_res.has_value() && leaf_sym_res.error().code == ErrorCode::io,
        "leaf symlink pin accepted on record");

  MemoryRecordRequest dir_sym_req{};
  dir_sym_req.kind = MemoryKind::finding;
  dir_sym_req.title = "Dir symlink";
  dir_sym_req.body = "Tries to pin file through directory symlink";
  dir_sym_req.actor = "tester";
  dir_sym_req.sources = {MemorySourcePin{"linkdir/nested.txt", ""}};
  dir_sym_req.repo_root = repo;
  const auto dir_sym_res = store.record(std::move(dir_sym_req));
  check(!dir_sym_res.has_value() && dir_sym_res.error().code == ErrorCode::io,
        "directory symlink pin accepted on record");

  // 4. Reject '..' directly in verify_memory_freshness.
  MemoryEntry crafted{};
  crafted.id = "mem-1";
  crafted.sources = {MemorySourcePin{"../outside-secret.txt", outside_sha}};
  const auto verify_dotdot = verify_memory_freshness(crafted, repo);
  check(!verify_dotdot.has_value() &&
            verify_dotdot.error().code == ErrorCode::invalid_range,
        "verify_memory_freshness accepted '..'");

  // 5. Reject absolute path outside verify_root during recall().
  MemoryRecordRequest prehashed_outside{};
  prehashed_outside.kind = MemoryKind::finding;
  prehashed_outside.title = "Prehashed external pin";
  prehashed_outside.body = "Recorded with explicit sha256 outside verify_root.";
  prehashed_outside.actor = "tester";
  prehashed_outside.sources = {MemorySourcePin{outside.string(), outside_sha}};
  (void)must(store.record(std::move(prehashed_outside)), "record prehashed outside");

  MemoryRecallQuery q_abs{};
  q_abs.query = "external";
  q_abs.verify_root = repo;
  const auto recall_abs = store.recall(q_abs);
  check(!recall_abs.has_value() && recall_abs.error().code == ErrorCode::invalid_range,
        "recall verify_root accepted absolute path outside verify_root");

  // 6. Record legitimate inside file, then replace it with a symlink to outside file
  // (which even has the SAME sha256!) -> verify_root MUST reject symlink escape!
  MemoryRecordRequest legit_req{};
  legit_req.kind = MemoryKind::finding;
  legit_req.title = "Legitimate note";
  legit_req.body = "Pinned to docs/note.txt.";
  legit_req.actor = "tester";
  legit_req.sources = {MemorySourcePin{"docs/note.txt", ""}};
  legit_req.repo_root = repo;
  (void)must(store.record(std::move(legit_req)), "record legit pin");

  check(std::filesystem::remove(inside_file), "remove inside_file failed");
  check(::symlink(outside.c_str(), inside_file.c_str()) == 0,
        "replace inside_file with symlink failed");

  MemoryRecallQuery q_sym{};
  q_sym.query = "legitimate";
  q_sym.verify_root = repo;
  const auto recall_sym = store.recall(q_sym);
  check(!recall_sym.has_value() && recall_sym.error().code == ErrorCode::io,
        "recall verify_root followed symlink instead of rejecting");

  // 7. Reject symlink as verify_root itself.
  const auto root_link = base / "repo-symlink";
  check(::symlink(repo.c_str(), root_link.c_str()) == 0, "repo symlink failed");
  MemoryRecallQuery q_bad_root{};
  q_bad_root.query = "legitimate";
  q_bad_root.verify_root = root_link;
  check(!store.recall(q_bad_root).has_value(), "symlink verify_root was accepted");
}

void test_multithread_concurrent_records(const std::filesystem::path &base) {
  g_stage = "multithread_concurrent_records";
  const auto root = base / "concurrent-threads";
  (void)must(ProjectMemoryStore::open(root), "open concurrent root");

  constexpr int kThreads = 4;
  constexpr int kPerThread = 20;
  std::atomic<int> failures{0};
  std::vector<std::thread> threads;
  threads.reserve(kThreads);

  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&, t] {
      auto handle = ProjectMemoryStore::open(root);
      if (!handle.has_value()) {
        std::cerr << "thread " << t
                  << " open failed: " << error_name(handle.error().code) << " ("
                  << handle.error().detail << ")\n";
        failures.fetch_add(1);
        return;
      }
      const std::string actor = "worker-" + std::to_string(t);
      for (int i = 0; i < kPerThread; ++i) {
        MemoryRecordRequest req{};
        req.kind = MemoryKind::finding;
        req.title =
            "Concurrent entry t=" + std::to_string(t) + " i=" + std::to_string(i);
        req.body =
            "Payload from thread " + std::to_string(t) + " iter " + std::to_string(i);
        req.tags = {"concurrent", actor};
        req.actor = actor;
        auto res = handle.value().record(std::move(req));
        if (!res.has_value()) {
          std::cerr << "thread " << t << " record " << i
                    << " failed: " << error_name(res.error().code) << " ("
                    << res.error().detail << ")\n";
          failures.fetch_add(1);
          return;
        }
      }
    });
  }
  for (auto &th : threads)
    th.join();
  check(failures.load() == 0, "concurrent thread encountered error");

  auto verify = must(ProjectMemoryStore::open(root), "reopen concurrent root");
  constexpr std::size_t kTotal = static_cast<std::size_t>(kThreads * kPerThread);
  std::set<std::string> titles;
  for (std::size_t idx = 1; idx <= kTotal; ++idx) {
    const std::string id = "mem-" + std::to_string(idx);
    const auto entry = must(verify.get(id), "get concurrent id");
    check(entry.has_value(), "missing monotonic concurrent id");
    if (entry.has_value()) {
      check(entry->id == id, "concurrent id mismatch");
      check(titles.insert(entry->title).second, "duplicate concurrent payload");
    }
  }
  check(!must(verify.get("mem-81"), "check no 81st entry").has_value(),
        "unexpected extra concurrent entry");

  // Also verify limit clamping to kMemoryMaxLimit (64).
  const auto clamped_recent = must(verify.recent(200, false), "clamped recent");
  check(clamped_recent.size() == kMemoryMaxLimit &&
            clamped_recent.front().id == "mem-80",
        "recent limit did not clamp to 64 or sort newest first");
  MemoryRecallQuery clamped_q{};
  clamped_q.query = "concurrent";
  clamped_q.limit = 200;
  const auto clamped_hits = must(verify.recall(clamped_q), "clamped recall");
  check(clamped_hits.size() == kMemoryMaxLimit, "recall limit did not clamp to 64");
}

void test_crash_recovery_truncated_tail(const std::filesystem::path &base) {
  g_stage = "crash_recovery_truncated_tail";
  const auto root = base / "crash-recovery";
  auto store = must(ProjectMemoryStore::open(root), "open crash store");

  MemoryRecordRequest req1{};
  req1.kind = MemoryKind::decision;
  req1.title = "Committed entry 1";
  req1.body = "First durable decision.";
  req1.actor = "alpha";
  const auto m1 = must(store.record(std::move(req1)), "record m1");

  MemoryRecordRequest req2{};
  req2.kind = MemoryKind::handoff;
  req2.title = "Committed entry 2";
  req2.body = "Second durable handoff.";
  req2.actor = "beta";
  const auto m2 = must(store.record(std::move(req2)), "record m2");
  check(m1.id == "mem-1" && m2.id == "mem-2", "initial crash test ids mismatch");

  // Inject mid-write crash: truncated JSON without trailing newline.
  const auto entries_path = root / "entries.jsonl";
  {
    const int fd = ::open(entries_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open entries.jsonl for truncated tail injection failed");
    const std::string_view partial =
        R"({"id":"mem-3","kind":"finding","title":"Truncated","body":"incomp)";
    const ssize_t wrote = ::write(fd, partial.data(), partial.size());
    (void)::close(fd);
    check(wrote == static_cast<ssize_t>(partial.size()),
          "truncated tail injection write failed");
  }

  // Existing committed entries remain intact; truncated tail is ignored.
  const auto before_rec = must(store.recent(16, true), "recent with truncated tail");
  check(before_rec.size() == 2 && before_rec[0] == m2 && before_rec[1] == m1,
        "committed entries damaged by truncated tail");
  check(!must(store.get("mem-3"), "get mem-3 before recovery").has_value(),
        "truncated mem-3 was treated as committed");

  // Next record() recovers on a fresh line with mem-3.
  MemoryRecordRequest req3{};
  req3.kind = MemoryKind::friction;
  req3.title = "Recovered entry 3";
  req3.body = "Cleanly recovered after truncated tail.";
  req3.actor = "gamma";
  const auto m3 = must(store.record(std::move(req3)), "record recovered m3");
  check(m3.id == "mem-3", "recovered entry did not receive mem-3");

  const auto after_rec = must(store.recent(16, true), "recent after recovery");
  check(after_rec.size() == 3 && after_rec[0] == m3 && after_rec[1] == m2 &&
            after_rec[2] == m1,
        "entries after truncated-tail recovery mismatch");

  // Worst-case crash: complete JSON object missing only its trailing '\n'.
  {
    const int fd = ::open(entries_path.c_str(), O_WRONLY | O_APPEND | O_CLOEXEC);
    check(fd >= 0, "open entries.jsonl for missing-nl injection failed");
    const std::string_view missing_nl =
        R"({"id":"mem-4","kind":"finding","title":"Uncommitted","body":"no newline","actor":"alpha","created_ns":1000})";
    const ssize_t wrote = ::write(fd, missing_nl.data(), missing_nl.size());
    (void)::close(fd);
    check(wrote == static_cast<ssize_t>(missing_nl.size()),
          "missing-nl injection write failed");
  }
  check(!must(store.get("mem-4"), "unterminated json treated as committed").has_value(),
        "unterminated complete JSON was treated as committed");

  MemoryRecordRequest req4{};
  req4.kind = MemoryKind::invariant;
  req4.title = "Committed entry 4";
  req4.body = "Must cleanly displace uncommitted missing-nl fragment.";
  req4.actor = "beta";
  const auto m4 = must(store.record(std::move(req4)), "record m4 after missing-nl");
  check(m4.id == "mem-4" && m4.title == "Committed entry 4",
        "recovery after missing-nl crash failed");
  const auto final_rec = must(store.recent(16, true), "recent after missing-nl");
  check(final_rec.size() == 4 && final_rec[0] == m4,
        "uncommitted missing-nl line resurrected or displaced m4");
}

} // namespace

int main() {
  char pattern[] = "/tmp/blackbird-project-memory-XXXXXX";
  const char *raw_dir = ::mkdtemp(pattern);
  if (!raw_dir)
    return 2;
  const std::filesystem::path base{raw_dir};
  try {
    test_sha256_and_validators(base);
    test_directory_security(base);
    test_record_recall_ranking_and_supersedes(base);
    test_honest_freshness_verification(base);
    test_path_containment_and_symlink_escapes(base);
    test_multithread_concurrent_records(base);
    test_crash_recovery_truncated_tail(base);
    std::filesystem::remove_all(base);
    std::cout << "project_memory: sha256/validators, directory security, "
                 "record/recall ranking & supersedes, honest freshness, "
                 "path containment & symlink rejection, multithread concurrency, "
                 "and crash recovery passed\n";
    return 0;
  } catch (const std::exception &error) {
    std::cerr << g_stage << ": " << error.what() << '\n';
    std::filesystem::remove_all(base);
    return 1;
  }
}
