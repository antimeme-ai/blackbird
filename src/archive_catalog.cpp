#include "blackbird/archive_catalog.hpp"
#include <algorithm>
#include <chrono>
#include <functional>
#include <limits>
namespace blackbird {
namespace {
constexpr std::size_t prefix_size = 160;
constexpr std::size_t entry_size = 96;
constexpr std::uint64_t magic = 0x3154414341524242ULL;
void put(MutableByteView out, std::uint64_t n) {
  for (auto &b : out) {
    b = static_cast<std::byte>(n & 255U);
    n >>= 8;
  }
}
std::uint64_t get(ByteView in) {
  std::uint64_t n = 0;
  for (std::size_t i = 0; i < in.size(); ++i)
    n |= static_cast<std::uint64_t>(std::to_integer<unsigned>(in[i])) << (8 * i);
  return n;
}
Result<void> read_at(Storage &file, std::uint64_t offset, MutableByteView out) {
  std::size_t done = 0;
  unsigned interruptions = 0;
  while (done < out.size()) {
    auto n = file.read_at(offset + done, out.subspan(done));
    if (!n.has_value()) {
      if (n.error().code == ErrorCode::interrupted && ++interruptions < 8)
        continue;
      return Result<void>::failure(n.error());
    }
    if (!n.value() || n.value() > out.size() - done)
      return Result<void>::failure({ErrorCode::incomplete});
    done += n.value();
  }
  return Result<void>::success();
}
Result<void> write_at(Storage &file, std::uint64_t offset, ByteView in) {
  std::size_t done = 0;
  while (done < in.size()) {
    auto n = file.write_at(offset + done, in.subspan(done));
    if (!n.has_value())
      return Result<void>::failure(n.error());
    if (!n.value() || n.value() > in.size() - done)
      return Result<void>::failure({ErrorCode::incomplete});
    done += n.value();
  }
  return Result<void>::success();
}
std::array<std::byte, entry_size> encode(const ArchiveEntry &entry,
                                         std::uint32_t ordinal) {
  std::array<std::byte, entry_size> bytes{};
  MutableByteView out{bytes};
  std::copy(entry.key.begin(), entry.key.end(), bytes.begin());
  const auto &r = entry.record;
  put(out.subspan(40, 8), static_cast<std::uint16_t>(r.kind));
  put(out.subspan(48, 8), r.sequence);
  put(out.subspan(56, 8), r.batch_first);
  put(out.subspan(64, 8), r.payload_offset);
  put(out.subspan(72, 8), r.payload_size);
  put(out.subspan(80, 8), r.frame_checksum);
  put(out.subspan(88, 4), ordinal);
  put(out.subspan(92, 4), crc32c(ByteView{bytes}.first(92)));
  return bytes;
}
Result<ArchiveEntry> decode_entry(ByteView in, std::uint64_t ordinal,
                                  const JournalHeader &header, JournalCursor boundary) {
  const auto kind = get(in.subspan(40, 8)), sequence = get(in.subspan(48, 8)),
             first = get(in.subspan(56, 8));
  const auto offset = get(in.subspan(64, 8)), size = get(in.subspan(72, 8)),
             checksum = get(in.subspan(80, 8));
  if (get(in.subspan(88, 4)) != ordinal ||
      get(in.subspan(92, 4)) != crc32c(in.first(92)) || (kind != 1 && kind != 2) ||
      !sequence || sequence >= boundary.sequence || !first || first > sequence ||
      offset < journal_header_size + journal_frame_header_size ||
      offset > boundary.end_offset || size > boundary.end_offset - offset ||
      size > header.limits.max_payload || checksum > UINT32_MAX)
    return Result<ArchiveEntry>::failure({ErrorCode::corrupt});
  ArchiveEntry result{{},
                      {header.environment, header.journal, static_cast<FrameKind>(kind),
                       sequence, first, offset, static_cast<std::uint32_t>(size),
                       static_cast<std::uint32_t>(checksum)}};
  std::copy_n(in.begin(), result.key.size(), result.key.begin());
  return Result<ArchiveEntry>::success(result);
}
class CatalogBatchReader {
public:
  CatalogBatchReader(Storage &file, const JournalHeader &header, JournalCursor boundary,
                     std::uint64_t count)
      : file_(file), header_(header), boundary_(boundary), count_(count) {}
  Result<std::optional<ArchiveEntry>> next() {
    using Answer = Result<std::optional<ArchiveEntry>>;
    if (ordinal_ >= count_)
      return Answer::success(std::nullopt);
    if (cursor_ == buffered_) {
      constexpr std::uint64_t batch_entries = 128;
      const auto chunk = std::min(batch_entries, count_ - ordinal_);
      buffer_.resize(static_cast<std::size_t>(chunk) * entry_size);
      auto read = read_at(file_, prefix_size + ordinal_ * entry_size, buffer_);
      if (!read.has_value())
        return Answer::failure(read.error());
      cursor_ = 0;
      buffered_ = static_cast<std::size_t>(chunk);
    }
    const auto slice = ByteView{buffer_}.subspan(cursor_ * entry_size, entry_size);
    auto decoded = decode_entry(slice, ordinal_, header_, boundary_);
    if (!decoded.has_value())
      return Answer::failure(decoded.error());
    ++cursor_;
    ++ordinal_;
    return Answer::success(std::move(decoded).value());
  }

private:
  Storage &file_;
  JournalHeader header_;
  JournalCursor boundary_;
  std::uint64_t count_ = 0, ordinal_ = 0;
  std::vector<std::byte> buffer_;
  std::size_t cursor_ = 0, buffered_ = 0;
};
} // namespace
static Result<std::uint64_t>
publish_stream(JournalDirectory &directory, std::string_view name, JournalHeader header,
               JournalCursor boundary,
               const std::function<Result<std::optional<ArchiveEntry>>()> &next) {
  using Answer = Result<std::uint64_t>;
  try {
    if (boundary.journal != header.journal || boundary.end_offset < journal_header_size)
      return Answer::failure({ErrorCode::invalid_range});
    auto h = encode_journal_header(header);
    if (!h.has_value())
      return Answer::failure(h.error());
    const auto temporary =
        std::string{name} + ".tmp." +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    auto created = directory.create_exclusive(temporary);
    if (!created.has_value())
      return Answer::failure(created.error());
    auto file = std::move(created).value();
    std::array<std::byte, prefix_size> bytes{};
    auto written = write_at(*file, 0, bytes);
    if (!written.has_value())
      return Answer::failure(written.error());
    // Stream complete contiguous batches and patch the header count/CRC before sync.
    constexpr std::size_t batch_entries = 128;
    std::optional<RecoveryKey> prior;
    std::vector<std::byte> batch;
    batch.reserve(batch_entries * entry_size);
    std::uint64_t count = 0;
    std::uint64_t batch_start = 0;
    for (;;) {
      auto loaded = next();
      if (!loaded.has_value())
        return Answer::failure(loaded.error());
      const auto &maybe = loaded.value();
      if (!maybe.has_value())
        break;
      if (count >= UINT32_MAX)
        return Answer::failure({ErrorCode::invalid_range});
      const auto &entry = *maybe;
      const auto &r = entry.record;
      if ((prior && !(prior.value() < entry.key)) || r.journal != header.journal ||
          r.environment != header.environment || !r.sequence ||
          r.sequence >= boundary.sequence || !r.batch_first ||
          r.batch_first > r.sequence ||
          r.payload_offset < journal_header_size + journal_frame_header_size ||
          r.payload_offset > boundary.end_offset ||
          r.payload_size > boundary.end_offset - r.payload_offset ||
          r.payload_size > header.limits.max_payload ||
          (r.kind != FrameKind::source && r.kind != FrameKind::semantic))
        return Answer::failure({ErrorCode::invalid_range});
      prior = entry.key;
      const auto item = encode(entry, static_cast<std::uint32_t>(count));
      batch.insert(batch.end(), item.begin(), item.end());
      ++count;
      if (batch.size() == batch_entries * entry_size) {
        written = write_at(*file, prefix_size + batch_start * entry_size, batch);
        if (!written.has_value())
          return Answer::failure(written.error());
        batch.clear();
        batch_start = count;
      }
    }
    if (!batch.empty()) {
      written = write_at(*file, prefix_size + batch_start * entry_size, batch);
      if (!written.has_value())
        return Answer::failure(written.error());
    }
    MutableByteView out{bytes};
    put(out.first(8), magic);
    put(out.subspan(8, 8), 2);
    std::copy(h.value().begin(), h.value().end(), bytes.begin() + 16);
    put(out.subspan(128, 8), boundary.sequence);
    put(out.subspan(136, 8), boundary.end_offset);
    put(out.subspan(144, 8), count);
    put(out.subspan(152, 4), crc32c(ByteView{bytes}.first(152)));
    written = write_at(*file, 0, bytes);
    if (!written.has_value())
      return Answer::failure(written.error());
    auto synced = file->synchronize(SyncStrength::full);
    if (!synced.has_value())
      return Answer::failure(synced.error());
    auto replaced = directory.replace_file(temporary, name);
    if (!replaced.has_value())
      return Answer::failure(replaced.error());
    auto dir_synced = directory.synchronize_directory(SyncStrength::full);
    if (!dir_synced.has_value())
      return Answer::failure(dir_synced.error());
    return Answer::success(count);
  } catch (const std::bad_alloc &) {
    return Answer::failure({ErrorCode::allocation});
  }
}
Result<void> ArchiveCatalog::publish(JournalDirectory &directory, std::string_view name,
                                     JournalHeader header, JournalCursor boundary,
                                     std::span<const ArchiveEntry> sorted,
                                     const RawRetainedOrigin &raw_origin) {
  const auto input_count = sorted.size();
  const bool previous_present = false;
  RawRetainedFields arguments;
  arguments.header(header);
  arguments.cursor(boundary);
  arguments.native(input_count);
  arguments.native(previous_present);
  RawRetainedPair trace{raw_origin, {3200, 3201}, 228, arguments.view()};
  auto answer = trace.run([&]() -> Result<void> {
    std::size_t index = 0;
    auto published = publish_stream(
        directory, name, header, boundary,
        [&]() -> Result<std::optional<ArchiveEntry>> {
          if (index >= sorted.size())
            return Result<std::optional<ArchiveEntry>>::success(std::nullopt);
          return Result<std::optional<ArchiveEntry>>::success(sorted[index++]);
        });
    return published.has_value() ? Result<void>::success()
                                 : Result<void>::failure(published.error());
  });
  RawRetainedFields returned;
  if (answer.has_value()) {
    returned.native(input_count);
    trace.result(answer, returned.view());
  } else
    trace.result(answer);
  return answer;
}
Result<std::uint64_t> ArchiveCatalog::publish_merge(
    JournalDirectory &directory, std::string_view name, JournalHeader header,
    JournalCursor boundary, const ArchiveCatalog *previous,
    std::span<const ArchiveEntry> delta, const RawRetainedOrigin &raw_origin) {
  const auto input_count = delta.size();
  const bool previous_present = previous != nullptr;
  RawRetainedFields arguments;
  arguments.header(header);
  arguments.cursor(boundary);
  arguments.native(input_count);
  arguments.native(previous_present);
  const auto previous_count = previous ? previous->count() : 0;
  if (previous)
    arguments.native(previous_count);
  RawRetainedPair trace{raw_origin, {3200, 3201}, 228, arguments.view()};
  std::optional<RawRetainedOriginScope> previous_origin;
  if (previous)
    previous_origin.emplace(previous->raw_origin_, trace.child());
  auto answer = trace.run([&]() -> Result<std::uint64_t> {
    using Answer = Result<std::uint64_t>;
    for (std::size_t i = 1; i < delta.size(); ++i)
      if (!(delta[i - 1].key < delta[i].key))
        return Answer::failure({ErrorCode::invalid_range});
    std::optional<CatalogBatchReader> reader;
    if (previous)
      reader.emplace(*previous->file_, previous->header_, previous->boundary_,
                     previous->count_);
    std::size_t fresh = 0;
    std::optional<ArchiveEntry> selected;
    const auto next = [&]() -> Result<std::optional<ArchiveEntry>> {
      if (!selected && reader) {
        auto loaded = reader->next();
        if (!loaded.has_value())
          return Result<std::optional<ArchiveEntry>>::failure(loaded.error());
        selected = std::move(loaded).value();
      }
      if (fresh < delta.size() && (!selected || !(selected->key < delta[fresh].key))) {
        if (selected && selected->key == delta[fresh].key)
          selected.reset();
        return Result<std::optional<ArchiveEntry>>::success(delta[fresh++]);
      }
      if (!selected)
        return Result<std::optional<ArchiveEntry>>::success(std::nullopt);
      auto result = std::move(*selected);
      selected.reset();
      return Result<std::optional<ArchiveEntry>>::success(std::move(result));
    };
    return publish_stream(directory, name, header, boundary, next);
  });
  RawRetainedFields returned;
  if (answer.has_value()) {
    returned.native(answer.value());
    trace.result(answer, returned.view());
  } else
    trace.result(answer);
  return answer;
}
Result<std::unique_ptr<ArchiveCatalog>>
ArchiveCatalog::open(JournalDirectory &directory, std::string_view name,
                     JournalHeader header, JournalCursor boundary,
                     std::uint64_t maximum_entries,
                     const RawRetainedOrigin &raw_origin) {
  RawRetainedFields arguments;
  arguments.header(header);
  arguments.cursor(boundary);
  arguments.native(maximum_entries);
  RawRetainedPair trace{raw_origin, {3202, 3203}, 219, arguments.view()};
  auto answer = trace.run([&]() -> Result<std::unique_ptr<ArchiveCatalog>> {
    using Answer = Result<std::unique_ptr<ArchiveCatalog>>;
    auto opened = directory.open_existing(name, FileAccess::read_only);
    if (!opened.has_value())
      return Answer::failure(opened.error());
    auto file = std::move(opened).value();
    std::array<std::byte, prefix_size> bytes{};
    auto read = read_at(*file, 0, bytes);
    if (!read.has_value())
      return Answer::failure(read.error());
    const ByteView in{bytes};
    const auto count = get(in.subspan(144, 8));
    auto h = encode_journal_header(header);
    auto extent = file->extent();
    if (!h.has_value())
      return Answer::failure(h.error());
    if (!extent.has_value())
      return Answer::failure(extent.error());
    if (get(in.first(8)) != magic || get(in.subspan(8, 8)) != 2 ||
        !std::equal(h.value().begin(), h.value().end(), bytes.begin() + 16) ||
        boundary.journal != header.journal ||
        get(in.subspan(128, 8)) != boundary.sequence ||
        get(in.subspan(136, 8)) != boundary.end_offset ||
        get(in.subspan(152, 4)) != crc32c(in.first(152)) || get(in.last(4)) != 0 ||
        count > UINT32_MAX || count > maximum_entries ||
        count > (UINT64_MAX - prefix_size) / entry_size ||
        extent.value() != prefix_size + count * entry_size)
      return Answer::failure({ErrorCode::corrupt});
    try {
      return Answer::success(std::unique_ptr<ArchiveCatalog>{
          new ArchiveCatalog{std::move(file), header, boundary, count, trace.child()}});
    } catch (const std::bad_alloc &) {
      return Answer::failure({ErrorCode::allocation});
    }
  });
  RawRetainedFields returned;
  if (answer.has_value()) {
    returned.native(answer.value()->count_);
    trace.result(answer, returned.view());
  } else
    trace.result(answer);
  return answer;
}
Result<ArchiveEntry> ArchiveCatalog::entry(std::uint64_t ordinal) const {
  RawRetainedFields arguments;
  arguments.native(ordinal);
  RawRetainedPair trace{raw_origin_, {3206, 3207}, 204, arguments.view()};
  auto answer = trace.run([&]() -> Result<ArchiveEntry> {
    if (ordinal >= count_)
      return Result<ArchiveEntry>::failure({ErrorCode::invalid_range});
    std::array<std::byte, entry_size> bytes{};
    auto read = read_at(*file_, prefix_size + ordinal * entry_size, bytes);
    if (!read.has_value())
      return Result<ArchiveEntry>::failure(read.error());
    const ByteView in{bytes};
    return decode_entry(in, ordinal, header_, boundary_);
  });
  RawRetainedFields returned;
  if (answer.has_value()) {
    returned.add(answer.value().key);
    returned.physical(answer.value().record);
  }
  trace.result(answer, returned.view());
  return answer;
}
Result<std::optional<PhysicalJournalRecord>>
ArchiveCatalog::find(const RecoveryKey &key) const {
  RawRetainedFields arguments;
  arguments.add(key);
  arguments.cursor(boundary_);
  RawRetainedPair trace{raw_origin_, {3204, 3205}, 228, arguments.view()};
  RawRetainedOriginScope origin_scope{raw_origin_, trace.child()};
  auto answer = trace.run([&]() -> Result<std::optional<PhysicalJournalRecord>> {
    std::uint64_t first = 0, end = count_;
    while (first < end) {
      const auto middle = first + (end - first) / 2;
      auto loaded = entry(middle);
      if (!loaded.has_value())
        return Result<std::optional<PhysicalJournalRecord>>::failure(loaded.error());
      if (loaded.value().key < key)
        first = middle + 1;
      else
        end = middle;
    }
    if (first == count_)
      return Result<std::optional<PhysicalJournalRecord>>::success(std::nullopt);
    auto loaded = entry(first);
    if (!loaded.has_value())
      return Result<std::optional<PhysicalJournalRecord>>::failure(loaded.error());
    return Result<std::optional<PhysicalJournalRecord>>::success(
        loaded.value().key == key
            ? std::optional<PhysicalJournalRecord>{loaded.value().record}
            : std::nullopt);
  });
  RawRetainedFields returned;
  if (answer.has_value()) {
    const auto &selected = answer.value();
    if (selected.has_value())
      returned.physical(*selected);
  }
  trace.result(answer, returned.view());
  return answer;
}
} // namespace blackbird
