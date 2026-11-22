#include "blackbird/context.hpp"
#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/saved_state.hpp"
#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <map>
#include <set>

namespace blackbird {
std::string read_text(const ImmutableBytes &bytes) {
  const auto data = unwrap(bytes.read());
  return std::string{reinterpret_cast<const char *>(data.data()), data.size()};
}
Result<Value> read_packet(const ImmutableBytes &bytes, ValueLimits limits) {
  if (bytes.size() > limits.bytes)
    return Result<Value>::failure({ErrorCode::capacity});
  auto data = bytes.read();
  if (!data.has_value())
    return Result<Value>::failure(data.error());
  return decode_packet(data.value(), limits);
}
Result<Value> read_application_packet(const ApplicationRecordEvent &record) {
  return read_packet(record.payload);
}
std::string hex_identity(const IdentityBytes &bytes) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(32);
  for (const auto b : bytes) {
    const auto n = std::to_integer<unsigned>(b);
    out += digits[n >> 4U];
    out += digits[n & 15U];
  }
  return out;
}
const Value &field(const Value &value, std::string_view name) {
  const auto *f = value.find(name);
  if (f == nullptr)
    throw Error{ErrorCode::corrupt};
  return *f;
}
const std::string &string_field(const Value &value, std::string_view name) {
  const auto &f = field(value, name);
  const auto *s = std::get_if<std::string>(&f.value());
  if (s == nullptr)
    throw Error{ErrorCode::corrupt};
  return *s;
}

std::string_view block_kind_name(BlockKind kind) noexcept {
  switch (kind) {
  case BlockKind::instruction:
    return "instruction";
  case BlockKind::exchange:
    return "exchange";
  case BlockKind::note:
    return "note";
  }
  return "note";
}
std::optional<BlockKind> parse_block_kind(std::string_view name) noexcept {
  if (name == "instruction")
    return BlockKind::instruction;
  if (name == "exchange")
    return BlockKind::exchange;
  if (name == "note")
    return BlockKind::note;
  return std::nullopt;
}
std::string_view compact_op_name(CompactOp op) noexcept {
  switch (op) {
  case CompactOp::drop:
    return "drop";
  case CompactOp::summarize:
    return "summarize";
  case CompactOp::restore:
    return "restore";
  case CompactOp::pin:
    return "pin";
  case CompactOp::unpin:
    return "unpin";
  }
  return "drop";
}
std::optional<CompactOp> parse_compact_op(std::string_view name) noexcept {
  if (name == "drop")
    return CompactOp::drop;
  if (name == "summarize")
    return CompactOp::summarize;
  if (name == "restore")
    return CompactOp::restore;
  if (name == "pin")
    return CompactOp::pin;
  if (name == "unpin")
    return CompactOp::unpin;
  return std::nullopt;
}

namespace {
std::optional<IdentityBytes> parse_hex_identity(std::string_view hex) noexcept {
  if (hex.size() != 32)
    return std::nullopt;
  IdentityBytes out{};
  for (std::size_t i = 0; i < 16; ++i) {
    unsigned byte = 0;
    const auto res =
        std::from_chars(hex.data() + i * 2, hex.data() + i * 2 + 2, byte, 16);
    if (res.ec != std::errc{} || res.ptr != hex.data() + i * 2 + 2 ||
        hex.substr(i * 2, 2).find_first_not_of("0123456789abcdef") !=
            std::string_view::npos)
      return std::nullopt;
    out[i] = static_cast<std::byte>(byte);
  }
  return out;
}

std::uint64_t parse_u64(const Value &v) {
  const auto *n = std::get_if<Number>(&v.value());
  if (!n || n->text().empty())
    throw Error{ErrorCode::corrupt};
  std::uint64_t out = 0;
  const auto &s = n->text();
  const auto res = std::from_chars(s.data(), s.data() + s.size(), out);
  if (res.ec != std::errc{} || res.ptr != s.data() + s.size())
    throw Error{ErrorCode::corrupt};
  return out;
}

std::uint64_t measure_items_bytes(const std::vector<Value> &items) {
  std::uint64_t total = 0;
  for (const auto &item : items) {
    if (const auto sz = encoded_packet_size(item); sz.has_value())
      total += sz.value();
  }
  return total;
}

std::string sanitize_snippet(std::string_view text, std::size_t max_chars) {
  std::string out;
  out.reserve(std::min(text.size(), max_chars + 3));
  bool prev_space = false;
  for (const char ch : text) {
    if (out.size() >= max_chars) {
      out += "...";
      break;
    }
    const auto c = static_cast<unsigned char>(ch);
    if (c == '\n' || c == '\r' || c == '\t' || c == ' ') {
      if (!prev_space && !out.empty())
        out += ' ';
      prev_space = true;
    } else if (c >= 32 && c != 127) {
      out += ch;
      prev_space = false;
    }
  }
  while (!out.empty() && out.back() == ' ')
    out.pop_back();
  return out;
}

std::string extract_text_content(const Value &item) {
  const auto *content = item.find("content");
  if (!content)
    return {};
  if (const auto *s = std::get_if<std::string>(&content->value()))
    return *s;
  if (const auto *arr = std::get_if<Value::Array>(&content->value())) {
    std::string out;
    for (const auto &part : *arr) {
      if (const auto *t = part.find("text");
          t && std::holds_alternative<std::string>(t->value())) {
        if (!out.empty())
          out += ' ';
        out += t->string();
      }
    }
    return out;
  }
  return {};
}

std::string build_preview(const std::vector<Value> &items) {
  std::vector<std::string> tools;
  std::string text;
  std::string role;
  for (const auto &item : items) {
    if (!std::holds_alternative<Value::Object>(item.value()))
      continue;
    if (const auto *type = item.find("type");
        type && std::holds_alternative<std::string>(type->value())) {
      if (type->string() == "function_call") {
        if (const auto *name = item.find("name");
            name && std::holds_alternative<std::string>(name->value()))
          tools.push_back(name->string());
        continue;
      }
      if (type->string() == "function_call_output" || type->string() == "reasoning")
        continue;
    }
    if (const auto *r = item.find("role");
        r && std::holds_alternative<std::string>(r->value())) {
      if (role.empty())
        role = r->string();
      if (text.empty())
        text = extract_text_content(item);
    }
  }
  std::string out;
  if (!tools.empty()) {
    out += "tools: ";
    for (std::size_t i = 0; i < tools.size() && i < 4; ++i) {
      if (i > 0)
        out += ", ";
      out += tools[i];
    }
    if (tools.size() > 4)
      out += " (+" + std::to_string(tools.size() - 4) + ")";
  }
  const auto snippet = sanitize_snippet(text, 96);
  if (!snippet.empty()) {
    if (!out.empty())
      out += " | ";
    if (!role.empty())
      out += role + ": ";
    out += snippet;
  }
  if (out.empty()) {
    if (!role.empty())
      return role + " (" + std::to_string(items.size()) + " items)";
    return std::to_string(items.size()) + " item(s)";
  }
  return out;
}

bool item_is_call(const Value &item) noexcept {
  const auto *type = item.find("type");
  return type && *type == Value{"function_call"};
}
bool item_is_output(const Value &item) noexcept {
  const auto *type = item.find("type");
  return type && *type == Value{"function_call_output"};
}
bool item_is_reasoning(const Value &item) noexcept {
  const auto *type = item.find("type");
  return type && *type == Value{"reasoning"};
}
std::optional<std::string_view> item_call_id(const Value &item) noexcept {
  const auto *id = item.find("call_id");
  if (!id || !std::holds_alternative<std::string>(id->value()) || id->string().empty())
    return std::nullopt;
  return id->string();
}

std::vector<std::string> unanswered_calls(const std::vector<Value> &items) {
  std::vector<std::string> call_order;
  std::set<std::string> calls;
  std::set<std::string> outputs;
  for (const auto &item : items) {
    if (item_is_call(item)) {
      if (const auto id = item_call_id(item)) {
        if (calls.emplace(*id).second)
          call_order.emplace_back(*id);
      }
    } else if (item_is_output(item)) {
      if (const auto id = item_call_id(item))
        outputs.emplace(*id);
    }
  }
  std::vector<std::string> missing;
  for (const auto &id : call_order) {
    if (!outputs.contains(id))
      missing.push_back(id);
  }
  return missing;
}

bool compute_open(const std::vector<Value> &items) {
  return !unanswered_calls(items).empty();
}

BlockKind infer_kind(const std::vector<Value> &items, std::string_view label,
                     std::optional<BlockKind> declared) {
  if (declared.has_value())
    return *declared;
  if (label == "operator" || label.starts_with("rrc:") ||
      label == "backstop.instructions" || label == "seed.instruction")
    return BlockKind::instruction;
  if (label.starts_with("provider."))
    return BlockKind::exchange;
  for (const auto &item : items) {
    if (item_is_call(item) || item_is_output(item) || item_is_reasoning(item))
      return BlockKind::exchange;
    if (const auto *role = item.find("role");
        role && std::holds_alternative<std::string>(role->value())) {
      if (role->string() == "assistant")
        return BlockKind::exchange;
      if (role->string() == "user" || role->string() == "system" ||
          role->string() == "developer")
        return BlockKind::instruction;
    }
  }
  return BlockKind::note;
}

Value sort_keys(const Value &v) {
  if (const auto *obj = std::get_if<Value::Object>(&v.value())) {
    Value::Object sorted;
    sorted.reserve(obj->size());
    for (const auto &[k, val] : *obj)
      sorted.emplace_back(k, sort_keys(val));
    std::sort(sorted.begin(), sorted.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    return Value::object(std::move(sorted));
  }
  if (const auto *arr = std::get_if<Value::Array>(&v.value())) {
    Value::Array out;
    out.reserve(arr->size());
    for (const auto &elem : *arr)
      out.push_back(sort_keys(elem));
    return Value{std::move(out)};
  }
  return v;
}

Value encode_records_array(const std::vector<IdentityBytes> &records) {
  Value::Array out;
  out.reserve(records.size());
  for (const auto &rec : records)
    out.push_back(Value{hex_identity(rec)});
  return Value{std::move(out)};
}

std::vector<IdentityBytes> decode_records_array(const Value &val) {
  std::vector<IdentityBytes> out;
  for (const auto &elem : val.array()) {
    const auto parsed = parse_hex_identity(elem.string());
    if (!parsed)
      throw Error{ErrorCode::corrupt};
    out.push_back(*parsed);
  }
  return out;
}

Value encode_block(const Block &b) {
  Value::Array replaces;
  replaces.reserve(b.replaces.size());
  for (const auto r : b.replaces)
    replaces.push_back(Value{Number{r}});
  return Value::object({{"id", Value{Number{b.id}}},
                        {"kind", Value{std::string{block_kind_name(b.kind)}}},
                        {"pinned", Value{b.pinned}},
                        {"open", Value{b.open}},
                        {"label", Value{b.label}},
                        {"bytes", Value{Number{b.bytes}}},
                        {"items", Value{b.items}},
                        {"replaces", Value{std::move(replaces)}},
                        {"records", encode_records_array(b.records)}});
}

Block decode_block(const Value &v) {
  Block b;
  b.id = parse_u64(field(v, "id"));
  const auto kind = parse_block_kind(string_field(v, "kind"));
  if (!kind)
    throw Error{ErrorCode::corrupt};
  b.kind = *kind;
  b.pinned = std::get<bool>(field(v, "pinned").value());
  b.open = std::get<bool>(field(v, "open").value());
  b.label = string_field(v, "label");
  b.items = field(v, "items").array();
  b.bytes =
      v.find("bytes") ? parse_u64(field(v, "bytes")) : measure_items_bytes(b.items);
  if (const auto *rep = v.find("replaces")) {
    for (const auto &r : rep->array())
      b.replaces.push_back(parse_u64(r));
  }
  if (const auto *recs = v.find("records"))
    b.records = decode_records_array(*recs);
  return b;
}

Value encode_archived(const ArchivedBlock &a) {
  return Value::object({{"id", Value{Number{a.id}}},
                        {"kind", Value{std::string{block_kind_name(a.kind)}}},
                        {"label", Value{a.label}},
                        {"preview", Value{a.preview}},
                        {"bytes", Value{Number{a.bytes}}},
                        {"records", encode_records_array(a.records)}});
}

ArchivedBlock decode_archived(const Value &v) {
  ArchivedBlock a;
  a.id = parse_u64(field(v, "id"));
  const auto kind = parse_block_kind(string_field(v, "kind"));
  if (!kind)
    throw Error{ErrorCode::corrupt};
  a.kind = *kind;
  a.label = string_field(v, "label");
  a.preview = string_field(v, "preview");
  a.bytes = parse_u64(field(v, "bytes"));
  a.records = decode_records_array(field(v, "records"));
  return a;
}

std::set<std::uint64_t> expand_target_ids(const CompactRequest &req,
                                          const std::vector<Block> &live,
                                          const std::vector<ArchivedBlock> &archived) {
  std::set<std::uint64_t> out;
  for (const auto id : req.ids) {
    if (id == 0)
      throw Error{ErrorCode::invalid_range};
    out.insert(id);
  }
  if (req.from.has_value() || req.to.has_value()) {
    const std::uint64_t lo = req.from.value_or(1);
    const std::uint64_t hi = req.to.value_or(UINT64_MAX);
    if (lo == 0 || hi < lo)
      throw Error{ErrorCode::invalid_range};
    if (req.op == CompactOp::restore) {
      for (const auto &a : archived) {
        if (a.id >= lo && a.id <= hi)
          out.insert(a.id);
      }
    } else {
      for (const auto &b : live) {
        if (b.id >= lo && b.id <= hi)
          out.insert(b.id);
      }
    }
  }
  return out;
}

} // namespace

// --- AuditLog ---

std::string AuditLog::record(ApplicationChannel channel, const Value &packet) {
  const auto identity = issue();
  auto result = hex_identity(identity.bytes());
  (void)record(identity, channel, packet);
  return result;
}

RecordReference AuditLog::record(ApplicationRecordId identity,
                                 ApplicationChannel channel, const Value &packet) {
  const ImmutableBytes serialized{unwrap(encode_packet(packet))};
  const auto result =
      unwrap(root_.submit({{}, ApplicationRecordEvent{identity, channel, serialized}}));
  return result.record;
}

SourceReference AuditLog::retain_program(std::string_view source,
                                         DefinitionGenerationId generation) {
  const auto original = issue();
  const auto activation = issue();
  const auto cursor = root_.cursor();
  if (cursor.sequence == UINT64_MAX)
    throw Error{ErrorCode::overflow};
  const auto identity = hex_identity(generation.bytes());
  const auto capture =
      Value::object({{"label", Value{"program.source"}},
                     {"metadata", Value::object({{"generation", Value{identity}}})}});
  const auto effective = Value::object(
      {{"generation", Value{identity}}, {"activation", Value{"turn-boundary"}}});
  const auto raw = std::as_bytes(std::span{source.data(), source.size()});
  const std::array<RetainedEvent, 2> events{
      RetainedEvent{{SourceReference{cursor.journal, cursor.sequence + 1}},
                    ApplicationRecordEvent{original, ApplicationChannel::log,
                                           unwrap(encode_packet(capture))}},
      RetainedEvent{{},
                    ApplicationRecordEvent{activation, ApplicationChannel::program,
                                           unwrap(encode_packet(effective))}}};
  (void)unwrap(root_.append(cursor, std::span{&raw, 1}, events));
  return {cursor.journal, cursor.sequence + 1};
}

std::string AuditLog::original(OriginalCapture capture) {
  const auto identity = issue();
  auto output = hex_identity(identity.bytes());
  (void)original(identity, std::move(capture));
  return output;
}

std::optional<SourceReference> AuditLog::original(ApplicationRecordId identity,
                                                  OriginalCapture capture) {
  const auto label = capture.label;
  const auto raw = capture.bytes;
  auto metadata = std::move(capture.metadata);
  auto packet = Value::object(
      {{"label", Value{std::string{label}}}, {"metadata", std::move(metadata)}});
  if (label == "provider.stream") {
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    if (seconds < 0)
      throw Error{ErrorCode::invalid_range};
    const auto now = static_cast<std::uint64_t>(seconds);
    const auto expires = now + 30ULL * 24 * 60 * 60;
    const auto filename =
        std::to_string(expires) + "." + hex_identity(identity.bytes());
    auto stored = root_.store_diagnostic(
        filename, std::as_bytes(std::span{raw.data(), raw.size()}), now);
    auto &details = packet.object()[1].second.object();
    details.emplace_back("diagnostic_file", Value{filename});
    details.emplace_back("expires_at", Value{Number{expires}});
    details.emplace_back("bytes", Value{Number{raw.size()}});
    details.emplace_back("available", Value{stored.has_value()});
    if (!stored.has_value())
      details.emplace_back("storage_error",
                           Value{std::string{error_name(stored.error().code)}});
    record(identity, ApplicationChannel::log, packet);
    return std::nullopt;
  }
  const auto cursor = root_.cursor();
  if (cursor.sequence == UINT64_MAX)
    throw Error{ErrorCode::overflow};
  const SourceReference reference{cursor.journal, cursor.sequence + 1};
  const auto source = std::as_bytes(std::span{raw.data(), raw.size()});
  RetainedEvent event{{reference},
                      ApplicationRecordEvent{identity, ApplicationChannel::log,
                                             unwrap(encode_packet(packet))}};
  (void)unwrap(root_.append(cursor, std::span{&source, 1}, std::span{&event, 1}));
  return reference;
}

// --- ContextStore ---

ContextStore::ContextStore(AuditLog &log) : ContextStore(log, ContextOpen{}) {}

ContextStore::ContextStore(AuditLog &log, ContextOpen open)
    : log_(log), root_lifetime_(log.root().lifetime()), open_(open),
      head_(hex_identity(log.root().journal_usage().prefix.journal.bytes())) {
  for (const auto &program : log_.root().current_programs()) {
    if (program.find("label") &&
        string_field(program, "label") == "context-format-level") {
      const auto level = parse_u64(field(program, "level"));
      if (level != format_level)
        throw Error{ErrorCode::unsupported, level_refused};
      format_level_written_ = true;
    }
  }
  const auto *saved = open_.whole_history ? nullptr : log_.root().saved_state();
  if (saved)
    load_from_snapshot(*saved);
  replay_facts(saved);
  if (!open_.probe) {
    log_.root().set_maintenance_checkpoint(
        [this](const RawEventRef &) { return checkpoint(); });
    if (!open_.defer_checkpoint)
      maybe_checkpoint();
  }
}

ContextStore::~ContextStore() {
  if (!open_.probe && !root_lifetime_.expired())
    log_.root().set_maintenance_checkpoint({});
}

void ContextStore::finish_open() {
  if (!open_.probe)
    maybe_checkpoint();
}

void ContextStore::load_from_snapshot(const SavedState &saved) {
  const auto &ctx = saved.context;
  if (!ctx.find("version") || parse_u64(field(ctx, "version")) != 3)
    throw Error{ErrorCode::unsupported, level_refused};
  head_ = string_field(ctx, "head");
  next_id_ = parse_u64(field(ctx, "next_id"));
  blocks_.clear();
  archived_.clear();
  for (const auto &b : field(ctx, "blocks").array())
    blocks_.push_back(decode_block(b));
  if (const auto *arch = ctx.find("archived")) {
    for (const auto &a : arch->array())
      archived_.push_back(decode_archived(a));
  }
}

void ContextStore::replay_facts(const SavedState *restored) {
  if (restored) {
    const auto &tail = log_.root().tail_facts();
    for (const auto &fact : tail) {
      if (fact.record.journal == restored->boundary.journal &&
          fact.record.sequence <= restored->boundary.sequence)
        continue;
      if (const auto *rec = std::get_if<ApplicationRecordEvent>(&fact.event.body);
          rec && rec->channel == ApplicationChannel::context)
        apply_record(*rec);
    }
    return;
  }
  const auto count = log_.root().fact_count();
  for (std::size_t i = 0; i < count; ++i) {
    const auto fact = unwrap(log_.root().fact(i));
    if (const auto *rec = std::get_if<ApplicationRecordEvent>(&fact.event.body);
        rec && rec->channel == ApplicationChannel::context)
      apply_record(*rec);
  }
}

void ContextStore::apply_record(const ApplicationRecordEvent &record) {
  const auto packet = unwrap(read_application_packet(record));
  const auto *v = packet.find("v");
  if (!v || parse_u64(*v) != 3)
    throw Error{ErrorCode::unsupported, level_refused};
  const auto &op = string_field(packet, "op");
  const auto rev = hex_identity(record.identity.bytes());

  if (op == "append") {
    Block b;
    b.id = parse_u64(field(packet, "id"));
    const auto kind = parse_block_kind(string_field(packet, "kind"));
    if (!kind)
      throw Error{ErrorCode::corrupt};
    b.kind = *kind;
    b.label = packet.find("label") ? string_field(packet, "label") : std::string{};
    b.items = field(packet, "items").array();
    b.bytes = measure_items_bytes(b.items);
    b.open = compute_open(b.items);
    b.records.push_back(record.identity.bytes());
    if (b.id >= next_id_)
      next_id_ = b.id + 1;
    blocks_.push_back(std::move(b));
    head_ = rev;
    return;
  }

  if (op == "extend") {
    const auto id = parse_u64(field(packet, "id"));
    const auto &added = field(packet, "items").array();
    auto it = std::find_if(blocks_.begin(), blocks_.end(),
                           [id](const Block &b) { return b.id == id; });
    if (it == blocks_.end())
      throw Error{ErrorCode::corrupt};
    for (const auto &item : added)
      it->items.push_back(item);
    it->bytes = measure_items_bytes(it->items);
    it->open = compute_open(it->items);
    it->records.push_back(record.identity.bytes());
    head_ = rev;
    return;
  }

  if (op == "compact") {
    std::set<std::uint64_t> drop_ids;
    for (const auto &d : field(packet, "drop").array())
      drop_ids.insert(parse_u64(d));
    std::optional<Block> summary_block;
    if (const auto *sum = packet.find("summary"); sum && *sum != Value{}) {
      Block s;
      s.id = parse_u64(field(*sum, "id"));
      s.kind = BlockKind::note;
      s.label = "summary";
      s.items = field(*sum, "items").array();
      s.bytes = measure_items_bytes(s.items);
      for (const auto &r : field(*sum, "replaces").array())
        s.replaces.push_back(parse_u64(r));
      s.records.push_back(record.identity.bytes());
      if (s.id >= next_id_)
        next_id_ = s.id + 1;
      summary_block = std::move(s);
    }
    std::vector<Block> next;
    next.reserve(blocks_.size());
    bool inserted = false;
    for (auto &b : blocks_) {
      if (drop_ids.contains(b.id)) {
        if (summary_block && !inserted) {
          next.push_back(std::move(*summary_block));
          inserted = true;
        }
        archived_.push_back(ArchivedBlock{
            .id = b.id,
            .records = std::move(b.records),
            .label = std::move(b.label),
            .preview = build_preview(b.items),
            .bytes = b.bytes,
            .kind = b.kind,
        });
      } else {
        next.push_back(std::move(b));
      }
    }
    if (summary_block && !inserted)
      next.push_back(std::move(*summary_block));
    blocks_.swap(next);
    head_ = rev;
    return;
  }

  if (op == "pin") {
    std::set<std::uint64_t> ids;
    for (const auto &d : field(packet, "ids").array())
      ids.insert(parse_u64(d));
    const bool pinned = std::get<bool>(field(packet, "pinned").value());
    for (auto &b : blocks_) {
      if (ids.contains(b.id))
        b.pinned = pinned;
    }
    head_ = rev;
    return;
  }

  if (op == "restore") {
    std::set<std::uint64_t> ids;
    for (const auto &d : field(packet, "ids").array())
      ids.insert(parse_u64(d));
    std::vector<ArchivedBlock> remaining;
    for (auto &a : archived_) {
      if (!ids.contains(a.id)) {
        remaining.push_back(std::move(a));
        continue;
      }
      auto loaded = load_block_items(a.id, a.records);
      if (!loaded)
        throw Error{ErrorCode::corrupt};
      Block restored;
      restored.id = a.id;
      restored.kind = a.kind;
      restored.label = std::move(a.label);
      restored.items = std::move(*loaded);
      restored.bytes = measure_items_bytes(restored.items);
      restored.open = compute_open(restored.items);
      restored.records = std::move(a.records);
      auto pos = std::find_if(blocks_.begin(), blocks_.end(),
                              [id = restored.id](const Block &b) { return b.id > id; });
      blocks_.insert(pos, std::move(restored));
    }
    archived_.swap(remaining);
    head_ = rev;
    return;
  }

  if (op == "replace") {
    std::vector<Block> next;
    std::set<std::uint64_t> kept_ids;
    for (const auto &bv : field(packet, "blocks").array()) {
      Block b = decode_block(bv);
      if (b.records.empty())
        b.records.push_back(record.identity.bytes());
      if (b.id >= next_id_)
        next_id_ = b.id + 1;
      kept_ids.insert(b.id);
      next.push_back(std::move(b));
    }
    // Archive any previously live block dropped by replace so originals remain
    // readable.
    for (auto &old : blocks_) {
      if (kept_ids.contains(old.id))
        continue;
      const bool already_archived =
          std::any_of(archived_.begin(), archived_.end(),
                      [id = old.id](const ArchivedBlock &a) { return a.id == id; });
      if (!already_archived) {
        archived_.push_back(ArchivedBlock{
            .id = old.id,
            .records = std::move(old.records),
            .label = std::move(old.label),
            .preview = build_preview(old.items),
            .bytes = old.bytes,
            .kind = old.kind,
        });
      }
    }
    blocks_.swap(next);
    head_ = rev;
    return;
  }

  throw Error{ErrorCode::corrupt};
}

std::optional<Value::Array>
ContextStore::load_block_items(std::uint64_t id,
                               const std::vector<IdentityBytes> &records) const {
  Value::Array combined;
  for (const auto &rec_id : records) {
    const auto fact =
        log_.root().lookup(log_.root().visible(), 1, RetainedKind::application, rec_id);
    if (!fact)
      return std::nullopt;
    const auto *app = std::get_if<ApplicationRecordEvent>(&fact->event.body);
    if (!app || app->channel != ApplicationChannel::context)
      return std::nullopt;
    const auto packet = unwrap(read_application_packet(*app));
    const auto &op = string_field(packet, "op");
    if (op == "append" || op == "extend") {
      if (parse_u64(field(packet, "id")) != id)
        return std::nullopt;
      for (const auto &item : field(packet, "items").array())
        combined.push_back(item);
    } else if (op == "compact") {
      const auto *sum = packet.find("summary");
      if (!sum || *sum == Value{} || parse_u64(field(*sum, "id")) != id)
        return std::nullopt;
      for (const auto &item : field(*sum, "items").array())
        combined.push_back(item);
    } else if (op == "replace") {
      bool found = false;
      for (const auto &bv : field(packet, "blocks").array()) {
        if (parse_u64(field(bv, "id")) == id) {
          for (const auto &item : field(bv, "items").array())
            combined.push_back(item);
          found = true;
          break;
        }
      }
      if (!found)
        return std::nullopt;
    } else {
      return std::nullopt;
    }
  }
  return combined;
}

void ContextStore::write_format_level() {
  if (format_level_written_)
    return;
  log_.record(ApplicationChannel::program,
              Value::object({{"label", Value{"context-format-level"}},
                             {"level", Value{Number{format_level}}}}));
  format_level_written_ = true;
}

Result<void> ContextStore::checkpoint() {
  try {
    Value::Array live;
    live.reserve(blocks_.size());
    for (const auto &b : blocks_)
      live.push_back(encode_block(b));
    Value::Array arch;
    arch.reserve(archived_.size());
    for (const auto &a : archived_)
      arch.push_back(encode_archived(a));
    auto saved = Value::object({{"version", Value{Number{3}}},
                                {"head", Value{head_}},
                                {"next_id", Value{Number{next_id_}}},
                                {"blocks", Value{std::move(live)}},
                                {"archived", Value{std::move(arch)}}});
    auto result = log_.root().save_current_state(saved);
    checkpoint_error_ =
        result.has_value() ? std::nullopt : std::optional<Error>{result.error()};
    return result;
  } catch (const Error &error) {
    checkpoint_error_ = error;
    return Result<void>::failure(error);
  } catch (const std::bad_alloc &) {
    checkpoint_error_ = Error{ErrorCode::allocation};
    return Result<void>::failure(*checkpoint_error_);
  } catch (...) {
    checkpoint_error_ = Error{ErrorCode::external_unknown};
    return Result<void>::failure(*checkpoint_error_);
  }
}

void ContextStore::maybe_checkpoint() {
  const auto *saved = log_.root().saved_state();
  const auto cursor = log_.root().cursor();
  if (!head_.empty() &&
      (!saved || cursor.sequence - saved->boundary.sequence >= 64 ||
       cursor.end_offset - saved->boundary.end_offset >= 4 * 1024 * 1024))
    (void)checkpoint();
}

void ContextStore::notify_changed(ContextChangeKind kind, std::string_view mode,
                                  std::uint64_t before_bytes,
                                  std::uint64_t after_bytes) const {
  if (!changed)
    return;
  try {
    changed(ContextChange{.revision = head_,
                          .mode = std::string{mode},
                          .bytes_before = static_cast<std::size_t>(before_bytes),
                          .bytes_after = static_cast<std::size_t>(after_bytes),
                          .kind = kind});
  } catch (...) {
  }
}

std::uint64_t ContextStore::total_bytes() const noexcept {
  std::uint64_t total = 0;
  for (const auto &b : blocks_)
    total += b.bytes;
  return total;
}

Value::Array ContextStore::items() const {
  Value::Array out;
  for (const auto &b : blocks_) {
    for (const auto &item : b.items)
      out.push_back(item);
  }
  return out;
}

bool ContextStore::has_open_exchanges() const noexcept {
  return std::any_of(blocks_.begin(), blocks_.end(),
                     [](const Block &b) { return b.open; });
}

std::uint64_t ContextStore::append(Value::Array items, std::string_view label,
                                   std::optional<BlockKind> declared) {
  if (items.empty())
    return 0;
  write_format_level();

  // If all appended items are function_call_outputs matching an open exchange block,
  // fold them directly into that exchange block so calls & outputs stay one unit.
  if (!declared.has_value() &&
      std::all_of(items.begin(), items.end(), item_is_output)) {
    std::set<std::string> output_ids;
    for (const auto &it : items) {
      if (const auto cid = item_call_id(it))
        output_ids.emplace(*cid);
    }
    if (!output_ids.empty()) {
      for (auto it = blocks_.rbegin(); it != blocks_.rend(); ++it) {
        if (!it->open)
          continue;
        const auto missing = unanswered_calls(it->items);
        bool matches_all = true;
        for (const auto &oid : output_ids) {
          if (std::find(missing.begin(), missing.end(), oid) == missing.end()) {
            matches_all = false;
            break;
          }
        }
        if (matches_all) {
          const auto identity = log_.issue();
          auto packet = Value::object({{"v", Value{Number{3}}},
                                       {"op", Value{"extend"}},
                                       {"id", Value{Number{it->id}}},
                                       {"label", Value{std::string{label}}},
                                       {"items", Value{items}}});
          (void)log_.record(identity, ApplicationChannel::context, packet);
          for (auto &item : items)
            it->items.push_back(std::move(item));
          it->bytes = measure_items_bytes(it->items);
          it->open = compute_open(it->items);
          it->records.push_back(identity.bytes());
          head_ = hex_identity(identity.bytes());
          maybe_checkpoint();
          return it->id;
        }
      }
    }
  }

  const auto id = next_id_;
  const auto kind = infer_kind(items, label, declared);
  const auto identity = log_.issue();
  auto packet = Value::object({{"v", Value{Number{3}}},
                               {"op", Value{"append"}},
                               {"id", Value{Number{id}}},
                               {"kind", Value{std::string{block_kind_name(kind)}}},
                               {"label", Value{std::string{label}}},
                               {"items", Value{items}}});
  (void)log_.record(identity, ApplicationChannel::context, packet);
  Block b;
  b.id = id;
  b.kind = kind;
  b.label = std::string{label};
  b.bytes = measure_items_bytes(items);
  b.open = compute_open(items);
  b.items = std::move(items);
  b.records.push_back(identity.bytes());
  blocks_.push_back(std::move(b));
  next_id_ = id + 1;
  head_ = hex_identity(identity.bytes());
  maybe_checkpoint();
  return id;
}

std::size_t ContextStore::close_open_exchanges(bool interrupted) {
  std::size_t closed = 0;
  for (auto &b : blocks_) {
    if (!b.open)
      continue;
    const auto missing = unanswered_calls(b.items);
    if (missing.empty()) {
      b.open = false;
      continue;
    }
    Value::Array synthetic;
    synthetic.reserve(missing.size());
    for (const auto &cid : missing) {
      synthetic.push_back(Value::object(
          {{"type", Value{"function_call_output"}},
           {"call_id", Value{cid}},
           {"output",
            Value::object(
                {{"error", Value{interrupted ? "turn_interrupted" : "turn_stopped"}},
                 {"message",
                  Value{interrupted ? "Turn interrupted before tool call completed."
                                    : "Turn stopped before tool call completed; "
                                      "outcome unknown."}}})}}));
    }
    RetainedState::MaintenanceScope maintenance{log_.root()};
    write_format_level();
    const auto identity = log_.issue();
    auto packet = Value::object({{"v", Value{Number{3}}},
                                 {"op", Value{"extend"}},
                                 {"id", Value{Number{b.id}}},
                                 {"label", Value{"stop.linkage"}},
                                 {"items", Value{synthetic}}});
    (void)log_.record(identity, ApplicationChannel::context, packet);
    for (auto &item : synthetic)
      b.items.push_back(std::move(item));
    b.bytes = measure_items_bytes(b.items);
    b.open = false;
    b.records.push_back(identity.bytes());
    head_ = hex_identity(identity.bytes());
    closed += missing.size();
  }
  return closed;
}

Value ContextStore::compact(const CompactRequest &request) {
  const auto target_ids = expand_target_ids(request, blocks_, archived_);
  if (target_ids.empty()) {
    return Value::object({{"ok", Value{false}},
                          {"op", Value{std::string{compact_op_name(request.op)}}},
                          {"reason", Value{"no-matching-blocks"}}});
  }
  if (request.op == CompactOp::summarize && request.summary.empty())
    throw Error{ErrorCode::invalid_range};

  const auto bytes_before = total_bytes();

  if (request.op == CompactOp::pin || request.op == CompactOp::unpin) {
    const bool pin_value = request.op == CompactOp::pin;
    Value::Array affected, skipped;
    std::vector<std::uint64_t> matched;
    for (const auto id : target_ids) {
      auto it = std::find_if(blocks_.begin(), blocks_.end(),
                             [id](const Block &b) { return b.id == id; });
      if (it == blocks_.end()) {
        skipped.push_back(
            Value::object({{"id", Value{Number{id}}}, {"reason", Value{"not_found"}}}));
        continue;
      }
      matched.push_back(id);
      affected.push_back(Value{Number{id}});
    }
    if (!matched.empty()) {
      write_format_level();
      const auto identity = log_.issue();
      auto packet = Value::object({{"v", Value{Number{3}}},
                                   {"op", Value{"pin"}},
                                   {"ids", Value{affected}},
                                   {"pinned", Value{pin_value}}});
      (void)log_.record(identity, ApplicationChannel::context, packet);
      for (auto &b : blocks_) {
        if (std::find(matched.begin(), matched.end(), b.id) != matched.end())
          b.pinned = pin_value;
      }
      head_ = hex_identity(identity.bytes());
      maybe_checkpoint();
    }
    std::size_t total_pinned = 0;
    for (const auto &b : blocks_) {
      if (b.pinned)
        ++total_pinned;
    }
    return Value::object({{"ok", Value{!matched.empty()}},
                          {"op", Value{std::string{compact_op_name(request.op)}}},
                          {"affected", Value{std::move(affected)}},
                          {"skipped", Value{std::move(skipped)}},
                          {"pinned_count", Value{Number{total_pinned}}}});
  }

  if (request.op == CompactOp::restore) {
    Value::Array affected, skipped;
    std::set<std::uint64_t> to_restore;
    for (const auto id : target_ids) {
      const bool already_live = std::any_of(
          blocks_.begin(), blocks_.end(), [id](const Block &b) { return b.id == id; });
      if (already_live) {
        skipped.push_back(Value::object(
            {{"id", Value{Number{id}}}, {"reason", Value{"already_live"}}}));
        continue;
      }
      const bool in_archive =
          std::any_of(archived_.begin(), archived_.end(),
                      [id](const ArchivedBlock &a) { return a.id == id; });
      if (!in_archive) {
        skipped.push_back(
            Value::object({{"id", Value{Number{id}}}, {"reason", Value{"not_found"}}}));
        continue;
      }
      to_restore.insert(id);
      affected.push_back(Value{Number{id}});
    }
    if (to_restore.empty()) {
      return Value::object({{"ok", Value{false}},
                            {"op", Value{"restore"}},
                            {"affected", Value{Value::Array{}}},
                            {"skipped", Value{std::move(skipped)}}});
    }
    // Load originals before writing the journal record so an I/O failure leaves state
    // clean.
    std::vector<Block> loaded_blocks;
    for (const auto &a : archived_) {
      if (!to_restore.contains(a.id))
        continue;
      auto loaded = load_block_items(a.id, a.records);
      if (!loaded)
        throw Error{ErrorCode::corrupt};
      Block b;
      b.id = a.id;
      b.kind = a.kind;
      b.label = a.label;
      b.items = std::move(*loaded);
      b.bytes = measure_items_bytes(b.items);
      b.open = compute_open(b.items);
      b.records = a.records;
      loaded_blocks.push_back(std::move(b));
    }
    write_format_level();
    const auto identity = log_.issue();
    auto packet = Value::object(
        {{"v", Value{Number{3}}}, {"op", Value{"restore"}}, {"ids", Value{affected}}});
    (void)log_.record(identity, ApplicationChannel::context, packet);
    std::erase_if(archived_,
                  [&](const ArchivedBlock &a) { return to_restore.contains(a.id); });
    for (auto &b : loaded_blocks) {
      auto pos = std::find_if(blocks_.begin(), blocks_.end(),
                              [id = b.id](const Block &cur) { return cur.id > id; });
      blocks_.insert(pos, std::move(b));
    }
    head_ = hex_identity(identity.bytes());
    maybe_checkpoint();
    const auto bytes_after = total_bytes();
    notify_changed(ContextChangeKind::restored, "restore", bytes_before, bytes_after);
    return Value::object({{"ok", Value{true}},
                          {"op", Value{"restore"}},
                          {"affected", Value{std::move(affected)}},
                          {"skipped", Value{std::move(skipped)}},
                          {"bytes_before", Value{Number{bytes_before}}},
                          {"bytes_after", Value{Number{bytes_after}}}});
  }

  // drop or summarize
  Value::Array affected, skipped;
  std::set<std::uint64_t> drop_ids;
  for (const auto id : target_ids) {
    auto it = std::find_if(blocks_.begin(), blocks_.end(),
                           [id](const Block &b) { return b.id == id; });
    if (it == blocks_.end()) {
      skipped.push_back(
          Value::object({{"id", Value{Number{id}}}, {"reason", Value{"not_found"}}}));
      continue;
    }
    if (it->open) {
      skipped.push_back(
          Value::object({{"id", Value{Number{id}}}, {"reason", Value{"open"}}}));
      continue;
    }
    if (it->pinned) {
      skipped.push_back(
          Value::object({{"id", Value{Number{id}}}, {"reason", Value{"pinned"}}}));
      continue;
    }
    if (it->kind == BlockKind::instruction) {
      skipped.push_back(
          Value::object({{"id", Value{Number{id}}}, {"reason", Value{"instruction"}}}));
      continue;
    }
    drop_ids.insert(id);
    affected.push_back(Value{Number{id}});
  }
  if (drop_ids.empty()) {
    return Value::object({{"ok", Value{false}},
                          {"op", Value{std::string{compact_op_name(request.op)}}},
                          {"affected", Value{Value::Array{}}},
                          {"skipped", Value{std::move(skipped)}}});
  }

  write_format_level();
  const auto identity = log_.issue();
  std::optional<Block> summary_block;
  Value summary_packet{};
  if (request.op == CompactOp::summarize) {
    Block s;
    s.id = next_id_;
    s.kind = BlockKind::note;
    s.label = "summary";
    s.items = {Value::object(
        {{"role", Value{"developer"}}, {"content", Value{request.summary}}})};
    s.bytes = measure_items_bytes(s.items);
    for (const auto id : drop_ids)
      s.replaces.push_back(id);
    s.records.push_back(identity.bytes());
    summary_packet = Value::object({{"id", Value{Number{s.id}}},
                                    {"items", Value{s.items}},
                                    {"replaces", Value{affected}}});
    summary_block = std::move(s);
  }
  auto packet = Value::object({{"v", Value{Number{3}}},
                               {"op", Value{"compact"}},
                               {"drop", Value{affected}},
                               {"summary", summary_packet}});
  (void)log_.record(identity, ApplicationChannel::context, packet);

  std::optional<std::uint64_t> summary_id;
  if (summary_block) {
    summary_id = summary_block->id;
    next_id_ = summary_block->id + 1;
  }
  std::vector<Block> next;
  next.reserve(blocks_.size());
  bool inserted = false;
  for (auto &b : blocks_) {
    if (drop_ids.contains(b.id)) {
      if (summary_block && !inserted) {
        next.push_back(std::move(*summary_block));
        inserted = true;
      }
      archived_.push_back(ArchivedBlock{
          .id = b.id,
          .records = std::move(b.records),
          .label = std::move(b.label),
          .preview = build_preview(b.items),
          .bytes = b.bytes,
          .kind = b.kind,
      });
    } else {
      next.push_back(std::move(b));
    }
  }
  if (summary_block && !inserted)
    next.push_back(std::move(*summary_block));
  blocks_.swap(next);
  head_ = hex_identity(identity.bytes());
  maybe_checkpoint();

  const auto bytes_after = total_bytes();
  notify_changed(ContextChangeKind::managed, compact_op_name(request.op), bytes_before,
                 bytes_after);
  Value::Object out{{"ok", Value{true}},
                    {"op", Value{std::string{compact_op_name(request.op)}}},
                    {"affected", Value{std::move(affected)}},
                    {"skipped", Value{std::move(skipped)}},
                    {"bytes_before", Value{Number{bytes_before}}},
                    {"bytes_after", Value{Number{bytes_after}}}};
  if (summary_id)
    out.emplace_back("summary_id", Value{Number{*summary_id}});
  return Value::object(std::move(out));
}

Value ContextStore::replace_blocks(const Value &blocks_value) {
  if (!std::holds_alternative<Value::Array>(blocks_value.value()))
    throw Error{ErrorCode::invalid_range};
  const auto bytes_before = total_bytes();
  std::vector<Block> next;
  std::set<std::uint64_t> seen_ids;
  std::uint64_t max_id = next_id_;
  for (const auto &entry : blocks_value.array()) {
    if (!std::holds_alternative<Value::Object>(entry.value()))
      throw Error{ErrorCode::invalid_range};
    Block b;
    if (const auto *idv = entry.find("id")) {
      b.id = parse_u64(*idv);
      if (b.id == 0)
        throw Error{ErrorCode::invalid_range};
    } else {
      b.id = max_id++;
    }
    if (!seen_ids.insert(b.id).second)
      throw Error{ErrorCode::conflict};
    if (b.id >= max_id)
      max_id = b.id + 1;
    if (const auto *kv = entry.find("kind")) {
      const auto parsed = parse_block_kind(kv->string());
      if (!parsed)
        throw Error{ErrorCode::invalid_range};
      b.kind = *parsed;
    } else {
      b.kind = BlockKind::note;
    }
    if (const auto *pv = entry.find("pinned"))
      b.pinned = std::get<bool>(pv->value());
    if (const auto *lv = entry.find("label"))
      b.label = lv->string();
    const auto &items_v = field(entry, "items");
    if (!std::holds_alternative<Value::Array>(items_v.value()))
      throw Error{ErrorCode::invalid_range};
    b.items = items_v.array();
    b.bytes = measure_items_bytes(b.items);
    b.open = compute_open(b.items);
    // Preserve original journal records when keeping an existing ID unchanged.
    for (const auto &old : blocks_) {
      if (old.id == b.id && old.items == b.items) {
        b.records = old.records;
        break;
      }
    }
    next.push_back(std::move(b));
  }
  write_format_level();
  const auto identity = log_.issue();
  Value::Array encoded_blocks;
  encoded_blocks.reserve(next.size());
  for (auto &b : next) {
    if (b.records.empty())
      b.records.push_back(identity.bytes());
    encoded_blocks.push_back(encode_block(b));
  }
  auto packet = Value::object({{"v", Value{Number{3}}},
                               {"op", Value{"replace"}},
                               {"blocks", Value{std::move(encoded_blocks)}}});
  (void)log_.record(identity, ApplicationChannel::context, packet);
  for (auto &old : blocks_) {
    if (seen_ids.contains(old.id))
      continue;
    const bool already =
        std::any_of(archived_.begin(), archived_.end(),
                    [id = old.id](const ArchivedBlock &a) { return a.id == id; });
    if (!already) {
      archived_.push_back(ArchivedBlock{
          .id = old.id,
          .records = std::move(old.records),
          .label = std::move(old.label),
          .preview = build_preview(old.items),
          .bytes = old.bytes,
          .kind = old.kind,
      });
    }
  }
  blocks_.swap(next);
  next_id_ = max_id;
  head_ = hex_identity(identity.bytes());
  maybe_checkpoint();
  const auto bytes_after = total_bytes();
  notify_changed(ContextChangeKind::edited, "replace", bytes_before, bytes_after);
  return Value::object({{"ok", Value{true}},
                        {"live_blocks", Value{Number{blocks_.size()}}},
                        {"bytes_before", Value{Number{bytes_before}}},
                        {"bytes_after", Value{Number{bytes_after}}}});
}

Value ContextStore::list(bool include_archived) const {
  Value::Array live;
  live.reserve(blocks_.size());
  for (const auto &b : blocks_) {
    Value::Object obj{{"id", Value{Number{b.id}}},
                      {"kind", Value{std::string{block_kind_name(b.kind)}}},
                      {"pinned", Value{b.pinned}},
                      {"open", Value{b.open}},
                      {"bytes", Value{Number{b.bytes}}},
                      {"items", Value{Number{b.items.size()}}},
                      {"preview", Value{build_preview(b.items)}}};
    if (!b.replaces.empty()) {
      Value::Array rep;
      for (const auto r : b.replaces)
        rep.push_back(Value{Number{r}});
      obj.emplace_back("replaces", Value{std::move(rep)});
    }
    live.push_back(Value::object(std::move(obj)));
  }
  Value::Object out{{"total_bytes", Value{Number{total_bytes()}}},
                    {"live_blocks", Value{Number{blocks_.size()}}},
                    {"archived_blocks", Value{Number{archived_.size()}}},
                    {"blocks", Value{std::move(live)}}};
  if (include_archived) {
    Value::Array arch;
    arch.reserve(archived_.size());
    for (const auto &a : archived_) {
      arch.push_back(
          Value::object({{"id", Value{Number{a.id}}},
                         {"kind", Value{std::string{block_kind_name(a.kind)}}},
                         {"bytes", Value{Number{a.bytes}}},
                         {"preview", Value{a.preview}}}));
    }
    out.emplace_back("archived", Value{std::move(arch)});
  }
  return Value::object(std::move(out));
}

Value ContextStore::read_block(std::uint64_t id, ReadBlockOptions options) const {
  if (options.limit == 0 || options.limit > 65536)
    throw Error{ErrorCode::invalid_range};
  bool is_archived = false;
  BlockKind kind = BlockKind::note;
  std::optional<Value::Array> items;
  for (const auto &b : blocks_) {
    if (b.id == id) {
      kind = b.kind;
      items = b.items;
      break;
    }
  }
  if (!items) {
    for (const auto &a : archived_) {
      if (a.id == id) {
        is_archived = true;
        kind = a.kind;
        items = load_block_items(a.id, a.records);
        break;
      }
    }
  }
  if (!items)
    throw Error{ErrorCode::invalid_range};
  const auto serialized = unwrap(dump_json(Value{*items}));
  const auto total = serialized.size();
  const auto start = std::min(options.offset, total);
  const auto len = std::min(options.limit, total - start);
  const auto next_offset = start + len;
  return Value::object({{"id", Value{Number{id}}},
                        {"kind", Value{std::string{block_kind_name(kind)}}},
                        {"archived", Value{is_archived}},
                        {"total_bytes", Value{Number{total}}},
                        {"offset", Value{Number{start}}},
                        {"next_offset", Value{Number{next_offset}}},
                        {"truncated", Value{next_offset < total}},
                        {"content", Value{serialized.substr(start, len)}}});
}

Value ContextStore::stats() const {
  std::size_t item_count = 0;
  for (const auto &b : blocks_)
    item_count += b.items.size();
  return Value::object({{"revision", Value{head_}},
                        {"live_blocks", Value{Number{blocks_.size()}}},
                        {"archived_blocks", Value{Number{archived_.size()}}},
                        {"item_count", Value{Number{item_count}}},
                        {"input_bytes", Value{Number{total_bytes()}}},
                        {"units", Value{"native binary packet bytes; not tokens"}}});
}

bool ContextStore::live_origin(std::string_view label) const {
  return std::any_of(blocks_.begin(), blocks_.end(),
                     [label](const Block &b) { return b.label == label; });
}

bool ContextStore::live_instruction(const Value &item) const {
  const auto needle = sort_keys(item);
  for (const auto &b : blocks_) {
    if (b.kind != BlockKind::instruction)
      continue;
    for (const auto &cur : b.items) {
      if (sort_keys(cur) == needle)
        return true;
    }
  }
  return false;
}

void ContextStore::validate_successor_seed(const Value &seed) {
  if (!std::holds_alternative<Value::Object>(seed.value()))
    throw Error{ErrorCode::invalid_range};
  const auto &blocks = field(seed, "blocks");
  if (!std::holds_alternative<Value::Array>(blocks.value()) || blocks.array().empty())
    throw Error{ErrorCode::invalid_range};
  for (const auto &b : blocks.array()) {
    if (!std::holds_alternative<Value::Object>(b.value()) || !b.find("items") ||
        !std::holds_alternative<Value::Array>(field(b, "items").value()))
      throw Error{ErrorCode::invalid_range};
  }
}

void ContextStore::seed_successor(const Value &seed) {
  validate_successor_seed(seed);
  if (!blocks_.empty())
    throw Error{ErrorCode::conflict};
  for (const auto &b : field(seed, "blocks").array()) {
    std::optional<BlockKind> kind;
    if (const auto *kv = b.find("kind");
        kv && std::holds_alternative<std::string>(kv->value()))
      kind = parse_block_kind(kv->string());
    const auto label = b.find("label") && std::holds_alternative<std::string>(
                                              field(b, "label").value())
                           ? string_field(b, "label")
                           : std::string{"seed.instruction"};
    (void)append(field(b, "items").array(), label, kind);
  }
}

} // namespace blackbird
