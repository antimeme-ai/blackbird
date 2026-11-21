#include "blackbird/next_turns.hpp"
#include "blackbird/context.hpp"
#include <algorithm>
#include <charconv>

namespace blackbird {
namespace {
constexpr std::size_t byte_limit = 1024 * 1024;
std::size_t number(const Value &v) {
  const auto text = v.number().text();
  std::size_t out = 0;
  const auto r = std::from_chars(text.data(), text.data() + text.size(), out);
  if (r.ec != std::errc{} || r.ptr != text.data() + text.size())
    throw Error{ErrorCode::invalid_range};
  return out;
}
// Conservative owned-memory accounting includes metadata, keys and revision nodes,
// not only text. Bounds also fence the binary UI-state projection/recovery size.
std::size_t metadata_bytes(const Value &value) {
  std::size_t out = 64;
  if (const auto *text = std::get_if<std::string>(&value.value()))
    out += text->size();
  else if (const auto *array = std::get_if<Value::Array>(&value.value()))
    for (const auto &entry : *array)
      out += metadata_bytes(entry);
  else if (const auto *object = std::get_if<Value::Object>(&value.value()))
    for (const auto &[key, entry] : *object)
      out += key.size() + metadata_bytes(entry);
  return out;
}
std::size_t bytes(const NextTurns::Item &item) {
  std::size_t out = sizeof(item) + item.id.size() + item.route.size() +
                    item.observed_route.size() + item.predecessor.size() +
                    item.previous_state.size() + item.context_entry.size() +
                    item.context_revision.size();
  for (const auto &revision : item.revisions)
    out += sizeof(revision) + revision.text->size();
  if (item.edit)
    out += item.edit->size(); // conservative if currently sharing submitted text
  for (const auto &request : item.requests)
    out += metadata_bytes(request);
  return out;
}
std::size_t bytes(const std::vector<NextTurns::Item> &items) {
  std::size_t out = 0;
  for (const auto &item : items)
    out += bytes(item);
  return out;
}
std::size_t remaining(const std::vector<NextTurns::Item> &items,
                      std::size_t excluded = 0) {
  const auto used = bytes(items);
  if (excluded > used || used - excluded > byte_limit)
    throw Error{ErrorCode::capacity};
  return byte_limit - (used - excluded);
}
} // namespace
std::string_view NextTurns::label(State state) {
  switch (state) {
  case State::acquired:
    return "sending locally";
  case State::queued:
    return "queued · next turn";
  case State::held:
    return "held";
  case State::editing:
    return "held · editing";
  case State::starting:
    return "starting";
  case State::completed:
    return "completed";
  case State::failed:
    return "failed";
  case State::interrupted:
    return "interrupted locally";
  case State::local:
    return "local command";
  case State::withdrawn:
    return "withdrawn · draft retained";
  case State::recovered:
    return "recovered · explicit Send required";
  }
  return "unavailable";
}
NextTurns::Item &NextTurns::find(std::string_view id) {
  const auto it = std::find_if(items_.begin(), items_.end(),
                               [&](const auto &item) { return item.id == id; });
  if (it == items_.end())
    throw Error{ErrorCode::invalid_identity};
  return *it;
}
NextTurns::Item &NextTurns::pending(std::string_view id, std::size_t revision) {
  auto &item = find(id);
  if (item.revision() != revision ||
      (item.state != State::queued && item.state != State::held &&
       item.state != State::editing))
    throw Error{ErrorCode::conflict};
  return item;
}
void NextTurns::acquire(std::string id, std::string text, std::string route,
                        RawUiSource source, std::string predecessor) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  if (id.empty() || std::any_of(items_.begin(), items_.end(),
                                [&](const auto &item) { return item.id == id; }))
    throw Error{ErrorCode::invalid_identity};
  if (items_.size() >= 256)
    throw Error{ErrorCode::capacity};
  Item item;
  item.id = std::move(id);
  item.route = std::move(route);
  item.predecessor = std::move(predecessor);
  item.revisions.push_back(
      {std::make_shared<const std::string>(std::move(text)), source});
  if (bytes(item) > remaining(items_))
    throw Error{ErrorCode::capacity};
  items_.push_back(std::move(item));
}
NextTurns::Item NextTurns::get(std::string_view id) const {
  const std::lock_guard lock{mutex_};
  const auto it = std::find_if(items_.begin(), items_.end(),
                               [&](const auto &item) { return item.id == id; });
  if (it == items_.end())
    throw Error{ErrorCode::invalid_identity};
  return *it;
}
std::vector<NextTurns::Item> NextTurns::snapshot() const {
  const std::lock_guard lock{mutex_};
  return items_;
}
void NextTurns::route(std::string_view id, std::string route) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = find(id);
  if (route.size() > remaining(items_, item.observed_route.size()))
    throw Error{ErrorCode::capacity};
  item.observed_route = std::move(route);
}
void NextTurns::context(std::string_view id, std::string entry, std::string revision) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = find(id);
  if (entry.size() + revision.size() >
      remaining(items_, item.context_entry.size() + item.context_revision.size()))
    throw Error{ErrorCode::capacity};
  item.context_entry = std::move(entry);
  item.context_revision = std::move(revision);
}
void NextTurns::request(const std::string &revision,
                        const std::vector<std::string> &entries,
                        const std::string &attempt) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  const auto observation = Value::object(
      {{"context_revision", Value{revision}},
       {"attempt", Value{attempt}},
       {"included", Value{false}},
       {"scope",
        Value{"local provider attempt commitment; remote disposition unknown"}}});
  const auto cost = metadata_bytes(observation);
  auto available = remaining(items_);
  // Preflight every related receipt before changing any: capacity refusal cannot
  // leave a subset labeled as committed while dispatch is refused.
  for (const auto &item : items_) {
    if (item.context_entry.empty())
      continue;
    if (item.requests.size() >= 256 || cost > available)
      throw Error{ErrorCode::capacity};
    available -= cost;
  }
  for (auto &item : items_) {
    if (item.context_entry.empty())
      continue; // No relation, not inferred omission/delivery.
    auto record = observation;
    for (auto &[key, value] : record.object())
      if (key == "included")
        value = Value{std::find(entries.begin(), entries.end(), item.context_entry) !=
                      entries.end()};
    item.requests.push_back(std::move(record));
  }
}
void NextTurns::queue(std::string_view id) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = find(id);
  if (item.state != State::acquired && item.state != State::local)
    throw Error{ErrorCode::conflict};
  item.state = State::queued;
}
void NextTurns::local(std::string_view id) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  find(id).state = State::local;
}
void NextTurns::hold_all() {
  const std::lock_guard lock{mutex_};
  ++generation_;
  for (auto &item : items_)
    if (item.state == State::queued)
      item.state = State::held;
}
void NextTurns::hold(std::string_view id, std::size_t revision) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = pending(id, revision);
  if (item.state != State::editing)
    item.state = State::held;
}
std::uint64_t NextTurns::edit(std::string_view id, std::size_t revision) {
  const std::lock_guard lock{mutex_};
  auto &item = pending(id, revision);
  if (!item.edit) {
    if (item.current().text->size() > remaining(items_))
      throw Error{ErrorCode::capacity};
    item.edit = item.current().text;
    item.edit_version = ++generation_;
  }
  item.state = State::editing;
  return item.edit_version;
}
std::uint64_t NextTurns::buffer(std::string_view id, std::size_t revision,
                                std::string text, std::uint64_t edit_version) {
  const std::lock_guard lock{mutex_};
  auto &item = pending(id, revision);
  if (item.state != State::editing || !item.edit || item.edit_version != edit_version)
    throw Error{ErrorCode::conflict};
  if (*item.edit == text)
    return item.edit_version;
  if (text.size() > remaining(items_, item.edit->size()))
    throw Error{ErrorCode::capacity};
  item.edit = std::make_shared<const std::string>(std::move(text));
  item.edit_version = ++generation_;
  return item.edit_version;
}
void NextTurns::apply(std::string_view id, EditGuard guard, RawUiSource source) {
  const std::lock_guard lock{mutex_};
  auto &item = pending(id, guard.revision);
  if (item.state != State::editing || !item.edit || item.edit_version != guard.version)
    throw Error{ErrorCode::conflict};
  if (sizeof(Revision) > remaining(items_))
    throw Error{ErrorCode::capacity};
  item.revisions.push_back({item.edit, source});
  item.edit.reset();
  item.state = State::held;
  ++generation_;
}
void NextTurns::discard(std::string_view id, EditGuard guard) {
  const std::lock_guard lock{mutex_};
  auto &item = pending(id, guard.revision);
  if (item.edit && item.edit_version != guard.version)
    throw Error{ErrorCode::conflict};
  item.edit.reset();
  item.state = State::held;
  ++generation_;
}
void NextTurns::release(std::string_view id, std::size_t revision) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = pending(id, revision);
  if (item.dirty())
    throw Error{ErrorCode::conflict}; // Apply or discard edits first
  item.edit.reset();
  item.state = State::queued;
}
void NextTurns::withdraw(std::string_view id, std::size_t revision) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = pending(id, revision);
  if (item.dirty())
    throw Error{ErrorCode::conflict};
  item.edit.reset();
  item.state = State::withdrawn; // bytes stay owned; no removal/save gap
}
NextTurns::Item NextTurns::launch(std::string_view id, LaunchGuard guard) {
  const std::lock_guard lock{mutex_};
  if (guard.require_saved && generation_ != persisted_)
    throw Error{ErrorCode::conflict};
  auto &item = pending(id, guard.revision);
  if (item.state != State::queued || item.edit)
    throw Error{ErrorCode::conflict};
  // Prepare the returned snapshot before mutating the dispatch authority.
  auto out = item;
  ++generation_;
  item.state = out.state = State::starting;
  item.turn = out.turn = guard.turn;
  return out;
}
void NextTurns::recovery_loaded(std::string_view id) {
  const std::lock_guard lock{mutex_};
  find(id).recovery_loaded = true;
  ++generation_;
}
void NextTurns::launch_refused(std::string_view id) {
  const std::lock_guard lock{mutex_};
  auto &item = find(id);
  if (item.state != State::starting)
    throw Error{ErrorCode::conflict};
  item.state = State::held;
  item.previous_state = "not started: worker launch refused";
  ++generation_;
}
void NextTurns::result(std::string_view id, State state) {
  const std::lock_guard lock{mutex_};
  ++generation_;
  auto &item = find(id);
  if (item.state != State::starting ||
      (state != State::completed && state != State::failed &&
       state != State::interrupted))
    throw Error{ErrorCode::conflict};
  item.state = state;
}
NextTurns::Save NextTurns::checkpoint() const {
  std::vector<Item> rows;
  std::uint64_t generation;
  {
    const std::lock_guard lock{mutex_};
    rows = items_;
    generation = generation_;
  }
  Value::Array out;
  for (const auto &item : rows) {
    Value::Array revisions;
    for (const auto &revision : item.revisions)
      revisions.emplace_back(*revision.text);
    out.push_back(Value::object({{"id", Value{item.id}},
                                 {"route", Value{item.route}},
                                 {"observed_route", Value{item.observed_route}},
                                 {"context_entry", Value{item.context_entry}},
                                 {"context_revision", Value{item.context_revision}},
                                 {"requests", Value{item.requests}},
                                 {"predecessor", Value{item.predecessor}},
                                 {"recovery_loaded", Value{item.recovery_loaded}},
                                 {"revisions", Value{std::move(revisions)}},
                                 {"state", Value{std::string{label(item.state)}}},
                                 {"previous_state", Value{item.previous_state}},
                                 {"turn", Value{Number{item.turn}}},
                                 {"edit_version", Value{Number{item.edit_version}}},
                                 {"edit", item.edit ? Value{*item.edit} : Value{}}}));
  }
  return {Value{std::move(out)}, generation};
}
void NextTurns::saved_generation(std::uint64_t generation) {
  const std::lock_guard lock{mutex_};
  if (generation > generation_)
    throw Error{ErrorCode::conflict};
  persisted_ = generation;
}
Value NextTurns::saved() const { return checkpoint().data; }
Value NextTurns::view() const {
  auto out = saved();
  for (auto &item : out.array()) {
    item.object().emplace_back("revision",
                               Value{Number{field(item, "revisions").array().size()}});
    item.object().emplace_back("inclusion",
                               Value{field(item, "requests").array().empty()
                                         ? "unavailable"
                                         : "see keyed local attempts; remote unknown"});
  }
  return out;
}
void NextTurns::restore(const Value &value) {
  std::vector<Item> restored;
  for (const auto &row : value.array()) {
    Item item;
    item.id = string_field(row, "id");
    item.route = string_field(row, "route");
    if (const auto *route = row.find("observed_route"))
      item.observed_route = route->string();
    item.predecessor = string_field(row, "predecessor");
    if (const auto *loaded = row.find("recovery_loaded"))
      item.recovery_loaded = std::get<bool>(loaded->value());
    if (const auto *entry = row.find("context_entry"))
      item.context_entry = entry->string();
    if (const auto *revision = row.find("context_revision"))
      item.context_revision = revision->string();
    if (const auto *requests = row.find("requests")) {
      if (requests->array().size() > 256)
        throw Error{ErrorCode::capacity};
      item.requests = requests->array();
    }
    if (item.id.empty() ||
        std::any_of(restored.begin(), restored.end(),
                    [&](const auto &prior) { return prior.id == item.id; }))
      throw Error{ErrorCode::corrupt};
    for (const auto &revision : field(row, "revisions").array())
      item.revisions.push_back(
          {std::make_shared<const std::string>(revision.string()), {}});
    if (item.revisions.empty())
      throw Error{ErrorCode::corrupt};
    if (!std::holds_alternative<std::nullptr_t>(field(row, "edit").value()))
      item.edit = std::make_shared<const std::string>(field(row, "edit").string());
    item.turn = number(field(row, "turn"));
    if (const auto *version = row.find("edit_version"))
      item.edit_version = number(*version);
    item.previous_state = string_field(row, "state");
    item.state = State::recovered;
    for (const auto terminal : {State::completed, State::failed, State::interrupted,
                                State::local, State::withdrawn})
      if (label(terminal) == item.previous_state)
        item.state = terminal;
    restored.push_back(std::move(item));
    if (restored.size() > 256 || bytes(restored) > byte_limit)
      throw Error{ErrorCode::capacity};
  }
  const std::lock_guard lock{mutex_};
  ++generation_;
  items_ = std::move(restored);
}
} // namespace blackbird
