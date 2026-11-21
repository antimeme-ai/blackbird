#pragma once
#include "blackbird/raw_ui.hpp"
#include "blackbird/value.hpp"
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace blackbird {
// Native owner. Payload revisions are immutable and shared by snapshots; a
// projection never clones the retained history. ID is supplied by Send's owner.
class NextTurns {
public:
  enum class State {
    acquired,
    queued,
    held,
    editing,
    starting,
    completed,
    failed,
    interrupted,
    local,
    withdrawn,
    recovered
  };
  struct Revision {
    std::shared_ptr<const std::string> text;
    RawUiSource source{};
  };
  struct Item {
    std::string id, route, observed_route, predecessor, previous_state, context_entry,
        context_revision;
    Value::Array requests;
    std::vector<Revision> revisions;
    State state = State::acquired;
    bool recovery_loaded = false;
    std::shared_ptr<const std::string> edit;
    std::uint64_t turn = 0, edit_version = 0;
    std::size_t revision() const { return revisions.size(); }
    const Revision &current() const { return revisions.back(); }
    bool dirty() const { return edit && *edit != *current().text; }
  };
  void acquire(std::string id, std::string text, std::string route,
               RawUiSource source = {}, std::string predecessor = {});
  Item get(std::string_view id) const;
  std::vector<Item> snapshot() const;
  void queue(std::string_view id);
  void route(std::string_view id, std::string route);
  void context(std::string_view id, std::string entry, std::string revision);
  void request(const std::string &revision, const std::vector<std::string> &entries,
               const std::string &attempt);
  void local(std::string_view id);
  void hold_all();
  void hold(std::string_view id, std::size_t revision);
  std::uint64_t edit(std::string_view id, std::size_t revision);
  std::uint64_t buffer(std::string_view id, std::size_t revision, std::string text,
                       std::uint64_t edit_version);
  struct EditGuard {
    std::size_t revision;
    std::uint64_t version;
  };
  void apply(std::string_view id, EditGuard guard, RawUiSource source = {});
  void discard(std::string_view id, EditGuard guard);
  void release(std::string_view id, std::size_t revision);
  void withdraw(std::string_view id, std::size_t revision);
  // Atomic against correction/hold/stop. A launch winner is never editable.
  struct LaunchGuard {
    std::size_t revision;
    std::uint64_t turn;
    bool require_saved = false;
  };
  Item launch(std::string_view id, LaunchGuard guard);
  void result(std::string_view id, State state);
  void launch_refused(std::string_view id);
  void recovery_loaded(std::string_view id);
  Value view() const;
  struct Save {
    Value data;
    std::uint64_t generation;
  };
  Save checkpoint() const;
  void saved_generation(std::uint64_t generation);
  Value saved() const;
  void restore(const Value &value); // recover only; never restores runnable work
  static std::string_view label(State state);

private:
  Item &find(std::string_view id);
  Item &pending(std::string_view id, std::size_t revision);
  mutable std::mutex mutex_;
  std::vector<Item> items_;
  std::uint64_t generation_ = 0, persisted_ = 0;
};
} // namespace blackbird
