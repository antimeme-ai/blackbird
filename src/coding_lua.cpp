#include "blackbird/command_post_tools.hpp"
#include "blackbird/json.hpp"
#include "blackbird/packet.hpp"
#include "blackbird/raw_authored.hpp"
#include "blackbird/raw_bridge.hpp"
#include "blackbird/raw_runtime.hpp"
#include "coding_internal.hpp"
extern "C" {
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
}
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <limits>

namespace blackbird {
using coding_detail::raw_native;
using coding_detail::raw_text;
namespace {
enum class ValueTag { array, object, number, null };
char markers[4]; // array, object, exact number, null (registry keys, no string
                 // allocation).
void tag(lua_State *L, ValueTag kind) {
  lua_rawgetp(L, LUA_REGISTRYINDEX, &markers[static_cast<int>(kind)]);
  lua_setmetatable(L, -2);
}
bool tagged(lua_State *L, int index, ValueTag kind) {
  if (!lua_getmetatable(L, index))
    return false;
  lua_rawgetp(L, LUA_REGISTRYINDEX, &markers[static_cast<int>(kind)]);
  const bool equal = lua_rawequal(L, -1, -2) != 0;
  lua_pop(L, 2);
  return equal;
}
void push_value(lua_State *L, const Value &j) {
  std::visit(
      [&](const auto &v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::nullptr_t>) {
          lua_newtable(L);
          tag(L, ValueTag::null);
        } else if constexpr (std::is_same_v<T, bool>)
          lua_pushboolean(L, v);
        else if constexpr (std::is_same_v<T, std::string>)
          lua_pushlstring(L, v.data(), v.size());
        else if constexpr (std::is_same_v<T, Number>) {
          std::visit(
              [&](const auto &n) {
                using N = std::decay_t<decltype(n)>;
                if constexpr (std::is_same_v<N, std::int64_t>)
                  lua_pushinteger(L, n);
                else if constexpr (std::is_same_v<N, double>)
                  lua_pushnumber(L, n);
                else if constexpr (std::is_same_v<N, std::uint64_t>) {
                  if (n <= static_cast<std::uint64_t>(INT64_MAX))
                    lua_pushinteger(L, static_cast<lua_Integer>(n));
                  else {
                    lua_createtable(L, 3, 0);
                    lua_pushinteger(L, 0);
                    lua_rawseti(L, -2, 1);
                    lua_pushinteger(L, static_cast<lua_Integer>(n & 0xffffffff));
                    lua_rawseti(L, -2, 2);
                    lua_pushinteger(L, static_cast<lua_Integer>(n >> 32));
                    lua_rawseti(L, -2, 3);
                    tag(L, ValueTag::number);
                  }
                } else {
                  lua_createtable(L, 4, 0);
                  lua_pushinteger(L, 1);
                  lua_rawseti(L, -2, 1);
                  lua_pushboolean(L, n.negative);
                  lua_rawseti(L, -2, 2);
                  lua_pushinteger(L, n.exponent);
                  lua_rawseti(L, -2, 3);
                  lua_createtable(
                      L,
                      static_cast<int>(std::min<std::size_t>(n.limbs.size(), INT_MAX)),
                      0);
                  for (std::size_t i = 0; i < n.limbs.size(); ++i) {
                    lua_pushinteger(L, n.limbs[i]);
                    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
                  }
                  lua_rawseti(L, -2, 4);
                  tag(L, ValueTag::number);
                }
              },
              v.storage());
        } else if constexpr (std::is_same_v<T, Value::Array>) {
          lua_newtable(L);
          for (std::size_t i = 0; i < v.size(); ++i) {
            push_value(L, v[i]);
            lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
          }
          tag(L, ValueTag::array);
        } else {
          lua_newtable(L);
          for (const auto &[key, value] : v) {
            lua_pushlstring(L, key.data(), key.size());
            push_value(L, value);
            lua_rawset(L, -3);
          }
          tag(L, ValueTag::object);
        }
      },
      j.value());
}
std::string lua_string(lua_State *L, int index) {
  if (lua_type(L, index) != LUA_TSTRING)
    throw Error{ErrorCode::invalid_range};
  std::size_t length = 0;
  const char *value = lua_tolstring(L, index, &length);
  return {value, length};
}
// Caller reserves the full traversal stack first. Only raw, nonallocating Lua
// reads occur while C++ owners exist; no metamethods/string-key interning here.
struct ValueRead {
  std::size_t depth;
  std::size_t *nodes;
};
Value read_value(lua_State *L, int index, ValueRead budget) {
  const auto depth = budget.depth;
  auto &nodes = *budget.nodes;
  if (depth > 128 || ++nodes > 500000)
    throw Error{ErrorCode::capacity};
  index = lua_absindex(L, index);
  switch (lua_type(L, index)) {
  case LUA_TNIL:
    return Value{};
  case LUA_TBOOLEAN:
    return Value{lua_toboolean(L, index) != 0};
  case LUA_TSTRING:
    return Value{lua_string(L, index)};
  case LUA_TNUMBER:
    return lua_isinteger(L, index) ? Value{Number{lua_tointeger(L, index)}}
                                   : Value{Number{lua_tonumber(L, index)}};
  case LUA_TTABLE: {
    if (tagged(L, index, ValueTag::null))
      return Value{};
    if (tagged(L, index, ValueTag::number)) {
      auto integer = [&](lua_Integer field) {
        lua_rawgeti(L, index, field);
        if (!lua_isinteger(L, -1))
          throw Error{ErrorCode::invalid_range};
        const auto n = lua_tointeger(L, -1);
        lua_pop(L, 1);
        return n;
      };
      const auto kind = integer(1);
      if (kind == 0) {
        const auto low = integer(2), high = integer(3);
        if (low < 0 || high < 0 || low > UINT32_MAX || high > UINT32_MAX)
          throw Error{ErrorCode::invalid_range};
        return Value{Number{static_cast<std::uint64_t>(low) |
                            (static_cast<std::uint64_t>(high) << 32)}};
      }
      if (kind != 1)
        throw Error{ErrorCode::invalid_range};
      lua_rawgeti(L, index, 2);
      if (lua_type(L, -1) != LUA_TBOOLEAN)
        throw Error{ErrorCode::invalid_range};
      const bool negative = lua_toboolean(L, -1) != 0;
      lua_pop(L, 1);
      Decimal n{negative, integer(3), {}};
      lua_rawgeti(L, index, 4);
      if (lua_type(L, -1) != LUA_TTABLE)
        throw Error{ErrorCode::invalid_range};
      const auto count = lua_rawlen(L, -1);
      if (!count || count > 500000 - nodes)
        throw Error{ErrorCode::capacity};
      nodes += count;
      n.limbs.reserve(count);
      for (std::size_t i = 1; i <= count; ++i) {
        lua_rawgeti(L, -1, static_cast<lua_Integer>(i));
        const auto limb = lua_tointeger(L, -1);
        if (!lua_isinteger(L, -1) || limb < 0 || limb >= 1000000000)
          throw Error{ErrorCode::invalid_range};
        n.limbs.push_back(static_cast<std::uint32_t>(limb));
        lua_pop(L, 1);
      }
      lua_pop(L, 1);
      return Value{Number{std::move(n)}};
    }
    const auto length = lua_rawlen(L, index);
    const bool array = tagged(L, index, ValueTag::array) ||
                       (!tagged(L, index, ValueTag::object) && length != 0);
    if (array) {
      std::size_t count = 0;
      lua_pushnil(L);
      while (lua_next(L, index)) {
        if (!lua_isinteger(L, -2) || lua_tointeger(L, -2) < 1 ||
            static_cast<unsigned long long>(lua_tointeger(L, -2)) > length)
          throw Error{ErrorCode::invalid_range};
        ++count;
        lua_pop(L, 1);
      }
      if (count != length)
        throw Error{ErrorCode::invalid_range};
      Value::Array values;
      values.reserve(length);
      for (std::size_t i = 0; i < length; ++i) {
        lua_rawgeti(L, index, static_cast<lua_Integer>(i + 1));
        values.push_back(read_value(L, -1, {depth + 1, &nodes}));
        lua_pop(L, 1);
      }
      return Value{std::move(values)};
    }
    Value::Object fields;
    lua_pushnil(L);
    while (lua_next(L, index)) {
      auto key = lua_string(L, -2);
      auto value = read_value(L, -1, {depth + 1, &nodes});
      fields.emplace_back(std::move(key), std::move(value));
      lua_pop(L, 1);
    }
    std::sort(fields.begin(), fields.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    return Value::object(std::move(fields));
  }
  default:
    throw Error{ErrorCode::unsupported};
  }
}
} // namespace

struct CodingEngine::Runtime::Impl {
  CodingEngine &engine;
  struct Trace {
    RawThreadHandle handle;
    RawAuthoredOwner owner;
    std::optional<RawControlToken> setup;
    RawAuthoredReference installation;
    explicit Trace(CodingEngine &engine)
        : handle(raw_current_thread()),
          owner{engine.generation_.bytes(), {}, raw_enabled(), {}} {}
    void begin(const std::optional<SourceReference> &source, std::size_t length) {
      if (!owner.enabled)
        return;
      setup.emplace(unwrap(raw_claim_control(175)));
      const bool available = source.has_value();
      if (available) {
        const std::array fields{ByteView{owner.generation},
                                ByteView{source->journal.bytes()},
                                raw_native(source->sequence), raw_native(length)};
        (void)raw_authored_publish(1505, fields);
        const std::array request{ByteView{owner.generation}, raw_native(available),
                                 ByteView{source->journal.bytes()},
                                 raw_native(source->sequence)};
        owner.vm = raw_authored_publish(1500, request);
      } else {
        const std::array request{ByteView{owner.generation}, raw_native(available)};
        owner.vm = raw_authored_publish(1500, request);
      }
    }
    void allocated(bool created) {
      const std::uint8_t outcome = created ? 1 : 0;
      const std::array fields{ByteView{owner.vm.lane}, raw_native(owner.vm.ordinal),
                              raw_native(outcome)};
      (void)raw_authored_publish(1501, fields, setup ? &*setup : nullptr);
    }
    void installing() {
      const std::array fields{ByteView{owner.vm.lane}, raw_native(owner.vm.ordinal)};
      installation = raw_authored_publish(1502, fields, setup ? &*setup : nullptr);
    }
    void installed(int lua_status) {
      const std::array fields{ByteView{installation.lane},
                              raw_native(installation.ordinal), raw_native(lua_status)};
      (void)raw_authored_publish(1503, fields, setup ? &*setup : nullptr);
    }
    void finish(std::uint8_t branch, std::optional<Error> caught_error = {}) noexcept {
      if (!setup.has_value() || owner.vm.ordinal == 0) {
        setup.reset();
        return;
      }
      if (owner.admission_failure.has_value())
        caught_error = owner.admission_failure;
      try {
        if (caught_error.has_value()) {
          const std::array fields{ByteView{owner.vm.lane}, raw_native(owner.vm.ordinal),
                                  raw_native(branch), raw_native(caught_error->code),
                                  raw_native(caught_error->detail)};
          (void)raw_authored_publish(1504, fields, &*setup);
        } else {
          const std::array fields{ByteView{owner.vm.lane}, raw_native(owner.vm.ordinal),
                                  raw_native(branch)};
          (void)raw_authored_publish(1504, fields, &*setup);
        }
      } catch (const Error &failure) {
        raw_fence(failure);
      }
      setup.reset();
    }
  } trace;
  static_assert(sizeof(lua_Integer) == 8 &&
                std::numeric_limits<lua_Integer>::is_signed &&
                std::is_same_v<lua_Number, double> && sizeof(int) == 4);
  struct Loaded {
    int lua_status;
    RawAuthoredReference reference;
  };
  Loaded load(lua_State *L, std::string_view source, const char *name, SourceKind kind,
              RawControlToken *credit) {
    if (!trace.owner.enabled)
      return {luaL_loadbufferx(L, source.data(), source.size(), name, "t"), {}};
    const auto length = source.size();
    const std::array requested{ByteView{trace.owner.vm.lane},
                               raw_native(trace.owner.vm.ordinal), raw_native(kind),
                               raw_native(length), raw_text(source)};
    const auto request = raw_authored_publish(1506, requested);
    const int lua_status = luaL_loadbufferx(L, source.data(), length, name, "t");
    const bool available = lua_status == LUA_OK;
    if (available) {
      const void *function = lua_topointer(L, -1);
      const std::array fields{ByteView{request.lane}, raw_native(request.ordinal),
                              raw_native(lua_status), raw_native(available),
                              raw_native(function)};
      (void)raw_authored_publish(1507, fields, credit);
    } else {
      const std::array fields{ByteView{request.lane}, raw_native(request.ordinal),
                              raw_native(lua_status), raw_native(available)};
      (void)raw_authored_publish(1507, fields, credit);
    }
    return {lua_status, request};
  }
  void acquisition_failed(Error why) noexcept {
    if (why.code == ErrorCode::interrupted || why.code == ErrorCode::audit_unavailable)
      trace.owner.admission_failure = why;
  }
  std::optional<RawControlToken> claim(std::uint64_t bytes) {
    if (!trace.owner.enabled)
      return {};
    if (trace.owner.admission_failure.has_value())
      throw *trace.owner.admission_failure;
    auto result = raw_claim_control(bytes);
    if (!result.has_value()) {
      trace.owner.admission_failure = result.error();
      throw result.error();
    }
    return std::move(result).value();
  }
  int load_and_call(lua_State *L, std::string_view source, const char *name,
                    SourceKind kind, int results) {
    auto credit = claim(161);
    try {
      const auto loaded = load(L, source, name, kind, credit ? &*credit : nullptr);
      if (loaded.lua_status != LUA_OK)
        return loaded.lua_status;
      if (!trace.owner.enabled) {
        failure.reset();
        return lua_pcall(L, 0, results, 0);
      }
      const std::array fields{
          ByteView{trace.owner.vm.lane}, raw_native(trace.owner.vm.ordinal),
          ByteView{loaded.reference.lane}, raw_native(loaded.reference.ordinal)};
      const auto request =
          raw_authored_publish(1508, fields, credit ? &*credit : nullptr);
      failure.reset();
      const int lua_status = lua_pcall(L, 0, results, 0);
      const std::array returned{ByteView{request.lane}, raw_native(request.ordinal),
                                raw_native(lua_status)};
      (void)raw_authored_publish(1509, returned, credit ? &*credit : nullptr);
      return lua_status;
    } catch (const Error &why) {
      acquisition_failed(why);
      throw;
    }
  }
  int validation_load(std::string_view source, const char *name) {
    auto credit = claim(53);
    try {
      return load(state, source, name, SourceKind::validation,
                  credit ? &*credit : nullptr)
          .lua_status;
    } catch (const Error &why) {
      acquisition_failed(why);
      throw;
    }
  }
  inline static char authored_error_tag;
  static int authored_error_text(lua_State *L) {
    const auto *why = static_cast<const Error *>(lua_touserdata(L, 1));
    lua_pushstring(L, error_name(why->code));
    return 1;
  }
  static int authored_raise(lua_State *L, Error why) {
    auto *stored = static_cast<Error *>(lua_newuserdatauv(L, sizeof(Error), 0));
    std::construct_at(stored, why);
    lua_rawgetp(L, LUA_REGISTRYINDEX, &authored_error_tag);
    lua_setmetatable(L, -2);
    return lua_error(L);
  }
  static std::optional<Error> authored_error(lua_State *L, int index) noexcept {
    if (lua_type(L, index) != LUA_TUSERDATA || lua_rawlen(L, index) != sizeof(Error))
      return {};
    if (lua_getmetatable(L, index) == 0)
      return {};
    lua_rawgetp(L, LUA_REGISTRYINDEX, &authored_error_tag);
    const bool tagged = lua_rawequal(L, -1, -2) != 0;
    lua_pop(L, 2);
    if (!tagged)
      return {};
    return *static_cast<const Error *>(lua_touserdata(L, index));
  }
  static int authored(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    bool failed = false;
    Error rejected{ErrorCode::external_unknown};
    {
      auto admitted = raw_authored_admit(self->trace.owner);
      if (!admitted.has_value()) {
        rejected = admitted.error();
        failed = true;
      } else {
        auto credit = std::move(admitted).value();
        const int count = lua_gettop(L), site_type = lua_type(L, 1),
                  value_type = lua_type(L, 2);
        const bool site_available = lua_isinteger(L, 1) != 0;
        const lua_Integer site = site_available ? lua_tointeger(L, 1) : 0;
        try {
          if (count != 2 || !site_available || site <= 0)
            throw Error{ErrorCode::invalid_range};
          if (value_type != LUA_TNUMBER && value_type != LUA_TBOOLEAN &&
              value_type != LUA_TSTRING)
            throw Error{ErrorCode::unsupported};
          if (value_type == LUA_TSTRING) {
            std::size_t length = 0;
            const char *bytes = lua_tolstring(L, 2, &length);
            const std::array fields{ByteView{self->trace.owner.generation},
                                    ByteView{self->trace.owner.vm.lane},
                                    raw_native(self->trace.owner.vm.ordinal),
                                    raw_native(site),
                                    raw_native(length),
                                    std::as_bytes(std::span{bytes, length})};
            if (self->trace.owner.enabled)
              (void)raw_authored_publish(1513, fields);
          } else if (value_type == LUA_TBOOLEAN) {
            const int value = lua_toboolean(L, 2);
            const std::array fields{ByteView{self->trace.owner.generation},
                                    ByteView{self->trace.owner.vm.lane},
                                    raw_native(self->trace.owner.vm.ordinal),
                                    raw_native(site), raw_native(value)};
            if (self->trace.owner.enabled)
              (void)raw_authored_publish(1512, fields);
          } else if (lua_isinteger(L, 2)) {
            const lua_Integer value = lua_tointeger(L, 2);
            const std::array fields{ByteView{self->trace.owner.generation},
                                    ByteView{self->trace.owner.vm.lane},
                                    raw_native(self->trace.owner.vm.ordinal),
                                    raw_native(site), raw_native(value)};
            if (self->trace.owner.enabled)
              (void)raw_authored_publish(1510, fields);
          } else {
            const lua_Number value = lua_tonumber(L, 2);
            const std::array fields{ByteView{self->trace.owner.generation},
                                    ByteView{self->trace.owner.vm.lane},
                                    raw_native(self->trace.owner.vm.ordinal),
                                    raw_native(site), raw_native(value)};
            if (self->trace.owner.enabled)
              (void)raw_authored_publish(1511, fields);
          }
        } catch (const Error &caught_error) {
          if (credit.has_value()) {
            try {
              if (site_available) {
                const std::array fields{ByteView{self->trace.owner.generation},
                                        ByteView{self->trace.owner.vm.lane},
                                        raw_native(self->trace.owner.vm.ordinal),
                                        raw_native(count),
                                        raw_native(site_type),
                                        raw_native(value_type),
                                        raw_native(site_available),
                                        raw_native(site),
                                        raw_native(caught_error.code),
                                        raw_native(caught_error.detail)};
                (void)raw_authored_publish(1515, fields, &*credit);
              } else {
                const std::array fields{ByteView{self->trace.owner.generation},
                                        ByteView{self->trace.owner.vm.lane},
                                        raw_native(self->trace.owner.vm.ordinal),
                                        raw_native(count),
                                        raw_native(site_type),
                                        raw_native(value_type),
                                        raw_native(site_available),
                                        raw_native(caught_error.code),
                                        raw_native(caught_error.detail)};
                (void)raw_authored_publish(1515, fields, &*credit);
              }
            } catch (const Error &ingest) {
              raw_fence(ingest);
            }
          }
          if (caught_error.code == ErrorCode::interrupted ||
              caught_error.code == ErrorCode::audit_unavailable)
            self->trace.owner.admission_failure = caught_error;
          rejected = caught_error;
          failed = true;
        }
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    return 0;
  }
  static int module_load(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    luaL_checktype(L, 1, LUA_TSTRING);
    luaL_checktype(L, 2, LUA_TSTRING);
    luaL_checktype(L, 3, LUA_TTABLE);
    int lua_status = LUA_ERRRUN;
    bool failed = false;
    Error rejected{ErrorCode::external_unknown};
    RawAuthoredReference loaded_source{};
    auto *token = current_module(L);
    {
      RawCaptureFailureScope capture{self->trace.owner.enabled};
      try {
        auto credit = self->claim(53);
        std::size_t length = 0;
        const char *source = lua_tolstring(L, 1, &length);
        std::size_t name_size = 0;
        const char *name = lua_tolstring(L, 2, &name_size);
        if (token)
          token->chunk({name, name_size}, {name, std::strlen(name) + 1});
        capture.require();
        const auto loaded = self->load(L, {source, length}, name, SourceKind::module,
                                       credit ? &*credit : nullptr);
        lua_status = loaded.lua_status;
        loaded_source = loaded.reference;
        if (token)
          (void)token->event({4824, 3}, std::array{ByteView{loaded_source.lane},
                                                   raw_native(loaded_source.ordinal)});
        capture.require();
      } catch (const Error &caught_error) {
        self->acquisition_failed(caught_error);
        rejected = caught_error;
        failed = true;
      } catch (const std::bad_alloc &) {
        rejected = {ErrorCode::allocation};
        failed = true;
      } catch (...) {
        rejected = {ErrorCode::external_unknown};
        failed = true;
      }
      if (capture.error()) {
        self->trace.owner.admission_failure = *capture.error();
        if (token)
          token->failed(*capture.error());
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    if (lua_status != LUA_OK) {
      lua_pushnil(L);
      lua_insert(L, -2);
      return 2;
    }
    {
      RawCaptureFailureScope capture{self->trace.owner.enabled};
      try {
        const int index = 1;
        const void *function = lua_topointer(L, -1), *environment = lua_topointer(L, 3);
        const auto assignment =
            token ? token->event({4830, 4},
                                 std::array{ByteView{loaded_source.lane},
                                            raw_native(loaded_source.ordinal),
                                            raw_native(function),
                                            raw_native(environment), raw_native(index)})
                  : RawEventRef{};
        capture.require();
        lua_pushvalue(L, 3);
        const char *name = lua_setupvalue(L, -2, index);
        const bool present = name != nullptr;
        if (token && present) {
          const auto size = std::strlen(name) + 1;
          if (size > 5) {
            raw_capture_failed({ErrorCode::overflow});
            throw Error{ErrorCode::overflow};
          }
          (void)token->linked(4831, assignment,
                              std::array{raw_native(present), raw_native(size),
                                         std::as_bytes(std::span{name, size})});
        } else if (token)
          (void)token->linked(4831, assignment, std::array{raw_native(present)});
        capture.require();
      } catch (const Error &why) {
        rejected = why;
        failed = true;
      } catch (...) {
        rejected = {ErrorCode::external_unknown};
        failed = true;
      }
      if (capture.error()) {
        self->trace.owner.admission_failure = *capture.error();
        if (token)
          token->failed(*capture.error());
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    return 1;
  }
  static int module_call(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    luaL_checktype(L, 1, LUA_TFUNCTION);
    if (!lua_checkstack(L, 2))
      return luaL_error(L, "Module call stack exhausted");
    int lua_status = LUA_ERRRUN;
    bool failed = false;
    Error rejected{ErrorCode::external_unknown};
    auto *token = current_module(L);
    {
      RawCaptureFailureScope capture{self->trace.owner.enabled};
      try {
        auto credit = self->claim(92);
        const void *function =
            self->trace.owner.enabled ? lua_topointer(L, 1) : nullptr;
        const std::array fields{ByteView{self->trace.owner.vm.lane},
                                raw_native(self->trace.owner.vm.ordinal),
                                raw_native(function)};
        const auto request =
            self->trace.owner.enabled
                ? raw_authored_publish(1517, fields, credit ? &*credit : nullptr)
                : RawAuthoredReference{};
        if (token)
          (void)token->event({4834, 5}, std::array{ByteView{request.lane},
                                                   raw_native(request.ordinal),
                                                   raw_native(function)});
        capture.require();
        lua_pushvalue(L, 1);
        lua_status = lua_pcall(L, 0, 1, 0);
        if (token)
          token->inner_status(lua_status);
        const std::array returned{ByteView{request.lane}, raw_native(request.ordinal),
                                  raw_native(lua_status)};
        if (self->trace.owner.enabled)
          (void)raw_authored_publish(1518, returned, credit ? &*credit : nullptr);
      } catch (const Error &caught_error) {
        self->acquisition_failed(caught_error);
        rejected = caught_error;
        failed = true;
      } catch (const std::bad_alloc &) {
        rejected = {ErrorCode::allocation};
        failed = true;
      } catch (...) {
        rejected = {ErrorCode::external_unknown};
        failed = true;
      }
      if (capture.error()) {
        self->trace.owner.admission_failure = *capture.error();
        if (token)
          token->failed(*capture.error());
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    lua_pushboolean(L, lua_status == LUA_OK);
    lua_insert(L, -2);
    return 2;
  }
  lua_State *state = nullptr;
  std::string &error;
  std::optional<Error> failure;
  struct NativeExceptionFrame {
    std::exception_ptr primary;
  };
  NativeExceptionFrame *native_exception_frame = nullptr;
  struct ArgumentFrame {
    const Value *arguments = nullptr;
    int previous = LUA_NOREF;
    bool captured = false;
    std::uint8_t phase = 0;
  };
  ArgumentFrame *argument_frame = nullptr;
  bool argument_restore_failed = false;
  std::array<char, 512> bridge_error{};
  void failed(Error why, const char *message) noexcept {
    failure = why;
    if (why.code == ErrorCode::capacity)
      engine.capacity_stopped_ = true;
    const auto count = std::min(std::strlen(message), bridge_error.size() - 1);
    std::memcpy(bridge_error.data(), message, count);
    bridge_error[count] = '\0';
  }
  explicit Impl(CodingEngine &e, std::string &err) : engine(e), trace(e), error(err) {
    trace.begin(e.root_source_, e.root_source_length_);
    try {
      state = luaL_newstate();
      trace.allocated(state != nullptr);
      if (state == nullptr) {
        trace.finish(2, Error{ErrorCode::allocation});
        throw Error{ErrorCode::allocation};
      }
      *static_cast<Impl **>(lua_getextraspace(state)) = this;
      lua_sethook(state, interrupt_hook, LUA_MASKCOUNT, 1000);
      lua_pushcfunction(state, install);
      lua_pushlightuserdata(state, this);
      trace.installing();
      const int lua_status = lua_pcall(state, 1, 0, 0);
      trace.installed(lua_status);
      if (lua_status != LUA_OK) {
        lua_close(state);
        state = nullptr;
        const auto caught_error = failure.value_or(Error{ErrorCode::allocation});
        trace.finish(3, caught_error);
        throw caught_error;
      }
    } catch (const Error &caught) {
      if (state != nullptr) {
        lua_close(state);
        state = nullptr;
        trace.finish(1, caught);
      }
      throw;
    }
  }
  ~Impl() {
    std::optional<RawThreadBinding> retained;
    if (trace.handle)
      retained.emplace(trace.handle);
    if (module_issuer)
      module_issuer->closing.store(true);
    if (state != nullptr)
      lua_close(state);
    trace.finish(1);
  }
  enum Op {
    request_op,
    call_op,
    blocks_op,
    compact_op,
    read_block_op,
    set_blocks_op,
    append_op,
    decode_op,
    encode_op,
    display_op,
    array_op,
    present_op,
    restarting_op,
    stats_op,
    packet_decode_op,
    packet_encode_op,
    format_op,
    live_instruction_op,
    now_op,
    pin_op,
    flush_context_op,
    hooks_op,
    command_post_op
  };
  std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();
  static int lua_os_time(lua_State *L) {
    if (!lua_isnoneornil(L, 1))
      return luaL_error(L, "os.time table argument is not supported in sandbox");
    const auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    lua_pushinteger(L, static_cast<lua_Integer>(sec));
    return 1;
  }
  static int lua_os_clock(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    const auto elapsed = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - self->started_at)
                             .count();
    lua_pushnumber(L, elapsed);
    return 1;
  }
  static int lua_os_difftime(lua_State *L) {
    const lua_Number t2 = luaL_checknumber(L, 1);
    const lua_Number t1 = luaL_checknumber(L, 2);
    lua_pushnumber(L, t2 - t1);
    return 1;
  }
  static int install(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, 1));
    bool failed = false;
    {
      try {
        return install_impl(L);
      } catch (const Error &error) {
        self->failed(error, error_name(error.code));
        failed = true;
      } catch (const std::bad_alloc &) {
        self->failed({ErrorCode::allocation}, "allocation");
        failed = true;
      }
    }
    if (failed)
      return luaL_error(L, "VM installation failed");
    return 0;
  }
  static int install_impl(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, 1));
    lua_newtable(L);
    lua_newtable(L);
    lua_pushliteral(L, "k");
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);
    lua_rawsetp(L, LUA_REGISTRYINDEX, &module_current_key);
    lua_newtable(L);
    lua_pushcfunction(L, module_gc);
    lua_setfield(L, -2, "__gc");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, module_close, 1);
    lua_setfield(L, -2, "__close");
    lua_rawsetp(L, LUA_REGISTRYINDEX, &module_tag_key);
    lua_pushcfunction(L, create_module_userdata);
    lua_rawsetp(L, LUA_REGISTRYINDEX, &module_setup_key);
    lua_pushcfunction(L, prepare_native);
    lua_rawsetp(L, LUA_REGISTRYINDEX, &preparation_key);
    // Host effects go through the owned audit boundary, including module reads.
    const luaL_Reg libraries[] = {{LUA_GNAME, luaopen_base},
                                  {LUA_COLIBNAME, luaopen_coroutine},
                                  {LUA_TABLIBNAME, luaopen_table},
                                  {LUA_STRLIBNAME, luaopen_string},
                                  {LUA_MATHLIBNAME, luaopen_math},
                                  {LUA_UTF8LIBNAME, luaopen_utf8},
                                  {nullptr, nullptr}};
    for (const auto *library = libraries; library->name != nullptr; ++library) {
      luaL_requiref(L, library->name, library->func, 1);
      lua_pop(L, 1);
    }
    lua_pushnil(L);
    lua_setglobal(L, "dofile");
    lua_pushnil(L);
    lua_setglobal(L, "loadfile");
    // Safe read-only clock/time subset of `os`; zero shell/filesystem/env access.
    lua_newtable(L);
    lua_pushcfunction(L, lua_os_time);
    lua_setfield(L, -2, "time");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, lua_os_clock, 1);
    lua_setfield(L, -2, "clock");
    lua_pushcfunction(L, lua_os_difftime);
    lua_setfield(L, -2, "difftime");
    lua_setglobal(L, "os");
    for (int i = 0; i < 4; ++i) {
      lua_newtable(L);
      lua_rawsetp(L, LUA_REGISTRYINDEX, &markers[i]);
    }
    lua_newtable(L);
    lua_pushliteral(L, "authored native error");
    lua_setfield(L, -2, "__metatable");
    lua_pushcfunction(L, authored_error_text);
    lua_setfield(L, -2, "__tostring");
    lua_rawsetp(L, LUA_REGISTRYINDEX, &authored_error_tag);
    lua_newtable(L);
    constexpr const char *names[] = {
        "request",       "call",    "blocks",           "compact", "read_block",
        "set_blocks",    "append",  "decode",           "encode",  "display",
        "array",         "present", "restarting",       "stats",   "decode_packet",
        "encode_packet", "format",  "live_instruction", "now",     "pin",
        "flush_context", "hooks",   "command_post"};
    for (std::size_t i = 0; i < std::size(names); ++i) {
      lua_pushlightuserdata(L, self);
      lua_pushinteger(L, static_cast<lua_Integer>(i));
      lua_pushcclosure(L, bridge, 2);
      lua_setfield(L, -2, names[i]);
    }
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, authored, 1);
    lua_setfield(L, -2, "emit");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, module_load, 1);
    lua_setfield(L, -2, "_module_load");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, module_call, 1);
    lua_setfield(L, -2, "_module_call");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, module_begin, 1);
    lua_setfield(L, -2, "_module_begin");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, module_observe, 1);
    lua_setfield(L, -2, "_module_observe");
    lua_pushlightuserdata(L, self);
    lua_pushcclosure(L, module_end, 1);
    lua_setfield(L, -2, "_module_end");
    lua_rawgetp(L, LUA_REGISTRYINDEX, &module_current_key);
    lua_setfield(L, -2, "_module_current");
    lua_newtable(L);
    lua_getfield(L, -2, "decode");
    lua_setfield(L, -2, "decode");
    lua_getfield(L, -2, "encode");
    lua_setfield(L, -2, "encode");
    lua_setfield(L, -2, "json");
    lua_newtable(L);
    lua_getfield(L, -2, "decode_packet");
    lua_setfield(L, -2, "decode");
    lua_getfield(L, -2, "encode_packet");
    lua_setfield(L, -2, "encode");
    lua_setfield(L, -2, "binary");
    lua_pushvalue(L, -1);
    lua_setglobal(L, "blackbird");
    lua_setglobal(L, "arco"); // Compatibility alias for retained programs.
    constexpr const char *tool_api =
        "function blackbird.decide(args) return blackbird.call('decision_model',args) "
        "end "
        "function blackbird.colleague(q) return blackbird.call('colleague',q) end "
        "blackbird.participants={} "
        "for _,n in "
        "ipairs({'start','read','send','cancel','await','join','archive','configure'}) "
        "do "
        "blackbird.participants[n]=function(q) return "
        "blackbird.call('participant_'..n,q or {}) end end "
        "blackbird.process={} "
        "for _,op in "
        "ipairs({'read','foreground','background','input','resize','signal','stop','"
        "archive','configure'}) do "
        "local operation=op; blackbird.process[operation]=function(q) q=q or {}; "
        "q.op=operation; return blackbird.call('process',q) end end "
        "blackbird.tasks={} "
        "function blackbird.tasks.read(q) return blackbird.call('tasks_read',{query=q "
        "or {}}) end "
        "function blackbird.tasks.edit(q) return blackbird.call('tasks_edit',q) end "
        "function blackbird.define_tool(d) return blackbird.call('tool_define',"
        "{definition=d}) end "
        "for _,cp in "
        "ipairs({'platoon_board','bridge_guard','project_issues','project_memory','"
        "companion_timing'}) do "
        "local tool=cp; blackbird[tool]=function(...) return "
        "blackbird.command_post(tool,...) end end "
        "do local cache,loading={},{};local "
        "load_module,call_module,begin,observe,finish,current,protected,running="
        "blackbird._module_load,blackbird._module_call,blackbird._module_begin,"
        "blackbird._module_observe,blackbird._module_end,blackbird._module_current,"
        "pcall,coroutine.running; "
        "blackbird._module_load=nil;blackbird._module_call=nil;blackbird._module_begin="
        "nil;blackbird._module_observe=nil;blackbird._module_end=nil;blackbird._module_"
        "current=nil; "
        "local function import(name,token) "
        "local cached=cache[name];local hit=cached~=nil;observe(token,1,hit);if hit "
        "then return cached end "
        "local active=loading[name];observe(token,2,not not active);assert(not "
        "active,'cyclic module import: '..name); "
        "local r=blackbird.call('module_source',{name=name});assert(r.source,'module "
        "unavailable: '..name); "
        "local env=setmetatable({}, {__index=_G});local "
        "fn=assert(load_module(r.source,'@module:'..name..':'..r.revision,env)); "
        "loading[name]=true;observe(token,3,loading[name]);local "
        "ok,value=call_module(fn);"
        "loading[name]=nil;observe(token,4,loading[name]);if not ok then error(value) "
        "end;"
        "assert(value~=nil,'module must return a "
        "value');cache[name]=value;observe(token,5,cache[name]);return value end "
        "function blackbird.module(name) local key=running();local parent=current[key];"
        "local token <close> =begin(name,parent);if token==nil then return "
        "import(name,nil) end;current[key]=token;"
        "local "
        "ok,value=protected(import,name,token);current[key]=parent;finish(token,ok,"
        "value);"
        "if not ok then error(value) end;return value end end";
    if (self->load_and_call(L, tool_api, "tool-api", SourceKind::tool_api, 0) != LUA_OK)
      return lua_error(L);

    constexpr const char *print_program =
        "function print(...) local v={} for i=1,select('#',...) do "
        "v[i]=tostring(select(i,...)) end "
        "blackbird.display(table.concat(v,'\\t')..'\\n') end";
    if (self->load_and_call(L, print_program, "print-program", SourceKind::print, 0) !=
        LUA_OK)
      return lua_error(L);
    return 0;
  }
  struct ModuleUserdata {
    RawModuleToken *token = nullptr;
  };
  inline static char module_tag_key, module_current_key;
  std::shared_ptr<RawModuleIssuer> module_issuer;
  struct ModuleSetup {
    RawModuleToken *token;
    bool attached = false;
  };
  ModuleSetup *module_setup = nullptr;
  static ModuleUserdata *module_userdata(lua_State *L, int index) noexcept {
    if (lua_type(L, index) != LUA_TUSERDATA ||
        lua_rawlen(L, index) != sizeof(ModuleUserdata))
      return nullptr;
    if (!lua_getmetatable(L, index))
      return nullptr;
    lua_rawgetp(L, LUA_REGISTRYINDEX, &module_tag_key);
    const bool tagged = lua_rawequal(L, -1, -2) != 0;
    lua_pop(L, 2);
    return tagged ? static_cast<ModuleUserdata *>(lua_touserdata(L, index)) : nullptr;
  }
  static RawModuleToken *current_module(lua_State *L) noexcept {
    lua_rawgetp(L, LUA_REGISTRYINDEX, &module_current_key);
    lua_pushthread(L);
    lua_rawget(L, -2);
    auto *stored = module_userdata(L, -1);
    auto *token = stored ? stored->token : nullptr;
    lua_pop(L, 2);
    return token && token->active() ? token : nullptr;
  }
  static int module_gc(lua_State *L) {
    auto *self = *static_cast<Impl **>(lua_getextraspace(L));
    RawCaptureFailureScope capture{self->trace.owner.enabled};
    auto *stored = module_userdata(L, 1);
    if (stored && stored->token) {
      stored->token->finish(stored->token->closing() ? 2 : 1,
                            RawOperationBranch::unfinished);
      delete stored->token;
      stored->token = nullptr;
    }
    if (capture.error()) {
      self->trace.owner.admission_failure = *capture.error();
      self->failure = *capture.error();
    }
    return 0;
  }
  static int module_close(lua_State *L) {
    auto *self = *static_cast<Impl **>(lua_getextraspace(L));
    RawCaptureFailureScope capture{self->trace.owner.enabled};
    auto *stored = module_userdata(L, 1);
    if (!stored || !stored->token || !stored->token->active())
      return 0;
    lua_rawgetp(L, LUA_REGISTRYINDEX, &module_current_key);
    lua_getiuservalue(L, 1, 2);
    lua_rawget(L, -2);
    const bool current = lua_rawequal(L, 1, -1) != 0;
    lua_pop(L, 1);
    if (current) {
      lua_getiuservalue(L, 1, 2);
      lua_getiuservalue(L, 1, 1);
      lua_rawset(L, -3);
    }
    lua_pop(L, 1);
    const int type = lua_type(L, 2);
    const void *value = lua_topointer(L, 2);
    stored->token->finish(3, RawOperationBranch::unfinished, nullptr,
                          {.type = &type, .value = &value});
    if (capture.error()) {
      self->trace.owner.admission_failure = *capture.error();
      self->failure = *capture.error();
    }
    return 0;
  }
  static int create_module_userdata(lua_State *L) {
    auto *self = *static_cast<Impl **>(lua_getextraspace(L));
    auto *stored =
        static_cast<ModuleUserdata *>(lua_newuserdatauv(L, sizeof(ModuleUserdata), 2));
    stored->token = nullptr;
    lua_pushvalue(L, 1);
    lua_setiuservalue(L, -2, 1);
    lua_pushthread(L);
    lua_setiuservalue(L, -2, 2);
    lua_rawgetp(L, LUA_REGISTRYINDEX, &module_tag_key);
    lua_setmetatable(L, -2);
    stored->token = self->module_setup->token;
    self->module_setup->attached = true;
    return 1;
  }
  inline static char module_setup_key;
  static int module_begin(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    if (!self->trace.owner.enabled) {
      lua_pushnil(L);
      return 1;
    }
    bool failed = false;
    Error rejected{ErrorCode::external_unknown};
    {
      RawCaptureFailureScope capture{true};
      std::optional<RawModuleToken> paid;
      std::unique_ptr<RawModuleToken> token;
      RawModuleToken *offered = nullptr;
      RawOperationBranch outcome = RawOperationBranch::error;
      try {
        if (self->trace.owner.admission_failure)
          throw *self->trace.owner.admission_failure;
        if (!lua_checkstack(L, 8))
          throw Error{ErrorCode::allocation};
        if (!self->module_issuer)
          self->module_issuer = RawModuleIssuer::prepare();
        const auto vm = self->trace.owner.vm;
        const auto generation = self->trace.owner.generation;
        const int argc = lua_gettop(L), type = lua_type(L, 1);
        auto *parent = module_userdata(L, 2);
        const auto parent_ref = parent && parent->token && parent->token->active()
                                    ? parent->token->reference()
                                    : RawEventRef{};
        const bool parent_present = parent_ref.ordinal != 0;
        const auto operation = self->engine.operation_trace_
                                   ? self->engine.operation_trace_->reference()
                                   : RawEventRef{};
        const bool operation_present = operation.ordinal != 0;
        std::array<ByteView, 12> fields{};
        std::size_t count = 0;
        fields[count++] = vm.lane;
        fields[count++] = raw_native(vm.ordinal);
        fields[count++] = generation;
        fields[count++] = raw_native(argc);
        fields[count++] = raw_native(type);
        fields[count++] = raw_native(parent_present);
        if (parent_present) {
          fields[count++] = parent_ref.lane;
          fields[count++] = raw_native(parent_ref.ordinal);
        }
        fields[count++] = raw_native(operation_present);
        if (operation_present) {
          fields[count++] = operation.lane;
          fields[count++] = raw_native(operation.ordinal);
        }
        std::optional<std::string_view> name;
        if (type == LUA_TSTRING) {
          std::size_t size = 0;
          const char *text = lua_tolstring(L, 1, &size);
          name = std::string_view{text, size};
        }
        paid.emplace(self->module_issuer, std::span{fields}.first(count), name);
        capture.require();
        token = std::make_unique<RawModuleToken>(std::move(*paid));
        offered = token.get();
        const auto mode = std::uint8_t{3};
        const int base = lua_gettop(L);
        const auto request =
            offered->event({4832, 1}, std::array{raw_native(mode), raw_native(base)});
        capture.require();
        ModuleSetup setup{offered};
        auto *previous = self->module_setup;
        self->module_setup = &setup;
        struct Restore {
          ModuleSetup *&current;
          ModuleSetup *previous;
          ~Restore() { current = previous; }
        } restore{self->module_setup, previous};
        lua_rawgetp(L, LUA_REGISTRYINDEX, &module_setup_key);
        lua_pushvalue(L, 2);
        const int lua_status = lua_pcall(L, 1, 1, 0);
        if (setup.attached)
          (void)token.release();
        const int top = lua_gettop(L);
        (void)offered->linked(4833, request,
                              std::array{raw_native(lua_status), raw_native(top)});
        capture.require();
        if (lua_status != LUA_OK)
          throw Error{lua_status == LUA_ERRMEM ? ErrorCode::allocation
                                               : ErrorCode::external_unknown};
      } catch (const Error &why) {
        rejected = why;
        failed = true;
      } catch (const std::bad_alloc &) {
        rejected = {ErrorCode::allocation};
        outcome = RawOperationBranch::allocation;
        failed = true;
      } catch (...) {
        rejected = {ErrorCode::external_unknown};
        outcome = RawOperationBranch::nonstandard;
        failed = true;
      }
      if (failed) {
        raw_capture_failed(rejected);
        self->trace.owner.admission_failure = capture.error().value_or(rejected);
        self->failure = rejected;
        auto *owned = offered ? offered : paid ? &*paid : nullptr;
        if (owned)
          owned->finish(4, outcome, &rejected);
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    return 1;
  }
  static int module_observe(lua_State *L) {
    if (lua_isnil(L, 1))
      return 0;
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    bool failed = false;
    Error rejected{ErrorCode::external_unknown};
    {
      RawCaptureFailureScope capture{self->trace.owner.enabled};
      auto *stored = module_userdata(L, 1);
      try {
        if (!stored || !stored->token || !lua_isinteger(L, 2))
          throw Error{ErrorCode::invalid_range};
        const auto phase = lua_tointeger(L, 2);
        if (phase == 1 || phase == 2) {
          const auto branch = static_cast<std::uint8_t>(phase);
          const bool predicate = lua_toboolean(L, 3) != 0;
          (void)stored->token->event(
              {4822, 2}, std::array{raw_native(branch), raw_native(predicate)});
        } else if (phase >= 3 && phase <= 5) {
          const auto mutation = static_cast<std::uint8_t>(phase - 2);
          const int type = lua_type(L, 3);
          const void *value = lua_topointer(L, 3);
          (void)stored->token->event(
              {4823, static_cast<std::uint8_t>(phase == 3   ? 5
                                               : phase == 4 ? 6
                                                            : 7)},
              std::array{raw_native(mutation), raw_native(type), raw_native(value)});
        } else
          throw Error{ErrorCode::invalid_range};
        capture.require();
      } catch (const Error &why) {
        rejected = why;
        failed = true;
      } catch (...) {
        rejected = {ErrorCode::external_unknown};
        failed = true;
      }
      if (failed) {
        if (stored && stored->token)
          stored->token->failed(rejected);
        if (capture.error())
          self->trace.owner.admission_failure = *capture.error();
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    return 0;
  }
  static int module_end(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    auto *stored = module_userdata(L, 1);
    if (!stored || !stored->token || !stored->token->active())
      return authored_raise(L, {ErrorCode::invalid_range});
    bool failed = false;
    Error rejected{ErrorCode::external_unknown};
    {
      RawCaptureFailureScope capture{self->trace.owner.enabled};
      const int success = lua_toboolean(L, 2), type = lua_type(L, 3);
      const void *value = lua_topointer(L, 3);
      stored->token->finish(0, RawOperationBranch::returned, nullptr,
                            {.success = &success, .type = &type, .value = &value});
      if (capture.error()) {
        rejected = *capture.error();
        self->trace.owner.admission_failure = rejected;
        failed = true;
      }
    }
    if (failed)
      return authored_raise(L, rejected);
    return 0;
  }
  struct NativeFrame {
    Impl &runtime;
    RawCaptureFailureScope capture;
    RawBridgeTrace raw;
    std::optional<RawCapacityClaim> error_credit;
    std::optional<Value> value;
    std::optional<Error> primary;
    std::exception_ptr native_exception;
    NativeExceptionFrame *evaluation;
    RawOperationBranch branch = RawOperationBranch::returned;
    std::array<char, 512> message{};
    std::size_t message_size = 0;
    bool prepared = false;
    explicit NativeFrame(Impl &owner)
        : runtime(owner),
          capture(owner.trace.owner.enabled && owner.trace.owner.vm.ordinal != 0),
          evaluation(owner.native_exception_frame) {}
    void failed(Error why, const char *text, RawOperationBranch outcome) noexcept {
      primary = why;
      branch = outcome;
      if (why.code == ErrorCode::capacity)
        runtime.engine.capacity_stopped_ = true;
      message_size = std::min(std::strlen(text), message.size() - 1);
      std::memcpy(message.data(), text, message_size);
      message[message_size] = '\0';
    }
    void recording() noexcept {
      if (capture.error()) {
        runtime.trace.owner.admission_failure = *capture.error();
        failed(*capture.error(), error_name(capture.error()->code),
               RawOperationBranch::error);
      }
    }
    void begin(lua_State *L, int operation) {
      const auto vm = runtime.trace.owner.vm;
      const auto generation = runtime.trace.owner.generation;
      const auto operation_ref = runtime.engine.operation_trace_
                                     ? runtime.engine.operation_trace_->reference()
                                     : RawEventRef{};
      const bool operation_present = operation_ref.ordinal != 0;
      if (!lua_checkstack(L, 8))
        throw Error{ErrorCode::allocation};
      auto *parent_module = current_module(L);
      const auto module_ref =
          parent_module ? parent_module->reference() : RawEventRef{};
      const bool module_present = module_ref.ordinal != 0;
      const int argc = lua_gettop(L);
      std::array<ByteView, 12> fields{};
      std::size_t count = 0;
      fields[count++] = vm.lane;
      fields[count++] = raw_native(vm.ordinal);
      fields[count++] = generation;
      fields[count++] = raw_native(operation);
      fields[count++] = raw_native(argc);
      fields[count++] = raw_native(operation_present);
      if (operation_present) {
        fields[count++] = operation_ref.lane;
        fields[count++] = raw_native(operation_ref.ordinal);
      }
      fields[count++] = raw_native(module_present);
      if (module_present) {
        fields[count++] = module_ref.lane;
        fields[count++] = raw_native(module_ref.ordinal);
      }
      raw.start(4800, 4801, 264, runtime.trace.owner.enabled && vm.ordinal != 0,
                std::span{fields}.first(count));
      capture.require();
      error_credit = raw.data(560);
      capture.require();
    }
    void original(std::uint8_t role, std::string_view text) {
      if (text.size() > UINT32_MAX - 49) {
        raw_capture_failed({ErrorCode::overflow});
        throw Error{ErrorCode::overflow};
      }
      auto credit = raw.data(49 + text.size());
      const auto size = text.size();
      raw.original(4802, std::array{raw_native(role), raw_native(size), raw_text(text)},
                   credit ? &*credit : nullptr);
      capture.require();
    }
  };
  NativeFrame *bridge_frame = nullptr;
  struct Preparation {
    const Value *value = nullptr;
    const char *message = nullptr;
    std::size_t size = 0;
    std::uint8_t mode = 0;
  };
  Preparation *preparation = nullptr;
  inline static char preparation_key;
  static int prepare_native(lua_State *L) {
    auto *self = *static_cast<Impl **>(lua_getextraspace(L));
    auto *offered = self->preparation;
    if (offered->mode == 1)
      lua_pushlstring(L, offered->message, offered->size);
    else if (offered->mode == 2) {
      luaL_checktype(L, 1, LUA_TTABLE);
      lua_pushvalue(L, 1);
      tag(L, ValueTag::array);
    } else
      push_value(L, *offered->value);
    return 1;
  }
  int prepare_unrecorded(NativeFrame &frame, lua_State *L, std::uint8_t mode) {
    Preparation offered{frame.value ? &*frame.value : nullptr, frame.message.data(),
                        frame.message_size, mode};
    auto *previous = preparation;
    preparation = &offered;
    struct Restore {
      Preparation *&current;
      Preparation *previous;
      ~Restore() { current = previous; }
    } restore{preparation, previous};
    lua_rawgetp(L, LUA_REGISTRYINDEX, &preparation_key);
    if (mode == 2)
      lua_pushvalue(L, 1);
    const int lua_status = lua_pcall(L, mode == 2 ? 1 : 0, 1, 0);
    frame.prepared = true;
    return lua_status;
  }
  int prepare(NativeFrame &frame, lua_State *L, std::uint8_t mode) {
    if (!lua_checkstack(L, 4))
      throw Error{ErrorCode::allocation};
    const int base = lua_gettop(L);
    const auto request =
        frame.raw.event(4803, std::array{raw_native(mode), raw_native(base)});
    if (mode != 1)
      frame.capture.require();
    const int lua_status = prepare_unrecorded(frame, L, mode);
    const int top = lua_gettop(L);
    if (frame.raw.enabled())
      frame.raw.linked(4804, request,
                       std::array{raw_native(lua_status), raw_native(top)});
    frame.capture.require();
    return lua_status;
  }
  static std::string bridge_string(lua_State *L, int index, NativeFrame &frame,
                                   std::uint8_t role) {
    if (lua_type(L, index) != LUA_TSTRING)
      throw Error{ErrorCode::invalid_range};
    std::size_t size = 0;
    const char *text = lua_tolstring(L, index, &size);
    frame.original(role, {text, size});
    return {text, size};
  }
  static int bridge(lua_State *L) {
    auto *self = static_cast<Impl *>(lua_touserdata(L, lua_upvalueindex(1)));
    const auto op = static_cast<Op>(lua_tointeger(L, lua_upvalueindex(2)));
    bool raise = false;
    {
      NativeFrame frame{*self};
      auto *previous = self->bridge_frame;
      const auto previous_failure = self->failure;
      self->bridge_frame = &frame;
      self->failure.reset();
      struct Restore {
        Impl &runtime;
        NativeFrame *previous;
        ~Restore() { runtime.bridge_frame = previous; }
      } restore{*self, previous};
      try {
        if (frame.evaluation && frame.evaluation->primary)
          std::rethrow_exception(frame.evaluation->primary);
        frame.begin(L, static_cast<int>(op));
        frame.raw.stage(1);
        if (self->argument_restore_failed)
          throw Error{ErrorCode::external_unknown};
        if (self->trace.owner.admission_failure)
          throw *self->trace.owner.admission_failure;
        if (!lua_checkstack(L, 1024))
          throw Error{ErrorCode::allocation};
        frame.raw.stage(2);
        std::size_t nodes = 0;
        frame.raw.stage(3);
        switch (op) {
        case packet_decode_op:
          frame.value = unwrap(decode_packet_value(read_value(L, 1, {0, &nodes})));
          break;
        case packet_encode_op:
          frame.value =
              Value{unwrap(encode_packet_string(read_value(L, 1, {0, &nodes})))};
          break;
        case format_op:
          frame.value = Value{unwrap(format_value(read_value(L, 1, {0, &nodes})))};
          break;
        case stats_op:
          frame.value = self->engine.stats();
          break;
        case live_instruction_op:
          frame.value = Value{
              self->engine.context_.live_instruction(read_value(L, 1, {0, &nodes}))};
          break;
        case now_op: {
          const auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
          const auto mono_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::steady_clock::now().time_since_epoch())
                                   .count();
          frame.value = Value::object(
              {{"epoch_ms",
                Value{Number{static_cast<std::uint64_t>(epoch_ms > 0 ? epoch_ms : 0)}}},
               {"monotonic_ms",
                Value{Number{static_cast<std::uint64_t>(mono_ms > 0 ? mono_ms : 0)}}}});
          break;
        }
        case pin_op: {
          const auto ids_val = read_value(L, 1, {0, &nodes});
          const bool pin_flag =
              lua_isnoneornil(L, 2) ? true : (lua_toboolean(L, 2) != 0);
          Value::Object args{{"op", Value{pin_flag ? "pin" : "unpin"}}};
          if (std::holds_alternative<Number>(ids_val.value()))
            args.emplace_back("ids", Value{Value::Array{ids_val}});
          else
            args.emplace_back("ids", ids_val);
          frame.value = self->engine.context_compact(Value::object(std::move(args)));
          break;
        }
        case blocks_op: {
          const bool include_archived =
              !lua_isnoneornil(L, 1) && lua_toboolean(L, 1) != 0;
          frame.value = self->engine.context_list(include_archived);
          break;
        }
        case compact_op:
          frame.value = self->engine.context_compact(read_value(L, 1, {0, &nodes}));
          break;
        case read_block_op: {
          Value::Object args{{"id", read_value(L, 1, {0, &nodes})}};
          if (!lua_isnoneornil(L, 2)) {
            const auto opts = read_value(L, 2, {0, &nodes});
            if (!std::holds_alternative<Value::Object>(opts.value()))
              throw Error{ErrorCode::invalid_range};
            for (const auto &[k, v] : opts.object())
              args.emplace_back(k, v);
          }
          frame.value = self->engine.context_read(Value::object(std::move(args)));
          break;
        }
        case set_blocks_op:
          frame.value =
              self->engine.context_.replace_blocks(read_value(L, 1, {0, &nodes}));
          ++self->engine.upstream_epoch_;
          break;
        case flush_context_op: {
          const auto flushed = self->engine.flush_pending_compactions("lua");
          frame.value = Value::object(
              {{"flushed", Value{Number{flushed}}},
               {"upstream_epoch", Value{Number{self->engine.upstream_epoch_}}}});
          break;
        }
        case hooks_op: {
          const auto args = lua_isnoneornil(L, 1)
                                ? Value::object({{"op", Value{"list"}}})
                                : read_value(L, 1, {0, &nodes});
          frame.value = self->engine.hooks_tool(args);
          break;
        }
        case command_post_op: {
          if (lua_gettop(L) < 1 || lua_gettop(L) > 2)
            throw Error{ErrorCode::invalid_range};
          auto name = bridge_string(L, 1, frame, 1);
          if (!is_command_post_tool(name))
            throw Error{ErrorCode::invalid_range};
          auto args =
              lua_isnoneornil(L, 2) ? Value::object({}) : read_value(L, 2, {0, &nodes});
          if (!std::holds_alternative<Value::Object>(args.value()))
            throw Error{ErrorCode::invalid_range};
          frame.value =
              self->engine.dispatch(std::move(name), std::move(args), Value{});
          break;
        }
        case restarting_op:
          frame.value = Value{self->engine.restart_note_.has_value()};
          break;
        case request_op:
          frame.value = self->engine.request(lua_isnoneornil(L, 1)
                                                 ? Value::object({})
                                                 : read_value(L, 1, {0, &nodes}));
          break;
        case call_op: {
          auto name = bridge_string(L, 1, frame, 1);
          auto args = read_value(L, 2, {0, &nodes});
          // blackbird.call(name, args[, {call_id = ID}]): a relay declares the model
          // call it answers (T1).
          const auto options =
              lua_isnoneornil(L, 3) ? Value{} : read_value(L, 3, {0, &nodes});
          frame.value =
              self->engine.dispatch(std::move(name), std::move(args), options);
          break;
        }
        case append_op: {
          auto items = read_value(L, 1, {0, &nodes});
          std::optional<BlockKind> declared;
          if (!lua_isnoneornil(L, 2)) {
            const auto options = read_value(L, 2, {0, &nodes});
            const auto *fields = std::get_if<Value::Object>(&options.value());
            const auto *named =
                fields && fields->size() == 1 && fields->front().first == "kind"
                    ? std::get_if<std::string>(&fields->front().second.value())
                    : nullptr;
            declared = named ? parse_block_kind(*named) : std::nullopt;
            if (!declared)
              throw Error{ErrorCode::invalid_range};
          }
          const auto id =
              self->engine.context_.append(items.array(), "lua.synthetic", declared);
          self->engine.note_answered(items.array());
          frame.value = Value::object(
              {{"id", Value{Number{id}}},
               {"live_blocks", Value{Number{self->engine.context_.blocks().size()}}},
               {"total_bytes", Value{Number{self->engine.context_.total_bytes()}}}});
          break;
        }
        case decode_op:
          frame.value = unwrap(parse_json(bridge_string(L, 1, frame, 2)));
          break;
        case encode_op:
          frame.value = Value{unwrap(dump_json(read_value(L, 1, {0, &nodes})))};
          break;
        case display_op: {
          auto text = bridge_string(L, 1, frame, 4);
          self->engine.log_.original({"display", text, Value{}});
          if (self->engine.display)
            self->engine.display(text);
          frame.value = Value{};
          break;
        }
        case present_op:
          self->engine.present(read_value(L, 1, {0, &nodes}));
          frame.value = Value{};
          break;
        case array_op:
          break;
        }
        frame.capture.require();
      } catch (const Error &why) {
        frame.failed(why, error_name(why.code), RawOperationBranch::error);
      } catch (const std::bad_alloc &) {
        frame.failed({ErrorCode::allocation}, "allocation",
                     RawOperationBranch::allocation);
      } catch (const std::length_error &why) {
        frame.failed({ErrorCode::external_unknown}, why.what(),
                     RawOperationBranch::length);
      } catch (const std::exception &why) {
        frame.failed({ErrorCode::external_unknown}, why.what(),
                     RawOperationBranch::standard);
      } catch (...) {
        frame.native_exception = std::current_exception();
        frame.failed({ErrorCode::external_unknown}, "foreign native exception",
                     RawOperationBranch::nonstandard);
      }
      frame.recording();
      if (frame.primary) {
        try {
          const auto role = std::uint8_t{5};
          const auto size = frame.message_size;
          frame.raw.original(4802,
                             std::array{raw_native(role), raw_native(size),
                                        raw_text({frame.message.data(), size})},
                             frame.error_credit ? &*frame.error_credit : nullptr);
        } catch (const Error &) {
          frame.recording();
        }
      }
      frame.raw.stage(4);
      try {
        const int status = self->prepare(frame, L,
                                         frame.primary    ? 1
                                         : op == array_op ? 2
                                                          : 0);
        if (status != LUA_OK && !frame.primary)
          frame.failed(self->failure.value_or(Error{status == LUA_ERRMEM
                                                        ? ErrorCode::allocation
                                                        : ErrorCode::external_unknown}),
                       status == LUA_ERRMEM ? "allocation" : "Lua preparation failed",
                       RawOperationBranch::error);
        raise = frame.primary.has_value() || status != LUA_OK;
      } catch (const Error &why) {
        frame.failed(why, error_name(why.code), RawOperationBranch::error);
        raise = true;
      } catch (const std::exception &) {
        frame.failed({ErrorCode::external_unknown}, "native preparation failed",
                     RawOperationBranch::nonstandard);
        raise = true;
      } catch (...) {
        if (!frame.native_exception)
          frame.native_exception = std::current_exception();
        frame.failed({ErrorCode::external_unknown}, "native preparation failed",
                     RawOperationBranch::nonstandard);
        raise = true;
      }
      frame.recording();
      if (raise && !frame.prepared && lua_checkstack(L, 4))
        (void)self->prepare_unrecorded(frame, L, 1);
      const bool returned = !raise && !frame.primary;
      const int returns = 1;
      frame.raw.stage(5);
      if (returned)
        frame.raw.finish(frame.branch, nullptr,
                         std::array{raw_native(returned), raw_native(returns)});
      else
        frame.raw.finish(frame.branch, frame.primary ? &*frame.primary : nullptr,
                         std::array{raw_native(returned)});
      frame.recording();
      raise |= frame.primary.has_value();
      self->failure = previous ? previous_failure : frame.primary;
      // Carry the actual exception to the enclosing protected eval, after this
      // callback's owners are gone. A finalizer cannot replace an outer callback's
      // existing primary failure in the same eval.
      if (frame.native_exception && frame.evaluation && !frame.evaluation->primary &&
          !(previous && previous->evaluation == frame.evaluation && previous->primary))
        frame.evaluation->primary = frame.native_exception;
      frame.capture.finish();
    }
    // Protected preparation already rooted the result/error. No C++ owner remains.
    if (raise)
      return lua_error(L);
    return 1;
  }
  static void interrupt_hook(lua_State *L, lua_Debug *) {
    auto *self = *static_cast<Impl **>(lua_getextraspace(L));
    try {
      self->engine.poll_commands();
    } catch (const Error &error) {
      self->failure = error;
    } catch (...) {
      self->failure = Error{ErrorCode::external_unknown};
    }
    if (self->failure)
      luaL_error(L, "Command owner failed");
    if (self->engine.cancelled && self->engine.cancelled()) {
      self->failure = Error{ErrorCode::interrupted};
      luaL_error(L, "Turn interrupted");
    }
  }
  bool valid_module_source(std::string_view source) {
    const int base = lua_gettop(state);
    try {
      const bool valid = validation_load(source, "arco-module-candidate") == LUA_OK;
      lua_settop(state, base);
      return valid;
    } catch (...) {
      lua_settop(state, base);
      throw;
    }
  }
  bool valid_tool_source(std::string_view source) {
    const int base = lua_gettop(state);
    const auto wrapped = "return function(args)\n" + std::string{source} + "\nend";
    try {
      const bool valid = validation_load(wrapped, "arco-tool-definition") == LUA_OK;
      lua_settop(state, base);
      return valid;
    } catch (...) {
      lua_settop(state, base);
      throw;
    }
  }
  bool valid_hook_source(std::string_view source) {
    const int base = lua_gettop(state);
    const auto wrapped = "return function(event)\n" + std::string{source} + "\nend";
    try {
      const bool valid =
          validation_load(wrapped, "blackbird-hook-definition") == LUA_OK;
      lua_settop(state, base);
      return valid;
    } catch (...) {
      lua_settop(state, base);
      throw;
    }
  }
  Value invoke_hook(std::string_view source, const Value &event) {
    const std::string wrapped = "local fn = function(event)\n" + std::string{source} +
                                "\nend\nreturn fn(_native_args)";
    return eval(wrapped, &event, SourceKind::tool);
  }
  Value invoke_tool(ToolInvocation invocation) {
    const auto &source = string_field(invocation.definition, "source");
    const auto length = source.size();
    constexpr std::string_view prefix = "local fn = function(args)\n";
    constexpr std::string_view suffix = "\nend\nreturn fn(_native_args)";
    RawProgramCall wrapper{3836, 3837, invocation.origin,
                           std::array{raw_native(length)}};
    return wrapper.run([&] {
      if (length > UINT32_MAX - 48 - prefix.size() - suffix.size())
        throw Error{ErrorCode::overflow};
      const auto total = prefix.size() + length + suffix.size();
      auto original = wrapper.data(48 + total);
      std::string wrapped;
      wrapped.reserve(total);
      wrapped.append(prefix);
      wrapped.append(source);
      wrapped.append(suffix);
      wrapper.bytes(3838, wrapped, original);
      return eval(wrapped, &invocation.arguments, SourceKind::tool);
    });
  }
  static int transfer_arguments(lua_State *L) {
    auto *self = *static_cast<Impl **>(lua_getextraspace(L));
    auto *frame = self->argument_frame;
    if (frame->phase == 1) {
      if (frame->previous == LUA_REFNIL)
        lua_pushnil(L);
      else
        lua_rawgeti(L, LUA_REGISTRYINDEX, frame->previous);
      lua_setglobal(L, "_native_args");
    } else if (frame->phase == 2) {
      luaL_unref(L, LUA_REGISTRYINDEX, frame->previous);
    } else {
      lua_getglobal(L, "_native_args");
      frame->previous = luaL_ref(L, LUA_REGISTRYINDEX);
      frame->captured = true;
      push_value(L, *frame->arguments);
      lua_setglobal(L, "_native_args");
    }
    return 0;
  }
  int protected_arguments(ArgumentFrame &frame, std::uint8_t phase) {
    const RawProgramContext origin{
        RawEventRef{trace.owner.vm.lane, trace.owner.vm.ordinal}, {}};
    RawProgramCall transfer{3840, 3841, &origin,
                            std::array{raw_native(phase), raw_native(frame.captured),
                                       raw_native(frame.previous)},
                            sizeof(int) + sizeof(bool)};
    return transfer.run([&] {
      if (!lua_checkstack(state, 1024))
        throw Error{ErrorCode::allocation};
      auto *previous = argument_frame;
      argument_frame = &frame;
      frame.phase = phase;
      lua_pushcfunction(state, transfer_arguments);
      int lua_status = LUA_OK;
      try {
        lua_status = lua_pcall(state, 0, 0, 0);
      } catch (...) {
        argument_frame = previous;
        throw;
      }
      argument_frame = previous;
      if (phase == 2 && lua_status == LUA_OK) {
        frame.captured = false;
        frame.previous = LUA_NOREF;
      }
      transfer.finish(RawOperationBranch::returned, nullptr,
                      std::array{raw_native(lua_status), raw_native(frame.captured)});
      return lua_status;
    });
  }
  static int error_text(lua_State *L) {
    const char *message = lua_tostring(L, 1);
    if (message == nullptr)
      lua_pushnil(L);
    else
      lua_pushvalue(L, 1);
    return 1;
  }
  Value eval(std::string_view source, const Value *arguments = nullptr,
             SourceKind kind = SourceKind::root) {
    error.clear();
    NativeExceptionFrame native_exception;
    struct RestoreExceptionFrame {
      NativeExceptionFrame *&current;
      NativeExceptionFrame *previous;
      ~RestoreExceptionFrame() { current = previous; }
    } restore_exception{native_exception_frame, native_exception_frame};
    native_exception_frame = &native_exception;
    const int base = lua_gettop(state);
    ArgumentFrame frame{arguments};
    auto restore_arguments = [&] {
      if (frame.captured) {
        const int restore_base = lua_gettop(state);
        try {
          const int lua_status = protected_arguments(frame, 1);
          lua_settop(state, restore_base);
          if (lua_status != LUA_OK) {
            argument_restore_failed = true;
            throw Error{lua_status == LUA_ERRMEM ? ErrorCode::allocation
                                                 : ErrorCode::external_unknown};
          }
          const int released = protected_arguments(frame, 2);
          lua_settop(state, restore_base);
          if (released != LUA_OK) {
            argument_restore_failed = true;
            throw Error{released == LUA_ERRMEM ? ErrorCode::allocation
                                               : ErrorCode::external_unknown};
          }
        } catch (...) {
          argument_restore_failed = true;
          throw;
        }
      }
    };
    try {
      if (argument_restore_failed)
        throw Error{ErrorCode::external_unknown};
      if (arguments) {
        const int lua_status = protected_arguments(frame, 0);
        frame.arguments = nullptr;
        if (lua_status != LUA_OK)
          throw Error{lua_status == LUA_ERRMEM ? ErrorCode::allocation
                                               : ErrorCode::external_unknown};
      }
      const int execution_status =
          load_and_call(state, source, "arco-program", kind, 1);
      if (native_exception.primary)
        std::rethrow_exception(native_exception.primary);
      if (execution_status != LUA_OK) {
        const auto native_error = authored_error(state, -1);
        const RawProgramContext text_origin{
            RawEventRef{trace.owner.vm.lane, trace.owner.vm.ordinal}, {}};
        const std::uint8_t phase = 3;
        RawProgramCall conversion{3840, 3841, &text_origin,
                                  std::array{raw_native(phase),
                                             raw_native(frame.captured),
                                             raw_native(frame.previous)},
                                  sizeof(int) + sizeof(bool)};
        const int converted = conversion.run([&] {
          if (!lua_checkstack(state, 2))
            throw Error{ErrorCode::allocation};
          lua_pushcfunction(state, error_text);
          lua_pushvalue(state, -2);
          const int lua_status = lua_pcall(state, 1, 1, 0);
          conversion.finish(
              RawOperationBranch::returned, nullptr,
              std::array{raw_native(lua_status), raw_native(frame.captured)});
          return lua_status;
        });
        if (converted != LUA_OK)
          throw Error{ErrorCode::allocation};
        const char *message =
            lua_type(state, -1) == LUA_TSTRING ? lua_tostring(state, -1) : nullptr;
        error = native_error.has_value() ? error_name(native_error->code)
                                         : (message == nullptr ? "Lua error" : message);
        const auto lost = error.size() > 512 ? error.size() - 512 : 0;
        error.resize(std::min<std::size_t>(error.size(), 512));
        RetainedState::MaintenanceScope maintenance{engine.log_.root()};
        engine.log_.original(
            {"lua.error", error,
             Value::object(
                 {{"generation", Value{hex_identity(engine.generation_.bytes())}},
                  {"unretained_bytes", Value{Number{lost}}}})});
        throw native_error.value_or(
            failure.value_or(Error{ErrorCode::external_unknown}));
      }
      if (!lua_checkstack(state, 1024))
        throw Error{ErrorCode::allocation};
      if (argument_restore_failed)
        throw Error{ErrorCode::external_unknown};
      std::size_t nodes = 0;
      restore_arguments();
      if (native_exception.primary)
        std::rethrow_exception(native_exception.primary);
      auto result = read_value(state, -1, {0, &nodes});
      lua_settop(state, base);
      return result;
    } catch (...) {
      frame.arguments = nullptr;
      const auto primary = native_exception.primary ? native_exception.primary
                                                    : std::current_exception();
      try {
        restore_arguments();
      } catch (...) {
        // The registry root survives until Runtime closes. Both native statuses
        // are already emitted; restoration cannot replace the primary failure.
      }
      lua_settop(state, base);
      std::rethrow_exception(primary);
    }
  }
};

CodingEngine::Runtime::Runtime(CodingEngine &e)
    : impl(std::make_unique<Impl>(e, error)) {}
CodingEngine::Runtime::~Runtime() = default;
bool CodingEngine::Runtime::valid_module_source(std::string_view source) {
  return impl->valid_module_source(source);
}
bool CodingEngine::Runtime::valid_tool_source(std::string_view source) {
  return impl->valid_tool_source(source);
}
bool CodingEngine::Runtime::valid_hook_source(std::string_view source) {
  return impl->valid_hook_source(source);
}
Value CodingEngine::Runtime::invoke_tool(ToolInvocation invocation) {
  return impl->invoke_tool(invocation);
}
Value CodingEngine::Runtime::invoke_hook(std::string_view source, const Value &event) {
  return impl->invoke_hook(source, event);
}
Value CodingEngine::Runtime::eval(std::string_view source, const Value *arguments,
                                  SourceKind kind) {
  return impl->eval(source, arguments, kind);
}

} // namespace blackbird
