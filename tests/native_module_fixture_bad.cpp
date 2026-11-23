#include "blackbird/native_module_abi.h"

namespace {

constexpr uint32_t kUnsupportedAbiVersion = 999U;

const BlackbirdModuleDescriptor kBadDescriptor = {
    kUnsupportedAbiVersion,
    "fixture_bad",
    "999.0.0",
    nullptr,
};

} // namespace

extern "C" BLACKBIRD_MODULE_EXPORT const BlackbirdModuleDescriptor *
blackbird_module_describe(void) {
  return &kBadDescriptor;
}
