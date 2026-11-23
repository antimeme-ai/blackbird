#include "blackbird/native_module_abi.h"

#include <cstring>
#include <limits>

namespace {

constexpr char kPrefix[] = "v2:";
constexpr std::size_t kPrefixLen = sizeof(kPrefix) - 1U;

int fixture_v2_transform(const char *in, size_t in_len, char *out, size_t out_cap,
                         size_t *out_len) {
  if (out_len == nullptr || (in_len > 0 && in == nullptr)) {
    return BLACKBIRD_MODULE_ERR_INVALID_ARG;
  }
  if (in_len > std::numeric_limits<size_t>::max() - kPrefixLen) {
    return BLACKBIRD_MODULE_ERR_INVALID_ARG;
  }
  const size_t needed = kPrefixLen + in_len;
  *out_len = needed;
  if (out_cap < needed) {
    return BLACKBIRD_MODULE_ERR_BUFFER_TOO_SMALL;
  }
  if (out == nullptr) {
    return BLACKBIRD_MODULE_ERR_INVALID_ARG;
  }
  std::memcpy(out, kPrefix, kPrefixLen);
  if (in_len > 0) {
    std::memcpy(out + kPrefixLen, in, in_len);
  }
  return BLACKBIRD_MODULE_OK;
}

const BlackbirdModuleDescriptor kDescriptor = {
    BLACKBIRD_MODULE_ABI_VERSION,
    "fixture_prefix",
    "2.0.0",
    &fixture_v2_transform,
};

} // namespace

extern "C" BLACKBIRD_MODULE_EXPORT const BlackbirdModuleDescriptor *
blackbird_module_describe(void) {
  return &kDescriptor;
}
