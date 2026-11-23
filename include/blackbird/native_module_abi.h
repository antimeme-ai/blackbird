#ifndef BLACKBIRD_NATIVE_MODULE_ABI_H
#define BLACKBIRD_NATIVE_MODULE_ABI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLACKBIRD_MODULE_ABI_VERSION 1U
#define BLACKBIRD_MODULE_DESCRIBE_SYMBOL "blackbird_module_describe"

#define BLACKBIRD_MODULE_OK 0
#define BLACKBIRD_MODULE_ERR_BUFFER_TOO_SMALL (-1)
#define BLACKBIRD_MODULE_ERR_INVALID_ARG (-2)
#define BLACKBIRD_MODULE_ERR_INTERNAL (-3)

#if defined(__GNUC__) || defined(__clang__)
#define BLACKBIRD_MODULE_EXPORT __attribute__((visibility("default")))
#else
#define BLACKBIRD_MODULE_EXPORT
#endif

typedef int (*BlackbirdModuleTransformFn)(const char *in, size_t in_len, char *out,
                                          size_t out_cap, size_t *out_len);

typedef struct BlackbirdModuleDescriptor {
  uint32_t abi_version;
  const char *name;
  const char *version;
  BlackbirdModuleTransformFn transform;
} BlackbirdModuleDescriptor;

typedef const BlackbirdModuleDescriptor *(*BlackbirdModuleDescribeFn)(void);

BLACKBIRD_MODULE_EXPORT const BlackbirdModuleDescriptor *
blackbird_module_describe(void);

#ifdef __cplusplus
}
#endif

#endif /* BLACKBIRD_NATIVE_MODULE_ABI_H */
