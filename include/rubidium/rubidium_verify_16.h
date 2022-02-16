#ifndef rubidium_verify_16_H
#define rubidium_verify_16_H

#include <cstddef>
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rubidium_verify_16_BYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_verify_16_bytes(void);

RUBIDIUM_EXPORT
int rubidium_verify_16(const unsigned char *x, const unsigned char *y)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
