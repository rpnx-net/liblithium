#ifndef rubidium_core_hchacha20_H
#define rubidium_core_hchacha20_H

#include <cstddef>
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rubidium_core_hchacha20_OUTPUTBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_core_hchacha20_outputbytes(void);

#define rubidium_core_hchacha20_INPUTBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_core_hchacha20_inputbytes(void);

#define rubidium_core_hchacha20_KEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_core_hchacha20_keybytes(void);

#define rubidium_core_hchacha20_CONSTBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_core_hchacha20_constbytes(void);

RUBIDIUM_EXPORT
int rubidium_core_hchacha20(unsigned char *out, const unsigned char *in,
                          const unsigned char *k, const unsigned char *c)
            __attribute__ ((nonnull(1, 2, 3)));

#ifdef __cplusplus
}
#endif

#endif
