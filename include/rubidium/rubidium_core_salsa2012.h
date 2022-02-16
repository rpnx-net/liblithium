#ifndef rubidium_core_salsa2012_H
#define rubidium_core_salsa2012_H

#include <cstddef>
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rubidium_core_salsa2012_OUTPUTBYTES 64U
RUBIDIUM_EXPORT
size_t rubidium_core_salsa2012_outputbytes(void);

#define rubidium_core_salsa2012_INPUTBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_core_salsa2012_inputbytes(void);

#define rubidium_core_salsa2012_KEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_core_salsa2012_keybytes(void);

#define rubidium_core_salsa2012_CONSTBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_core_salsa2012_constbytes(void);

RUBIDIUM_EXPORT
int rubidium_core_salsa2012(unsigned char *out, const unsigned char *in,
                          const unsigned char *k, const unsigned char *c)
            __attribute__ ((nonnull(1, 2, 3)));

#ifdef __cplusplus
}
#endif

#endif
