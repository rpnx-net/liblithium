#ifndef rubidium_shorthash_siphash24_H
#define rubidium_shorthash_siphash24_H

#include <stddef.h>
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

/* -- 64-bit output -- */

#define rubidium_shorthash_siphash24_BYTES 8U
RUBIDIUM_EXPORT
size_t rubidium_shorthash_siphash24_bytes(void);

#define rubidium_shorthash_siphash24_KEYBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_shorthash_siphash24_keybytes(void);

RUBIDIUM_EXPORT
int rubidium_shorthash_siphash24(unsigned char *out, const unsigned char *in,
                               unsigned long long inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));

#ifndef RUBIDIUM_LIBRARY_MINIMAL
/* -- 128-bit output -- */

#define rubidium_shorthash_siphashx24_BYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_shorthash_siphashx24_bytes(void);

#define rubidium_shorthash_siphashx24_KEYBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_shorthash_siphashx24_keybytes(void);

RUBIDIUM_EXPORT
int rubidium_shorthash_siphashx24(unsigned char *out, const unsigned char *in,
                                unsigned long long inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));
#endif

#ifdef __cplusplus
}
#endif

#endif
