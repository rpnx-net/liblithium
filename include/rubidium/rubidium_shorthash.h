#ifndef rubidium_shorthash_H
#define rubidium_shorthash_H

#include <stddef.h>

#include "rubidium_shorthash_siphash24.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_shorthash_BYTES rubidium_shorthash_siphash24_BYTES
RUBIDIUM_EXPORT
size_t  rubidium_shorthash_bytes(void);

#define rubidium_shorthash_KEYBYTES rubidium_shorthash_siphash24_KEYBYTES
RUBIDIUM_EXPORT
size_t  rubidium_shorthash_keybytes(void);

#define rubidium_shorthash_PRIMITIVE "siphash24"
RUBIDIUM_EXPORT
const char *rubidium_shorthash_primitive(void);

RUBIDIUM_EXPORT
int rubidium_shorthash(unsigned char *out, const unsigned char *in,
                     unsigned long long inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
void rubidium_shorthash_keygen(unsigned char k[rubidium_shorthash_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
