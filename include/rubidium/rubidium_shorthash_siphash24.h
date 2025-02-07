#ifndef rubidium_shorthash_siphash24_H
#define rubidium_shorthash_siphash24_H

#include <cstddef>
#include "export.h"



/* -- 64-bit output -- */

#define rubidium_shorthash_siphash24_BYTES 8U

size_t rubidium_shorthash_siphash24_bytes(void);

#define rubidium_shorthash_siphash24_KEYBYTES 16U

size_t rubidium_shorthash_siphash24_keybytes(void);


int rubidium_shorthash_siphash24(unsigned char *out, const unsigned char *in,
                               std::size_t inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));

#ifndef RUBIDIUM_LIBRARY_MINIMAL
/* -- 128-bit output -- */

#define rubidium_shorthash_siphashx24_BYTES 16U

size_t rubidium_shorthash_siphashx24_bytes(void);

#define rubidium_shorthash_siphashx24_KEYBYTES 16U

size_t rubidium_shorthash_siphashx24_keybytes(void);


int rubidium_shorthash_siphashx24(unsigned char *out, const unsigned char *in,
                                std::size_t inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));
#endif



#endif
