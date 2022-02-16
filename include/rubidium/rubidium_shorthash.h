#ifndef rubidium_shorthash_H
#define rubidium_shorthash_H

#include <cstddef>

#include "rubidium_shorthash_siphash24.h"
#include "export.h"



#define rubidium_shorthash_BYTES rubidium_shorthash_siphash24_BYTES

size_t  rubidium_shorthash_bytes(void);

#define rubidium_shorthash_KEYBYTES rubidium_shorthash_siphash24_KEYBYTES

size_t  rubidium_shorthash_keybytes(void);

#define rubidium_shorthash_PRIMITIVE "siphash24"

const char *rubidium_shorthash_primitive(void);


int rubidium_shorthash(unsigned char *out, const unsigned char *in,
                     std::size_t inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));


void rubidium_shorthash_keygen(unsigned char k[rubidium_shorthash_KEYBYTES])
            __attribute__ ((nonnull));



#endif
