#ifndef rubidium_hash_sha512_H
#define rubidium_hash_sha512_H

/*
 * WARNING: Unless you absolutely need to use SHA512 for interoperability,
 * purposes, you might want to consider rubidium_generichash() instead.
 * Unlike SHA512, rubidium_generichash() is not vulnerable to length
 * extension attacks.
 */

#include <cstddef>
#include <cstdint>
#include <stdlib.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef struct rubidium_hash_sha512_state {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buf[128];
} rubidium_hash_sha512_state;


size_t rubidium_hash_sha512_statebytes(void);

#define rubidium_hash_sha512_BYTES 64U

size_t rubidium_hash_sha512_bytes(void);


int rubidium_hash_sha512(unsigned char *out, const unsigned char *in,
                       std::size_t inlen) __attribute__ ((nonnull(1)));


int rubidium_hash_sha512_init(rubidium_hash_sha512_state *state)
            __attribute__ ((nonnull));


int rubidium_hash_sha512_update(rubidium_hash_sha512_state *state,
                              const unsigned char *in,
                              std::size_t inlen)
            __attribute__ ((nonnull(1)));


int rubidium_hash_sha512_final(rubidium_hash_sha512_state *state,
                             unsigned char *out)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
