#ifndef rubidium_hash_sha256_H
#define rubidium_hash_sha256_H

/*
 * WARNING: Unless you absolutely need to use SHA256 for interoperability,
 * purposes, you might want to consider rubidium_generichash() instead.
 * Unlike SHA256, rubidium_generichash() is not vulnerable to length
 * extension attacks.
 */

#include <cstddef>
#include <cstdint>
#include <stdlib.h>

#include "export.h"



typedef struct rubidium_hash_sha256_state {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
} rubidium_hash_sha256_state;


size_t rubidium_hash_sha256_statebytes(void);

#define rubidium_hash_sha256_BYTES 32U

size_t rubidium_hash_sha256_bytes(void);


int rubidium_hash_sha256(unsigned char *out, const unsigned char *in,
                       std::size_t inlen) __attribute__ ((nonnull(1)));


int rubidium_hash_sha256_init(rubidium_hash_sha256_state *state)
            __attribute__ ((nonnull));


int rubidium_hash_sha256_update(rubidium_hash_sha256_state *state,
                              const unsigned char *in,
                              std::size_t inlen)
            __attribute__ ((nonnull(1)));


int rubidium_hash_sha256_final(rubidium_hash_sha256_state *state,
                             unsigned char *out)
            __attribute__ ((nonnull));



#endif
