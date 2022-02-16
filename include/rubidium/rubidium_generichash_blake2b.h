#ifndef RUBIDIUM_GENERICHASH_BLAKE2B_H
#define RUBIDIUM_GENERICHASH_BLAKE2B_H

#include <cstddef>
#include <cstdint>
#include <stdlib.h>
#include <cstdint>

#include "export.h"




typedef struct RUBIDIUM_ALIGN(64) rubidium_generichash_blake2b_state {
    unsigned char opaque[384];
} rubidium_generichash_blake2b_state;

#define rubidium_generichash_blake2b_BYTES_MIN     16U

size_t rubidium_generichash_blake2b_bytes_min(void);

#define rubidium_generichash_blake2b_BYTES_MAX     64U

size_t rubidium_generichash_blake2b_bytes_max(void);

#define rubidium_generichash_blake2b_BYTES         32U

size_t rubidium_generichash_blake2b_bytes(void);

#define rubidium_generichash_blake2b_KEYBYTES_MIN  16U

size_t rubidium_generichash_blake2b_keybytes_min(void);

#define rubidium_generichash_blake2b_KEYBYTES_MAX  64U

size_t rubidium_generichash_blake2b_keybytes_max(void);

#define rubidium_generichash_blake2b_KEYBYTES      32U

size_t rubidium_generichash_blake2b_keybytes(void);

#define rubidium_generichash_blake2b_SALTBYTES     16U

size_t rubidium_generichash_blake2b_saltbytes(void);

#define RUBIDIUM_GENERICHASH_BLAKE2B_PERSONALBYTES 16U

size_t rubidium_generichash_blake2b_personalbytes(void);


size_t rubidium_generichash_blake2b_statebytes(void);


int rubidium_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in,
                               std::size_t inlen,
                               const unsigned char *key, size_t keylen)
            __attribute__ ((nonnull(1)));


int rubidium_generichash_blake2b_salt_personal(unsigned char *out, size_t outlen,
                                             const unsigned char *in,
                                             std::size_t inlen,
                                             const unsigned char *key,
                                             size_t keylen,
                                             const unsigned char *salt,
                                             const unsigned char *personal)
            __attribute__ ((nonnull(1)));


int rubidium_generichash_blake2b_init(rubidium_generichash_blake2b_state *state,
                                    const unsigned char *key,
                                    const size_t keylen, const size_t outlen)
            __attribute__ ((nonnull(1)));


int rubidium_generichash_blake2b_init_salt_personal(rubidium_generichash_blake2b_state *state,
                                                  const unsigned char *key,
                                                  const size_t keylen, const size_t outlen,
                                                  const unsigned char *salt,
                                                  const unsigned char *personal)
            __attribute__ ((nonnull(1)));


int rubidium_generichash_blake2b_update(rubidium_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      std::size_t inlen)
            __attribute__ ((nonnull(1)));


int rubidium_generichash_blake2b_final(rubidium_generichash_blake2b_state *state,
                                     unsigned char *out,
                                     const size_t outlen) __attribute__ ((nonnull));


void rubidium_generichash_blake2b_keygen(unsigned char k[rubidium_generichash_blake2b_KEYBYTES])
            __attribute__ ((nonnull));


#endif
