#ifndef rubidium_auth_hmacsha256_H
#define rubidium_auth_hmacsha256_H

#include <cstddef>
#include "rubidium_hash_sha256.h"
#include "export.h"



#define rubidium_auth_hmacsha256_BYTES 32U

size_t rubidium_auth_hmacsha256_bytes(void);

#define rubidium_auth_hmacsha256_KEYBYTES 32U

size_t rubidium_auth_hmacsha256_keybytes(void);


int rubidium_auth_hmacsha256(unsigned char *out,
                           const unsigned char *in,
                           std::size_t inlen,
                           const unsigned char *k) __attribute__ ((nonnull(1, 4)));


int rubidium_auth_hmacsha256_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  std::size_t inlen,
                                  const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

/* ------------------------------------------------------------------------- */

typedef struct rubidium_auth_hmacsha256_state {
    rubidium_hash_sha256_state ictx;
    rubidium_hash_sha256_state octx;
} rubidium_auth_hmacsha256_state;


size_t rubidium_auth_hmacsha256_statebytes(void);


int rubidium_auth_hmacsha256_init(rubidium_auth_hmacsha256_state *state,
                                const unsigned char *key,
                                size_t keylen) __attribute__ ((nonnull));


int rubidium_auth_hmacsha256_update(rubidium_auth_hmacsha256_state *state,
                                  const unsigned char *in,
                                  std::size_t inlen)
            __attribute__ ((nonnull(1)));


int rubidium_auth_hmacsha256_final(rubidium_auth_hmacsha256_state *state,
                                 unsigned char *out) __attribute__ ((nonnull));



void rubidium_auth_hmacsha256_keygen(unsigned char k[rubidium_auth_hmacsha256_KEYBYTES])
            __attribute__ ((nonnull));



#endif
