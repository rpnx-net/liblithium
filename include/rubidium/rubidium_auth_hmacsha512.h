#ifndef RUBIDIUM_AUTH_HMACSHA512_H
#define RUBIDIUM_AUTH_HMACSHA512_H

#include <cstddef>
#include "rubidium_hash_sha512.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_auth_hmacsha512_BYTES 64U

size_t rubidium_auth_hmacsha512_bytes(void);

#define rubidium_auth_hmacsha512_KEYBYTES 32U

size_t rubidium_auth_hmacsha512_keybytes(void);


int rubidium_auth_hmacsha512(unsigned char *out,
                           const unsigned char *in,
                           std::size_t inlen,
                           const unsigned char *k) __attribute__ ((nonnull(1, 4)));


int rubidium_auth_hmacsha512_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  std::size_t inlen,
                                  const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

/* ------------------------------------------------------------------------- */

typedef struct rubidium_auth_hmacsha512_state {
    rubidium_hash_sha512_state ictx;
    rubidium_hash_sha512_state octx;
} rubidium_auth_hmacsha512_state;


size_t rubidium_auth_hmacsha512_statebytes(void);


int rubidium_auth_hmacsha512_init(rubidium_auth_hmacsha512_state *state,
                                const unsigned char *key,
                                size_t keylen) __attribute__ ((nonnull));


int rubidium_auth_hmacsha512_update(rubidium_auth_hmacsha512_state *state,
                                  const unsigned char *in,
                                  std::size_t inlen) __attribute__ ((nonnull(1)));


int rubidium_auth_hmacsha512_final(rubidium_auth_hmacsha512_state *state,
                                 unsigned char *out) __attribute__ ((nonnull));


void rubidium_auth_hmacsha512_keygen(unsigned char k[rubidium_auth_hmacsha512_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
