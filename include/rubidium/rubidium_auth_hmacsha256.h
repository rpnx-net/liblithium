#ifndef rubidium_auth_hmacsha256_H
#define rubidium_auth_hmacsha256_H

#include <stddef.h>
#include "rubidium_hash_sha256.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_auth_hmacsha256_BYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_auth_hmacsha256_bytes(void);

#define rubidium_auth_hmacsha256_KEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_auth_hmacsha256_keybytes(void);

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha256(unsigned char *out,
                           const unsigned char *in,
                           unsigned long long inlen,
                           const unsigned char *k) __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha256_verify(const unsigned char *h,
                                  const unsigned char *in,
                                  unsigned long long inlen,
                                  const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

/* ------------------------------------------------------------------------- */

typedef struct rubidium_auth_hmacsha256_state {
    rubidium_hash_sha256_state ictx;
    rubidium_hash_sha256_state octx;
} rubidium_auth_hmacsha256_state;

RUBIDIUM_EXPORT
size_t rubidium_auth_hmacsha256_statebytes(void);

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha256_init(rubidium_auth_hmacsha256_state *state,
                                const unsigned char *key,
                                size_t keylen) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha256_update(rubidium_auth_hmacsha256_state *state,
                                  const unsigned char *in,
                                  unsigned long long inlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha256_final(rubidium_auth_hmacsha256_state *state,
                                 unsigned char *out) __attribute__ ((nonnull));


RUBIDIUM_EXPORT
void rubidium_auth_hmacsha256_keygen(unsigned char k[rubidium_auth_hmacsha256_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
