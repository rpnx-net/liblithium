#ifndef RUBIDIUM_AUTH_HMACSHA512256_H
#define RUBIDIUM_AUTH_HMACSHA512256_H

#include <cstddef>
#include "rubidium_auth_hmacsha512.h"
#include "export.h"



#define RUBIDIUM_AUTH_HMACSHA512256_BYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_auth_hmacsha512256_bytes(void);

#define RUBIDIUM_AUTH_HMACSHA512256_KEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_auth_hmacsha512256_keybytes(void);

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha512256(unsigned char *out,
                              const unsigned char *in,
                              std::size_t inlen,
                              const unsigned char *k) __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha512256_verify(const unsigned char *h,
                                     const unsigned char *in,
                                     std::size_t inlen,
                                     const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

/* ------------------------------------------------------------------------- */

typedef rubidium_auth_hmacsha512_state rubidium_auth_hmacsha512256_state;

RUBIDIUM_EXPORT
size_t rubidium_auth_hmacsha512256_statebytes(void);

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha512256_init(rubidium_auth_hmacsha512256_state *state,
                                   const unsigned char *key,
                                   size_t keylen) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha512256_update(rubidium_auth_hmacsha512256_state *state,
                                     const unsigned char *in,
                                     std::size_t inlen) __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_auth_hmacsha512256_final(rubidium_auth_hmacsha512256_state *state,
                                    unsigned char *out) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_auth_hmacsha512256_keygen(unsigned char k[RUBIDIUM_AUTH_HMACSHA512256_KEYBYTES])
            __attribute__ ((nonnull));



#endif
