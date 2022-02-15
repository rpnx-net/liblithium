#ifndef RUBIDIUM_GENERICHASH_BLAKE2B_H
#define RUBIDIUM_GENERICHASH_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif



typedef struct RUBIDIUM_ALIGN(64) rubidium_generichash_blake2b_state {
    unsigned char opaque[384];
} rubidium_generichash_blake2b_state;

#define rubidium_generichash_blake2b_BYTES_MIN     16U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_bytes_min(void);

#define rubidium_generichash_blake2b_BYTES_MAX     64U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_bytes_max(void);

#define rubidium_generichash_blake2b_BYTES         32U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_bytes(void);

#define rubidium_generichash_blake2b_KEYBYTES_MIN  16U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_keybytes_min(void);

#define rubidium_generichash_blake2b_KEYBYTES_MAX  64U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_keybytes_max(void);

#define rubidium_generichash_blake2b_KEYBYTES      32U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_keybytes(void);

#define rubidium_generichash_blake2b_SALTBYTES     16U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_saltbytes(void);

#define rubidium_generichash_blake2b_PERSONALBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_personalbytes(void);

RUBIDIUM_EXPORT
size_t rubidium_generichash_blake2b_statebytes(void);

RUBIDIUM_EXPORT
int rubidium_generichash_blake2b(unsigned char *out, size_t outlen,
                               const unsigned char *in,
                               unsigned long long inlen,
                               const unsigned char *key, size_t keylen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_blake2b_salt_personal(unsigned char *out, size_t outlen,
                                             const unsigned char *in,
                                             unsigned long long inlen,
                                             const unsigned char *key,
                                             size_t keylen,
                                             const unsigned char *salt,
                                             const unsigned char *personal)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_blake2b_init(rubidium_generichash_blake2b_state *state,
                                    const unsigned char *key,
                                    const size_t keylen, const size_t outlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_blake2b_init_salt_personal(rubidium_generichash_blake2b_state *state,
                                                  const unsigned char *key,
                                                  const size_t keylen, const size_t outlen,
                                                  const unsigned char *salt,
                                                  const unsigned char *personal)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_blake2b_update(rubidium_generichash_blake2b_state *state,
                                      const unsigned char *in,
                                      unsigned long long inlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_blake2b_final(rubidium_generichash_blake2b_state *state,
                                     unsigned char *out,
                                     const size_t outlen) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_generichash_blake2b_keygen(unsigned char k[rubidium_generichash_blake2b_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
