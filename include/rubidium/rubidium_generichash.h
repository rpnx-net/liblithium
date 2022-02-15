#ifndef rubidium_generichash_H
#define rubidium_generichash_H

#include <stddef.h>

#include "rubidium_generichash_blake2b.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_generichash_BYTES_MIN rubidium_generichash_blake2b_BYTES_MIN
RUBIDIUM_EXPORT
size_t  rubidium_generichash_bytes_min(void);

#define rubidium_generichash_BYTES_MAX rubidium_generichash_blake2b_BYTES_MAX
RUBIDIUM_EXPORT
size_t  rubidium_generichash_bytes_max(void);

#define rubidium_generichash_BYTES rubidium_generichash_blake2b_BYTES
RUBIDIUM_EXPORT
size_t  rubidium_generichash_bytes(void);

#define rubidium_generichash_KEYBYTES_MIN rubidium_generichash_blake2b_KEYBYTES_MIN
RUBIDIUM_EXPORT
size_t  rubidium_generichash_keybytes_min(void);

#define rubidium_generichash_KEYBYTES_MAX rubidium_generichash_blake2b_KEYBYTES_MAX
RUBIDIUM_EXPORT
size_t  rubidium_generichash_keybytes_max(void);

#define rubidium_generichash_KEYBYTES rubidium_generichash_blake2b_KEYBYTES
RUBIDIUM_EXPORT
size_t  rubidium_generichash_keybytes(void);

#define rubidium_generichash_PRIMITIVE "blake2b"
RUBIDIUM_EXPORT
const char *rubidium_generichash_primitive(void);

/*
 * Important when writing bindings for other programming languages:
 * the state address should be 64-bytes aligned.
 */
typedef rubidium_generichash_blake2b_state rubidium_generichash_state;

RUBIDIUM_EXPORT
size_t  rubidium_generichash_statebytes(void);

RUBIDIUM_EXPORT
int rubidium_generichash(unsigned char *out, size_t outlen,
                       const unsigned char *in, unsigned long long inlen,
                       const unsigned char *key, size_t keylen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_init(rubidium_generichash_state *state,
                            const unsigned char *key,
                            const size_t keylen, const size_t outlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_update(rubidium_generichash_state *state,
                              const unsigned char *in,
                              unsigned long long inlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_generichash_final(rubidium_generichash_state *state,
                             unsigned char *out, const size_t outlen)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_generichash_keygen(unsigned char k[rubidium_generichash_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
