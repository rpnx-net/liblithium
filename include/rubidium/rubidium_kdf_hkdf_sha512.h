#ifndef rubidium_kdf_hkdf_sha512_H
#define rubidium_kdf_hkdf_sha512_H

#include <cstddef>
#include <cstdint>
#include <stdlib.h>

#include "rubidium_kdf.h"
#include "rubidium_auth_hmacsha512.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_kdf_hkdf_sha512_KEYBYTES rubidium_auth_hmacsha512_BYTES
RUBIDIUM_EXPORT
size_t rubidium_kdf_hkdf_sha512_keybytes(void);

#define rubidium_kdf_hkdf_sha512_BYTES_MIN 0U
RUBIDIUM_EXPORT
size_t rubidium_kdf_hkdf_sha512_bytes_min(void);

#define rubidium_kdf_hkdf_sha512_BYTES_MAX (0xff * rubidium_auth_hmacsha512_BYTES)
RUBIDIUM_EXPORT
size_t rubidium_kdf_hkdf_sha512_bytes_max(void);

RUBIDIUM_EXPORT
int rubidium_kdf_hkdf_sha512_extract(unsigned char prk[rubidium_kdf_hkdf_sha512_KEYBYTES],
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *ikm, size_t ikm_len)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
void rubidium_kdf_hkdf_sha512_keygen(unsigned char prk[rubidium_kdf_hkdf_sha512_KEYBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_kdf_hkdf_sha512_expand(unsigned char *out, size_t out_len,
                                  const char *ctx, size_t ctx_len,
                                  const unsigned char prk[rubidium_kdf_hkdf_sha512_KEYBYTES])
            __attribute__ ((nonnull(1)));

#ifdef __cplusplus
}
#endif

#endif
