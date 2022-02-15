#ifndef rubidium_kdf_hkdf_sha256_H
#define rubidium_kdf_hkdf_sha256_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "rubidium_kdf.h"
#include "rubidium_auth_hmacsha256.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_kdf_hkdf_sha256_KEYBYTES rubidium_auth_hmacsha256_BYTES
RUBIDIUM_EXPORT
size_t rubidium_kdf_hkdf_sha256_keybytes(void);

#define rubidium_kdf_hkdf_sha256_BYTES_MIN 0U
RUBIDIUM_EXPORT
size_t rubidium_kdf_hkdf_sha256_bytes_min(void);

#define rubidium_kdf_hkdf_sha256_BYTES_MAX (0xff * rubidium_auth_hmacsha256_BYTES)
RUBIDIUM_EXPORT
size_t rubidium_kdf_hkdf_sha256_bytes_max(void);

RUBIDIUM_EXPORT
int rubidium_kdf_hkdf_sha256_extract(unsigned char prk[rubidium_kdf_hkdf_sha256_KEYBYTES],
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *ikm, size_t ikm_len);

RUBIDIUM_EXPORT
void rubidium_kdf_hkdf_sha256_keygen(unsigned char prk[rubidium_kdf_hkdf_sha256_KEYBYTES]);

RUBIDIUM_EXPORT
int rubidium_kdf_hkdf_sha256_expand(unsigned char *out, size_t out_len,
                                  const char *ctx, size_t ctx_len,
                                  const unsigned char prk[rubidium_kdf_hkdf_sha256_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
