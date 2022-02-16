#ifndef rubidium_kdf_hkdf_sha256_H
#define rubidium_kdf_hkdf_sha256_H

#include <cstddef>
#include <cstdint>
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

size_t rubidium_kdf_hkdf_sha256_keybytes(void);

#define rubidium_kdf_hkdf_sha256_BYTES_MIN 0U

size_t rubidium_kdf_hkdf_sha256_bytes_min(void);

#define rubidium_kdf_hkdf_sha256_BYTES_MAX (0xff * rubidium_auth_hmacsha256_BYTES)

size_t rubidium_kdf_hkdf_sha256_bytes_max(void);


int rubidium_kdf_hkdf_sha256_extract(unsigned char prk[rubidium_kdf_hkdf_sha256_KEYBYTES],
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *ikm, size_t ikm_len);


void rubidium_kdf_hkdf_sha256_keygen(unsigned char prk[rubidium_kdf_hkdf_sha256_KEYBYTES]);


int rubidium_kdf_hkdf_sha256_expand(unsigned char *out, size_t out_len,
                                  const char *ctx, size_t ctx_len,
                                  const unsigned char prk[rubidium_kdf_hkdf_sha256_KEYBYTES]);

#ifdef __cplusplus
}
#endif

#endif
