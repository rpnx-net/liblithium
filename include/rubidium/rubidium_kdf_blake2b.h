#ifndef rubidium_kdf_blake2b_H
#define rubidium_kdf_blake2b_H

#include <cstddef>
#include <cstdint>
#include <stdlib.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_kdf_blake2b_BYTES_MIN 16

size_t rubidium_kdf_blake2b_bytes_min(void);

#define rubidium_kdf_blake2b_BYTES_MAX 64

size_t rubidium_kdf_blake2b_bytes_max(void);

#define rubidium_kdf_blake2b_CONTEXTBYTES 8

size_t rubidium_kdf_blake2b_contextbytes(void);

#define rubidium_kdf_blake2b_KEYBYTES 32

size_t rubidium_kdf_blake2b_keybytes(void);


int rubidium_kdf_blake2b_derive_from_key(unsigned char *subkey, size_t subkey_len,
                                       uint64_t subkey_id,
                                       const char ctx[rubidium_kdf_blake2b_CONTEXTBYTES],
                                       const unsigned char key[rubidium_kdf_blake2b_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
