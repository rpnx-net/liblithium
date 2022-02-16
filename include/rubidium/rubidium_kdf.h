#ifndef rubidium_kdf_H
#define rubidium_kdf_H

#include <cstddef>
#include <cstdint>

#include "rubidium_kdf_blake2b.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_kdf_BYTES_MIN rubidium_kdf_blake2b_BYTES_MIN
RUBIDIUM_EXPORT
size_t rubidium_kdf_bytes_min(void);

#define rubidium_kdf_BYTES_MAX rubidium_kdf_blake2b_BYTES_MAX
RUBIDIUM_EXPORT
size_t rubidium_kdf_bytes_max(void);

#define rubidium_kdf_CONTEXTBYTES rubidium_kdf_blake2b_CONTEXTBYTES
RUBIDIUM_EXPORT
size_t rubidium_kdf_contextbytes(void);

#define rubidium_kdf_KEYBYTES rubidium_kdf_blake2b_KEYBYTES
RUBIDIUM_EXPORT
size_t rubidium_kdf_keybytes(void);

#define rubidium_kdf_PRIMITIVE "blake2b"
RUBIDIUM_EXPORT
const char *rubidium_kdf_primitive(void)
            __attribute__ ((warn_unused_result));

RUBIDIUM_EXPORT
int rubidium_kdf_derive_from_key(unsigned char *subkey, size_t subkey_len,
                               uint64_t subkey_id,
                               const char ctx[rubidium_kdf_CONTEXTBYTES],
                               const unsigned char key[rubidium_kdf_KEYBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_kdf_keygen(unsigned char k[rubidium_kdf_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
