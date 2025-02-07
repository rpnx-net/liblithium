#ifndef rubidium_kdf_H
#define rubidium_kdf_H

#include <cstddef>
#include <cstdint>

#include "rubidium_kdf_blake2b.h"
#include "export.h"



#define rubidium_kdf_BYTES_MIN rubidium_kdf_blake2b_BYTES_MIN

size_t rubidium_kdf_bytes_min(void);

#define rubidium_kdf_BYTES_MAX rubidium_kdf_blake2b_BYTES_MAX

size_t rubidium_kdf_bytes_max(void);

#define rubidium_kdf_CONTEXTBYTES rubidium_kdf_blake2b_CONTEXTBYTES

size_t rubidium_kdf_contextbytes(void);

#define rubidium_kdf_KEYBYTES rubidium_kdf_blake2b_KEYBYTES

size_t rubidium_kdf_keybytes(void);

#define rubidium_kdf_PRIMITIVE "blake2b"

const char *rubidium_kdf_primitive(void)
            __attribute__ ((warn_unused_result));


int rubidium_kdf_derive_from_key(unsigned char *subkey, size_t subkey_len,
                               uint64_t subkey_id,
                               const char ctx[rubidium_kdf_CONTEXTBYTES],
                               const unsigned char key[rubidium_kdf_KEYBYTES])
            __attribute__ ((nonnull));


void rubidium_kdf_keygen(unsigned char k[rubidium_kdf_KEYBYTES])
            __attribute__ ((nonnull));



#endif
