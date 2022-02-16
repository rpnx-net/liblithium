#include <errno.h>

#include "rubidium_kdf_blake2b.h"
#include "rubidium_generichash_blake2b.h"
#include "private/common.h"

size_t
rubidium_kdf_blake2b_bytes_min(void)
{
    return rubidium_kdf_blake2b_BYTES_MIN;
}

size_t
rubidium_kdf_blake2b_bytes_max(void)
{
    return rubidium_kdf_blake2b_BYTES_MAX;
}

size_t
rubidium_kdf_blake2b_contextbytes(void)
{
    return rubidium_kdf_blake2b_CONTEXTBYTES;
}

size_t
rubidium_kdf_blake2b_keybytes(void)
{
    return rubidium_kdf_blake2b_KEYBYTES;
}

int rubidium_kdf_blake2b_derive_from_key(unsigned char *subkey, size_t subkey_len,
                                       uint64_t subkey_id,
                                       const char ctx[rubidium_kdf_blake2b_CONTEXTBYTES],
                                       const unsigned char key[rubidium_kdf_blake2b_KEYBYTES])
{
    unsigned char ctx_padded[RUBIDIUM_GENERICHASH_BLAKE2B_PERSONALBYTES];
    unsigned char salt[rubidium_generichash_blake2b_SALTBYTES];

    memcpy(ctx_padded, ctx, rubidium_kdf_blake2b_CONTEXTBYTES);
    memset(ctx_padded + rubidium_kdf_blake2b_CONTEXTBYTES, 0, sizeof ctx_padded - rubidium_kdf_blake2b_CONTEXTBYTES);
    store64_le((salt), (subkey_id));
    memset(salt + 8, 0, (sizeof salt) - 8);
    if (subkey_len < rubidium_kdf_blake2b_BYTES_MIN ||
        subkey_len > rubidium_kdf_blake2b_BYTES_MAX) {
        errno = EINVAL;
        return -1;
    }
    return rubidium_generichash_blake2b_salt_personal(subkey, subkey_len,
                                                    NULL, 0,
                                                    key, rubidium_kdf_blake2b_KEYBYTES,
                                                    salt, ctx_padded);
}
