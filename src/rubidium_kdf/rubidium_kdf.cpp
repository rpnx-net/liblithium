
#include "rubidium_kdf.h"
#include "randombytes.h"

const char *
rubidium_kdf_primitive(void)
{
    return rubidium_kdf_PRIMITIVE;
}

size_t
rubidium_kdf_bytes_min(void)
{
    return rubidium_kdf_BYTES_MIN;
}

size_t
rubidium_kdf_bytes_max(void)
{
    return rubidium_kdf_BYTES_MAX;
}

size_t
rubidium_kdf_contextbytes(void)
{
    return rubidium_kdf_CONTEXTBYTES;
}

size_t
rubidium_kdf_keybytes(void)
{
    return rubidium_kdf_KEYBYTES;
}

int
rubidium_kdf_derive_from_key(unsigned char *subkey, size_t subkey_len,
                           uint64_t subkey_id,
                           const char ctx[rubidium_kdf_CONTEXTBYTES],
                           const unsigned char key[rubidium_kdf_KEYBYTES])
{
    return rubidium_kdf_blake2b_derive_from_key(subkey, subkey_len,
                                              subkey_id, ctx, key);
}

void
rubidium_kdf_keygen(unsigned char k[rubidium_kdf_KEYBYTES])
{
    randombytes_buf(k, rubidium_kdf_KEYBYTES);
}
