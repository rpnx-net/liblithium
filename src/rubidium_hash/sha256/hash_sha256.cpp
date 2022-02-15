#include "rubidium_hash_sha256.h"

size_t
rubidium_hash_sha256_bytes(void)
{
    return rubidium_hash_sha256_BYTES;
}

size_t
rubidium_hash_sha256_statebytes(void)
{
    return sizeof(rubidium_hash_sha256_state);
}
