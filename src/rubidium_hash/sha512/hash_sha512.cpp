#include "rubidium_hash_sha512.h"

size_t
rubidium_hash_sha512_bytes(void)
{
    return rubidium_hash_sha512_BYTES;
}

size_t
rubidium_hash_sha512_statebytes(void)
{
    return sizeof(rubidium_hash_sha512_state);
}
