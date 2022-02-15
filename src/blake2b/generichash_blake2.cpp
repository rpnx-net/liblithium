#include "rubidium_generichash_blake2b.h"
#include "randombytes.h"

size_t
rubidium_generichash_blake2b_bytes_min(void) {
    return rubidium_generichash_blake2b_BYTES_MIN;
}

size_t
rubidium_generichash_blake2b_bytes_max(void) {
    return rubidium_generichash_blake2b_BYTES_MAX;
}

size_t
rubidium_generichash_blake2b_bytes(void) {
    return rubidium_generichash_blake2b_BYTES;
}

size_t
rubidium_generichash_blake2b_keybytes_min(void) {
    return rubidium_generichash_blake2b_KEYBYTES_MIN;
}

size_t
rubidium_generichash_blake2b_keybytes_max(void) {
    return rubidium_generichash_blake2b_KEYBYTES_MAX;
}

size_t
rubidium_generichash_blake2b_keybytes(void) {
    return rubidium_generichash_blake2b_KEYBYTES;
}

size_t
rubidium_generichash_blake2b_saltbytes(void) {
    return rubidium_generichash_blake2b_SALTBYTES;
}

size_t
rubidium_generichash_blake2b_personalbytes(void) {
    return RUBIDIUM_GENERICHASH_BLAKE2B_PERSONALBYTES;
}

size_t
rubidium_generichash_blake2b_statebytes(void)
{
    return (sizeof(rubidium_generichash_blake2b_state) + (size_t) 63U)
        & ~(size_t) 63U;
}

void
rubidium_generichash_blake2b_keygen(unsigned char k[rubidium_generichash_blake2b_KEYBYTES])
{
    randombytes_buf(k, rubidium_generichash_blake2b_KEYBYTES);
}
