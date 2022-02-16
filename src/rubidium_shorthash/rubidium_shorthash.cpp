
#include "rubidium_shorthash.h"
#include "randombytes.h"

size_t
rubidium_shorthash_bytes(void)
{
    return rubidium_shorthash_BYTES;
}

size_t
rubidium_shorthash_keybytes(void)
{
    return rubidium_shorthash_KEYBYTES;
}

const char *
rubidium_shorthash_primitive(void)
{
    return rubidium_shorthash_PRIMITIVE;
}

int
rubidium_shorthash(unsigned char *out, const unsigned char *in,
                 std::size_t inlen, const unsigned char *k)
{
    return rubidium_shorthash_siphash24(out, in, inlen, k);
}

void
rubidium_shorthash_keygen(unsigned char k[rubidium_shorthash_KEYBYTES])
{
    randombytes_buf(k, rubidium_shorthash_KEYBYTES);
}
