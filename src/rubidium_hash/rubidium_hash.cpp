
#include "rubidium_hash.h"

size_t
rubidium_hash_bytes(void)
{
    return rubidium_hash_BYTES;
}

int
rubidium_hash(unsigned char *out, const unsigned char *in,
            std::size_t inlen)
{
    return rubidium_hash_sha512(out, in, inlen);
}

const char *
rubidium_hash_primitive(void) {
    return rubidium_hash_PRIMITIVE;
}
