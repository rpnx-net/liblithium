
#include "rubidium_auth.h"
#include "randombytes.h"

size_t
rubidium_auth_bytes(void)
{
    return rubidium_auth_BYTES;
}

size_t
rubidium_auth_keybytes(void)
{
    return rubidium_auth_KEYBYTES;
}

const char *
rubidium_auth_primitive(void)
{
    return rubidium_auth_PRIMITIVE;
}

int
rubidium_auth(unsigned char *out, const unsigned char *in,
            unsigned long long inlen, const unsigned char *k)
{
    return rubidium_auth_hmacsha512256(out, in, inlen, k);
}

int
rubidium_auth_verify(const unsigned char *h, const unsigned char *in,
                   unsigned long long inlen,const unsigned char *k)
{
    return rubidium_auth_hmacsha512256_verify(h, in, inlen, k);
}

void
rubidium_auth_keygen(unsigned char k[rubidium_auth_KEYBYTES])
{
    randombytes_buf(k, rubidium_auth_KEYBYTES);
}
