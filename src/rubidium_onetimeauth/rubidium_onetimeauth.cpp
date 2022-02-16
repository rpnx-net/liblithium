
#include "rubidium_onetimeauth.h"
#include "randombytes.h"

size_t
rubidium_onetimeauth_statebytes(void)
{
    return sizeof(rubidium_onetimeauth_state);
}

size_t
rubidium_onetimeauth_bytes(void)
{
    return rubidium_onetimeauth_BYTES;
}

size_t
rubidium_onetimeauth_keybytes(void)
{
    return rubidium_onetimeauth_KEYBYTES;
}

int
rubidium_onetimeauth(unsigned char *out, const unsigned char *in,
                   std::size_t inlen, const unsigned char *k)
{
    return rubidium_onetimeauth_poly1305(out, in, inlen, k);
}

int
rubidium_onetimeauth_verify(const unsigned char *h, const unsigned char *in,
                          std::size_t inlen, const unsigned char *k)
{
    return rubidium_onetimeauth_poly1305_verify(h, in, inlen, k);
}

int
rubidium_onetimeauth_init(rubidium_onetimeauth_state *state,
                        const unsigned char *key)
{
    return rubidium_onetimeauth_poly1305_init
        ((rubidium_onetimeauth_poly1305_state *) state, key);
}

int
rubidium_onetimeauth_update(rubidium_onetimeauth_state *state,
                          const unsigned char *in,
                          std::size_t inlen)
{
    return rubidium_onetimeauth_poly1305_update
        ((rubidium_onetimeauth_poly1305_state *) state, in, inlen);
}

int
rubidium_onetimeauth_final(rubidium_onetimeauth_state *state,
                         unsigned char *out)
{
    return rubidium_onetimeauth_poly1305_final
        ((rubidium_onetimeauth_poly1305_state *) state, out);
}

const char *
rubidium_onetimeauth_primitive(void)
{
    return rubidium_onetimeauth_PRIMITIVE;
}

void rubidium_onetimeauth_keygen(unsigned char k[rubidium_onetimeauth_KEYBYTES])
{
    randombytes_buf(k, rubidium_onetimeauth_KEYBYTES);
}
