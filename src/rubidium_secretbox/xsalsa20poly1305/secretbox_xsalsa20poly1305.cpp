#include "rubidium_onetimeauth_poly1305.h"
#include "rubidium_secretbox_xsalsa20poly1305.h"
#include "rubidium_stream_xsalsa20.h"
#include "randombytes.h"

int
rubidium_secretbox_xsalsa20poly1305(unsigned char *c, const unsigned char *m,
                                  std::size_t mlen,
                                  const unsigned char *n,
                                  const unsigned char *k)
{
    int i;

    if (mlen < 32) {
        return -1;
    }
    rubidium_stream_xsalsa20_xor(c, m, mlen, n, k);
    rubidium_onetimeauth_poly1305(c + 16, c + 32, mlen - 32, c);
    for (i = 0; i < 16; ++i) {
        c[i] = 0;
    }
    return 0;
}

int
rubidium_secretbox_xsalsa20poly1305_open(unsigned char *m, const unsigned char *c,
                                       std::size_t clen,
                                       const unsigned char *n,
                                       const unsigned char *k)
{
    unsigned char subkey[32];
    int           i;

    if (clen < 32) {
        return -1;
    }
    rubidium_stream_xsalsa20(subkey, 32, n, k);
    if (rubidium_onetimeauth_poly1305_verify(c + 16, c + 32,
                                           clen - 32, subkey) != 0) {
        return -1;
    }
    rubidium_stream_xsalsa20_xor(m, c, clen, n, k);
    for (i = 0; i < 32; ++i) {
        m[i] = 0;
    }
    return 0;
}

size_t
rubidium_secretbox_xsalsa20poly1305_keybytes(void)
{
    return rubidium_secretbox_xsalsa20poly1305_KEYBYTES;
}

size_t
rubidium_secretbox_xsalsa20poly1305_noncebytes(void)
{
    return rubidium_secretbox_xsalsa20poly1305_NONCEBYTES;
}

size_t
rubidium_secretbox_xsalsa20poly1305_zerobytes(void)
{
    return rubidium_secretbox_xsalsa20poly1305_ZEROBYTES;
}

size_t
rubidium_secretbox_xsalsa20poly1305_boxzerobytes(void)
{
    return rubidium_secretbox_xsalsa20poly1305_BOXZEROBYTES;
}

size_t
rubidium_secretbox_xsalsa20poly1305_macbytes(void)
{
    return rubidium_secretbox_xsalsa20poly1305_MACBYTES;
}

size_t
rubidium_secretbox_xsalsa20poly1305_messagebytes_max(void)
{
    return rubidium_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX;
}

void
rubidium_secretbox_xsalsa20poly1305_keygen(unsigned char k[rubidium_secretbox_xsalsa20poly1305_KEYBYTES])
{
    randombytes_buf(k, rubidium_secretbox_xsalsa20poly1305_KEYBYTES);
}
