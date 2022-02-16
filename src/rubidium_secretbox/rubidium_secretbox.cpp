
#include "rubidium_secretbox.h"
#include "randombytes.h"

size_t
rubidium_secretbox_keybytes(void)
{
    return rubidium_secretbox_KEYBYTES;
}

size_t
rubidium_secretbox_noncebytes(void)
{
    return rubidium_secretbox_NONCEBYTES;
}

size_t
rubidium_secretbox_zerobytes(void)
{
    return rubidium_secretbox_ZEROBYTES;
}

size_t
rubidium_secretbox_boxzerobytes(void)
{
    return rubidium_secretbox_BOXZEROBYTES;
}

size_t
rubidium_secretbox_macbytes(void)
{
    return rubidium_secretbox_MACBYTES;
}

size_t
rubidium_secretbox_messagebytes_max(void)
{
    return rubidium_secretbox_MESSAGEBYTES_MAX;
}

const char *
rubidium_secretbox_primitive(void)
{
    return rubidium_secretbox_PRIMITIVE;
}

int
rubidium_secretbox(unsigned char *c, const unsigned char *m,
                 std::size_t mlen, const unsigned char *n,
                 const unsigned char *k)
{
    return rubidium_secretbox_xsalsa20poly1305(c, m, mlen, n, k);
}

int
rubidium_secretbox_open(unsigned char *m, const unsigned char *c,
                      std::size_t clen, const unsigned char *n,
                      const unsigned char *k)
{
    return rubidium_secretbox_xsalsa20poly1305_open(m, c, clen, n, k);
}

void
rubidium_secretbox_keygen(unsigned char k[rubidium_secretbox_KEYBYTES])
{
    randombytes_buf(k, rubidium_secretbox_KEYBYTES);
}
