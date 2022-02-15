#include "rubidium_core_hsalsa20.h"
#include "rubidium_stream_salsa20.h"
#include "rubidium_stream_xsalsa20.h"
#include "randombytes.h"
#include "utils.h"

int
rubidium_stream_xsalsa20(unsigned char *c, unsigned long long clen,
                       const unsigned char *n, const unsigned char *k)
{
    unsigned char subkey[32];
    int           ret;

    rubidium_core_hsalsa20(subkey, n, k, NULL);
    ret = rubidium_stream_salsa20(c, clen, n + 16, subkey);
    rubidium_memzero(subkey, sizeof subkey);

    return ret;
}

int
rubidium_stream_xsalsa20_xor_ic(unsigned char *c, const unsigned char *m,
                              unsigned long long mlen, const unsigned char *n,
                              uint64_t ic, const unsigned char *k)
{
    unsigned char subkey[32];
    int           ret;

    rubidium_core_hsalsa20(subkey, n, k, NULL);
    ret = rubidium_stream_salsa20_xor_ic(c, m, mlen, n + 16, ic, subkey);
    rubidium_memzero(subkey, sizeof subkey);

    return ret;
}

int
rubidium_stream_xsalsa20_xor(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           const unsigned char *k)
{
    return rubidium_stream_xsalsa20_xor_ic(c, m, mlen, n, 0ULL, k);
}

size_t
rubidium_stream_xsalsa20_keybytes(void)
{
    return rubidium_stream_xsalsa20_KEYBYTES;
}

size_t
rubidium_stream_xsalsa20_noncebytes(void)
{
    return rubidium_stream_xsalsa20_NONCEBYTES;
}

size_t
rubidium_stream_xsalsa20_messagebytes_max(void)
{
    return rubidium_stream_xsalsa20_MESSAGEBYTES_MAX;
}

void
rubidium_stream_xsalsa20_keygen(unsigned char k[rubidium_stream_xsalsa20_KEYBYTES])
{
    randombytes_buf(k, rubidium_stream_xsalsa20_KEYBYTES);
}
