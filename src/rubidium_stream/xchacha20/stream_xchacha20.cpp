
#include <stdlib.h>

#include "rubidium_core_hchacha20.h"
#include "rubidium_stream_chacha20.h"
#include "rubidium_stream_xchacha20.h"
#include "private/common.h"
#include "randombytes.h"

size_t
rubidium_stream_xchacha20_keybytes(void)
{
    return rubidium_stream_xchacha20_KEYBYTES;
}

size_t
rubidium_stream_xchacha20_noncebytes(void)
{
    return rubidium_stream_xchacha20_NONCEBYTES;
}

size_t
rubidium_stream_xchacha20_messagebytes_max(void)
{
    return rubidium_stream_xchacha20_MESSAGEBYTES_MAX;
}

int
rubidium_stream_xchacha20(unsigned char *c, unsigned long long clen,
                        const unsigned char *n, const unsigned char *k)
{
    unsigned char k2[rubidium_core_hchacha20_OUTPUTBYTES];

    rubidium_core_hchacha20(k2, n, k, NULL);
    COMPILER_ASSERT(rubidium_stream_chacha20_KEYBYTES <= sizeof k2);
    COMPILER_ASSERT(rubidium_stream_chacha20_NONCEBYTES ==
                    rubidium_stream_xchacha20_NONCEBYTES -
                    rubidium_core_hchacha20_INPUTBYTES);

    return rubidium_stream_chacha20(c, clen, n + rubidium_core_hchacha20_INPUTBYTES,
                                  k2);
}

int
rubidium_stream_xchacha20_xor_ic(unsigned char *c, const unsigned char *m,
                               unsigned long long mlen, const unsigned char *n,
                               uint64_t ic, const unsigned char *k)
{
    unsigned char k2[rubidium_core_hchacha20_OUTPUTBYTES];

    rubidium_core_hchacha20(k2, n, k, NULL);
    return rubidium_stream_chacha20_xor_ic(
        c, m, mlen, n + rubidium_core_hchacha20_INPUTBYTES, ic, k2);
}

int
rubidium_stream_xchacha20_xor(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k)
{
    return rubidium_stream_xchacha20_xor_ic(c, m, mlen, n, 0U, k);
}

void
rubidium_stream_xchacha20_keygen(
    unsigned char k[rubidium_stream_xchacha20_KEYBYTES])
{
    randombytes_buf(k, rubidium_stream_xchacha20_KEYBYTES);
}
