
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <cstring>
#include <stdexcept>


#include "rubidium_core_hchacha20.h"
#include "rubidium_onetimeauth_poly1305.h"
#include "rubidium_secretbox_xchacha20poly1305.h"
#include "rubidium_stream_chacha20.h"
#include "private/common.h"
#include "utils.h"

#define RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES 32U

int
rubidium_secretbox_xchacha20poly1305_detached(unsigned char *c,
                                            unsigned char *mac,
                                            const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *n,
                                            const unsigned char *k)
{
    rubidium_onetimeauth_poly1305_state state;
    unsigned char                     block0[64U];
    unsigned char                     subkey[RUBIDIUM_STREAM_CHACHA20_KEYBYTES];
    unsigned long long                mlen0;

    rubidium_core_hchacha20(subkey, n, k, NULL);

    /*
     * Allow the m and c buffers to partially overlap, by calling
     * memmove() if necessary.
     *
     * Note that there is no fully portable way to compare pointers.
     * Some tools even report undefined behavior, despite the conversion.
     * Nevertheless, this works on all supported platforms.
     */
    if (((uintptr_t) c > (uintptr_t) m &&
         (uintptr_t) c - (uintptr_t) m < mlen) ||
        ((uintptr_t) m > (uintptr_t) c &&
         (uintptr_t) m - (uintptr_t) c < mlen)) { /* LCOV_EXCL_LINE */
        std::memmove(c, m, mlen);
        m = c;
    }
    memset(block0, 0U, RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES);
    static_assert(64U >= RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES);
    mlen0 = mlen;
    if (mlen0 > 64U - RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES) {
        mlen0 = 64U - RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES;
    }
    for (std::size_t i = 0; i < mlen0; i++) {
        block0[i + RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES] = m[i];
    }
    rubidium_stream_chacha20_xor(block0, block0,
                                 mlen0 + RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES,
                               n + 16, subkey);
    static_assert(RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES >=
                  RUBIDIUM_ONETIMEAUTH_POLY1305_KEYBYTES);
    rubidium_onetimeauth_poly1305_init(&state, block0);

    for (std::size_t i = 0U; i < mlen0; i++) {
        c[i] = block0[RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES + i];
    }
    rubidium_memzero(block0, sizeof block0);
    if (mlen > mlen0) {
        rubidium_stream_chacha20_xor_ic(c + mlen0, m + mlen0, mlen - mlen0,
                                      n + 16, 1U, subkey);
    }
    rubidium_memzero(subkey, sizeof subkey);

    rubidium_onetimeauth_poly1305_update(&state, c, mlen);
    rubidium_onetimeauth_poly1305_final(&state, mac);
    rubidium_memzero(&state, sizeof state);

    return 0;
}

int
rubidium_secretbox_xchacha20poly1305_easy(unsigned char *c,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *n,
                                        const unsigned char *k)
{
    if (mlen > RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("mlen > RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MESSAGEBYTES_MAX");
    }
    return rubidium_secretbox_xchacha20poly1305_detached
        (c + RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES, c, m, mlen, n, k);
}

int
rubidium_secretbox_xchacha20poly1305_open_detached(unsigned char *m,
                                                 const unsigned char *c,
                                                 const unsigned char *mac,
                                                 unsigned long long clen,
                                                 const unsigned char *n,
                                                 const unsigned char *k)
{
    unsigned char      block0[64U];
    unsigned char      subkey[RUBIDIUM_STREAM_CHACHA20_KEYBYTES];
    unsigned long long i;
    unsigned long long mlen0;

    rubidium_core_hchacha20(subkey, n, k, NULL);

    memset(block0, 0, RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES);
    mlen0 = clen;
    if (mlen0 > 64U - RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES) {
        mlen0 = 64U - RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES;
    }
    for (i = 0U; i < mlen0; i++) {
        block0[RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES + i] = c[i];
    }
    rubidium_stream_chacha20_xor(block0, block0, 64, n + 16, subkey);
    if (rubidium_onetimeauth_poly1305_verify(mac, c, clen, block0) != 0) {
        rubidium_memzero(subkey, sizeof subkey);
        return -1;
    }
    if (m == NULL) {
        return 0;
    }

    /*
     * Allow the m and c buffers to partially overlap, by calling
     * memmove() if necessary.
     *
     * Note that there is no fully portable way to compare pointers.
     * Some tools even report undefined behavior, despite the conversion.
     * Nevertheless, this works on all supported platforms.
     */
    if (((uintptr_t) c > (uintptr_t) m &&
         (uintptr_t) c - (uintptr_t) m < clen) ||
        ((uintptr_t) m > (uintptr_t) c &&
         (uintptr_t) m - (uintptr_t) c < clen)) { /* LCOV_EXCL_LINE */
        memmove(m, c, clen);
        c = m;
    }
    for (i = 0U; i < mlen0; i++) {
        m[i] = block0[RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_ZEROBYTES + i];
    }
    if (clen > mlen0) {
        rubidium_stream_chacha20_xor_ic(m + mlen0, c + mlen0, clen - mlen0,
                                      n + 16, 1U, subkey);
    }
    rubidium_memzero(subkey, sizeof subkey);

    return 0;
}

int
rubidium_secretbox_xchacha20poly1305_open_easy(unsigned char *m,
                                             const unsigned char *c,
                                             unsigned long long clen,
                                             const unsigned char *n,
                                             const unsigned char *k)
{
    if (clen < RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES) {
        return -1;
    }
    return rubidium_secretbox_xchacha20poly1305_open_detached
        (m, c + RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES, c,
         clen - RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES, n, k);
}

size_t
rubidium_secretbox_xchacha20poly1305_keybytes(void)
{
    return RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_KEYBYTES;
}

size_t
rubidium_secretbox_xchacha20poly1305_noncebytes(void)
{
    return RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_NONCEBYTES;
}

size_t
rubidium_secretbox_xchacha20poly1305_macbytes(void)
{
    return RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES;
}

size_t
rubidium_secretbox_xchacha20poly1305_messagebytes_max(void)
{
    return RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MESSAGEBYTES_MAX;
}
