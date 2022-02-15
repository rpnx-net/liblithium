
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core.h"
#include "rubidium_core_hchacha20.h"
#include "rubidium_onetimeauth_poly1305.h"
#include "rubidium_secretbox_xchacha20poly1305.h"
#include "rubidium_stream_chacha20.h"
#include "private/common.h"
#include "utils.h"

#define rubidium_secretbox_xchacha20poly1305_ZEROBYTES 32U

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
    unsigned char                     subkey[rubidium_stream_chacha20_KEYBYTES];
    unsigned long long                i;
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
        memmove(c, m, mlen);
        m = c;
    }
    memset(block0, 0U, rubidium_secretbox_xchacha20poly1305_ZEROBYTES);
    COMPILER_ASSERT(64U >= rubidium_secretbox_xchacha20poly1305_ZEROBYTES);
    mlen0 = mlen;
    if (mlen0 > 64U - rubidium_secretbox_xchacha20poly1305_ZEROBYTES) {
        mlen0 = 64U - rubidium_secretbox_xchacha20poly1305_ZEROBYTES;
    }
    for (i = 0U; i < mlen0; i++) {
        block0[i + rubidium_secretbox_xchacha20poly1305_ZEROBYTES] = m[i];
    }
    rubidium_stream_chacha20_xor(block0, block0,
                               mlen0 + rubidium_secretbox_xchacha20poly1305_ZEROBYTES,
                               n + 16, subkey);
    COMPILER_ASSERT(rubidium_secretbox_xchacha20poly1305_ZEROBYTES >=
                    rubidium_onetimeauth_poly1305_KEYBYTES);
    rubidium_onetimeauth_poly1305_init(&state, block0);

    for (i = 0U; i < mlen0; i++) {
        c[i] = block0[rubidium_secretbox_xchacha20poly1305_ZEROBYTES + i];
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
    if (mlen > rubidium_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX) {
        rubidium_misuse();
    }
    return rubidium_secretbox_xchacha20poly1305_detached
        (c + rubidium_secretbox_xchacha20poly1305_MACBYTES, c, m, mlen, n, k);
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
    unsigned char      subkey[rubidium_stream_chacha20_KEYBYTES];
    unsigned long long i;
    unsigned long long mlen0;

    rubidium_core_hchacha20(subkey, n, k, NULL);

    memset(block0, 0, rubidium_secretbox_xchacha20poly1305_ZEROBYTES);
    mlen0 = clen;
    if (mlen0 > 64U - rubidium_secretbox_xchacha20poly1305_ZEROBYTES) {
        mlen0 = 64U - rubidium_secretbox_xchacha20poly1305_ZEROBYTES;
    }
    for (i = 0U; i < mlen0; i++) {
        block0[rubidium_secretbox_xchacha20poly1305_ZEROBYTES + i] = c[i];
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
        m[i] = block0[rubidium_secretbox_xchacha20poly1305_ZEROBYTES + i];
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
    if (clen < rubidium_secretbox_xchacha20poly1305_MACBYTES) {
        return -1;
    }
    return rubidium_secretbox_xchacha20poly1305_open_detached
        (m, c + rubidium_secretbox_xchacha20poly1305_MACBYTES, c,
         clen - rubidium_secretbox_xchacha20poly1305_MACBYTES, n, k);
}

size_t
rubidium_secretbox_xchacha20poly1305_keybytes(void)
{
    return rubidium_secretbox_xchacha20poly1305_KEYBYTES;
}

size_t
rubidium_secretbox_xchacha20poly1305_noncebytes(void)
{
    return rubidium_secretbox_xchacha20poly1305_NONCEBYTES;
}

size_t
rubidium_secretbox_xchacha20poly1305_macbytes(void)
{
    return rubidium_secretbox_xchacha20poly1305_MACBYTES;
}

size_t
rubidium_secretbox_xchacha20poly1305_messagebytes_max(void)
{
    return rubidium_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX;
}
