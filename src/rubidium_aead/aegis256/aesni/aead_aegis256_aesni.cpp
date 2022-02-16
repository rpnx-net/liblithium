/*
 * AEGIS-256 based on https://bench.cr.yp.to/supercop/supercop-20190816.tar.xz
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>


#include "rubidium_aead_aegis256.h"
#include "rubidium_verify_16.h"
#include "export.h"
#include "randombytes.h"
#include "runtime.h"
#include "utils.h"

#include "private/common.h"

#if defined(HAVE_TMMINTRIN_H) && defined(HAVE_WMMINTRIN_H)

#ifdef __GNUC__
# pragma GCC target("ssse3")
# pragma GCC target("aes")
#endif

#include <tmmintrin.h>
#include <wmmintrin.h>
#include "private/sse2_64_32.h"

static inline void
rubidium_aead_aegis256_update(__m128i *const state, const __m128i data)
{
    __m128i tmp;

    tmp      = _mm_aesenc_si128(state[5], state[0]);
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = _mm_xor_si128(tmp, data);
}

static void
rubidium_aead_aegis256_init(const unsigned char *key, const unsigned char *nonce, __m128i *const state)
{
    const __m128i c0 = _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, 0xf1, 0x2f, 0xc2, 0x6d,
                                    0x55, 0x18, 0x3d, 0xdb);
    const __m128i c1 = _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, 0x0d, 0x08, 0x05, 0x03,
                                    0x02, 0x01, 0x01, 0x00);
    __m128i       k1, k2;
    __m128i       kxn1, kxn2;
    int           i;

    k1 = _mm_loadu_si128((const __m128i *) (const void *) &key[0]);
    k2 = _mm_loadu_si128((const __m128i *) (const void *) &key[16]);
    kxn1 = _mm_xor_si128(k1, _mm_loadu_si128((__m128i *) (void *) &nonce[0]));
    kxn2 = _mm_xor_si128(k2, _mm_loadu_si128((__m128i *) (void *) &nonce[16]));

    state[0] = kxn1;
    state[1] = kxn2;
    state[2] = c0;
    state[3] = c1;
    state[4] = _mm_xor_si128(k1, c1);
    state[5] = _mm_xor_si128(k2, c0);

    for (i = 0; i < 4; i++) {
        rubidium_aead_aegis256_update(state, k1);
        rubidium_aead_aegis256_update(state, k2);
        rubidium_aead_aegis256_update(state, kxn1);
        rubidium_aead_aegis256_update(state, kxn2);
    }
}

static void
rubidium_aead_aegis256_mac(unsigned char *mac, std::size_t adlen, std::size_t mlen,
                         __m128i *const state)
{
    __m128i tmp;
    int     i;

    tmp = _mm_set_epi64x(mlen << 3, adlen << 3);
    tmp = _mm_xor_si128(tmp, state[3]);

    for (i = 0; i < 7; i++) {
        rubidium_aead_aegis256_update(state, tmp);
    }

    tmp = _mm_xor_si128(state[5], state[4]);
    tmp = _mm_xor_si128(tmp, state[3]);
    tmp = _mm_xor_si128(tmp, state[2]);
    tmp = _mm_xor_si128(tmp, state[1]);
    tmp = _mm_xor_si128(tmp, state[0]);

    _mm_storeu_si128((__m128i *) (void *) mac, tmp);
}

static void
rubidium_aead_aegis256_enc(unsigned char *const dst, const unsigned char *const src,
                         __m128i *const state)
{
    __m128i msg;
    __m128i tmp;

    msg = _mm_loadu_si128((const __m128i *) (const void *) src);
    tmp = _mm_xor_si128(msg, state[5]);
    tmp = _mm_xor_si128(tmp, state[4]);
    tmp = _mm_xor_si128(tmp, state[1]);
    tmp = _mm_xor_si128(tmp, _mm_and_si128(state[2], state[3]));
    _mm_storeu_si128((__m128i *) (void *) dst, tmp);

    rubidium_aead_aegis256_update(state, msg);
}

static void
rubidium_aead_aegis256_dec(unsigned char *const dst, const unsigned char *const src,
                         __m128i *const state)
{
    __m128i msg;

    msg = _mm_loadu_si128((const __m128i *) (const void *) src);
    msg = _mm_xor_si128(msg, state[5]);
    msg = _mm_xor_si128(msg, state[4]);
    msg = _mm_xor_si128(msg, state[1]);
    msg = _mm_xor_si128(msg, _mm_and_si128(state[2], state[3]));
    _mm_storeu_si128((__m128i *) (void *) dst, msg);

    rubidium_aead_aegis256_update(state, msg);
}

int
rubidium_aead_aegis256_encrypt_detached(unsigned char *c, unsigned char *mac,
                                      std::size_t *maclen_p, const unsigned char *m,
                                      std::size_t mlen, const unsigned char *ad,
                                      std::size_t adlen, const unsigned char *nsec,
                                      const unsigned char *npub, const unsigned char *k)
{
    __m128i                        state[6];
    RUBIDIUM_ALIGN(16) unsigned char src[16];
    RUBIDIUM_ALIGN(16) unsigned char dst[16];
    std::size_t i;

    (void) nsec;
    rubidium_aead_aegis256_init(k, npub, state);

    for (i = 0ULL; i + 16ULL <= adlen; i += 16ULL) {
        rubidium_aead_aegis256_enc(dst, ad + i, state);
    }
    if (adlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, ad + i, adlen & 0xf);
        rubidium_aead_aegis256_enc(dst, src, state);
    }
    for (i = 0ULL; i + 16ULL <= mlen; i += 16ULL) {
        rubidium_aead_aegis256_enc(c + i, m + i, state);
    }
    if (mlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, m + i, mlen & 0xf);
        rubidium_aead_aegis256_enc(dst, src, state);
        memcpy(c + i, dst, mlen & 0xf);
    }

    rubidium_aead_aegis256_mac(mac, adlen, mlen, state);
    rubidium_memzero(state, sizeof state);
    rubidium_memzero(src, sizeof src);
    rubidium_memzero(dst, sizeof dst);

    if (maclen_p != NULL) {
        *maclen_p = 16ULL;
    }
    return 0;
}

int
rubidium_aead_aegis256_encrypt(unsigned char *c, std::size_t *clen_p, const unsigned char *m,
                             std::size_t mlen, const unsigned char *ad,
                             std::size_t adlen, const unsigned char *nsec,
                             const unsigned char *npub, const unsigned char *k)
{
    std::size_t clen = 0ULL;
    int                ret;

    if (mlen > rubidium_aead_aegis256_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    ret = rubidium_aead_aegis256_encrypt_detached(c, c + mlen, NULL, m, mlen,
                                                ad, adlen, nsec, npub, k);
    if (clen_p != NULL) {
        if (ret == 0) {
            clen = mlen + 16ULL;
        }
        *clen_p = clen;
    }
    return ret;
}

int
rubidium_aead_aegis256_decrypt_detached(unsigned char *m, unsigned char *nsec, const unsigned char *c,
                                      std::size_t clen, const unsigned char *mac,
                                      const unsigned char *ad, std::size_t adlen,
                                      const unsigned char *npub, const unsigned char *k)
{
    __m128i                        state[6];
    RUBIDIUM_ALIGN(16) unsigned char src[16];
    RUBIDIUM_ALIGN(16) unsigned char dst[16];
    RUBIDIUM_ALIGN(16) unsigned char computed_mac[16];
    std::size_t i;
    std::size_t mlen;
    int                ret;

    (void) nsec;
    mlen = clen;
    rubidium_aead_aegis256_init(k, npub, state);

    for (i = 0ULL; i + 16ULL <= adlen; i += 16ULL) {
        rubidium_aead_aegis256_enc(dst, ad + i, state);
    }
    if (adlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, ad + i, adlen & 0xf);
        rubidium_aead_aegis256_enc(dst, src, state);
    }
    if (m != NULL) {
        for (i = 0ULL; i + 16ULL <= mlen; i += 16ULL) {
            rubidium_aead_aegis256_dec(m + i, c + i, state);
        }
    } else {
        for (i = 0ULL; i + 16ULL <= mlen; i += 16ULL) {
            rubidium_aead_aegis256_dec(dst, c + i, state);
        }
    }
    if (mlen & 0xf) {
        memset(src, 0, 16);
        memcpy(src, c + i, mlen & 0xf);
        rubidium_aead_aegis256_dec(dst, src, state);
        if (m != NULL) {
            memcpy(m + i, dst, mlen & 0xf);
        }
        memset(dst, 0, mlen & 0xf);
        state[0] = _mm_xor_si128(state[0],
                                 _mm_loadu_si128((const __m128i *) (const void *) dst));
    }

    rubidium_aead_aegis256_mac(computed_mac, adlen, mlen, state);
    rubidium_memzero(state, sizeof state);
    rubidium_memzero(src, sizeof src);
    rubidium_memzero(dst, sizeof dst);
    ret = rubidium_verify_16(computed_mac, mac);
    rubidium_memzero(computed_mac, sizeof computed_mac);
    if (m == NULL) {
        return ret;
    }
    if (ret != 0) {
        memset(m, 0, mlen);
        return -1;
    }
    return 0;
}

int
rubidium_aead_aegis256_decrypt(unsigned char *m, std::size_t *mlen_p, unsigned char *nsec,
                             const unsigned char *c, std::size_t clen,
                             const unsigned char *ad, std::size_t adlen,
                             const unsigned char *npub, const unsigned char *k)
{
    std::size_t mlen = 0ULL;
    int                ret  = -1;

    if (clen >= 16ULL) {
        ret = rubidium_aead_aegis256_decrypt_detached(m, nsec, c, clen - 16ULL, c + clen - 16ULL, ad,
                                                    adlen, npub, k);
    }
    if (mlen_p != NULL) {
        if (ret == 0) {
            mlen = clen - 16ULL;
        }
        *mlen_p = mlen;
    }
    return ret;
}

int
rubidium_aead_aegis256_is_available(void)
{
    return rubidium_runtime_has_aesni();
}

#endif
