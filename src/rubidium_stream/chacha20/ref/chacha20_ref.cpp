
/*
 chacha-merged.c version 20080118
 D. J. Bernstein
 Public domain.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rubidium_stream_chacha20.h"
#include "private/common.h"
#include "utils.h"

#include "../stream_chacha20.h"
#include "chacha20_ref.h"

struct chacha_ctx {
    uint32_t input[16];
};

typedef struct chacha_ctx chacha_ctx;

#define U32C(v) (v##U)

#define U32V(v) ((uint32_t)(v) &U32C(0xFFFFFFFF))

#define ROTATE(v, c) (std::rotl<std::uint32_t>(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d) \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 16);   \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 12);   \
    a = PLUS(a, b);              \
    d = ROTATE(XOR(d, a), 8);    \
    c = PLUS(c, d);              \
    b = ROTATE(XOR(b, c), 7);

static void
chacha_keysetup(chacha_ctx *ctx, const uint8_t *k)
{
    ctx->input[0]  = U32C(0x61707865);
    ctx->input[1]  = U32C(0x3320646e);
    ctx->input[2]  = U32C(0x79622d32);
    ctx->input[3]  = U32C(0x6b206574);
    ctx->input[4]  = load32_le(k + 0);
    ctx->input[5]  = load32_le(k + 4);
    ctx->input[6]  = load32_le(k + 8);
    ctx->input[7]  = load32_le(k + 12);
    ctx->input[8]  = load32_le(k + 16);
    ctx->input[9]  = load32_le(k + 20);
    ctx->input[10] = load32_le(k + 24);
    ctx->input[11] = load32_le(k + 28);
}

static void
chacha_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : load32_le(counter + 0);
    ctx->input[13] = counter == NULL ? 0 : load32_le(counter + 4);
    ctx->input[14] = load32_le(iv + 0);
    ctx->input[15] = load32_le(iv + 4);
}

static void
chacha_ietf_ivsetup(chacha_ctx *ctx, const uint8_t *iv, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : load32_le(counter);
    ctx->input[13] = load32_le(iv + 0);
    ctx->input[14] = load32_le(iv + 4);
    ctx->input[15] = load32_le(iv + 8);
}

static void
chacha20_encrypt_bytes(chacha_ctx *ctx, const uint8_t *m, uint8_t *c,
                       unsigned long long bytes)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14,
        x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14,
        j15;
    uint8_t     *ctarget = NULL;
    uint8_t      tmp[64];
    unsigned int i;

    if (!bytes) {
        return; /* LCOV_EXCL_LINE */
    }
    j0  = ctx->input[0];
    j1  = ctx->input[1];
    j2  = ctx->input[2];
    j3  = ctx->input[3];
    j4  = ctx->input[4];
    j5  = ctx->input[5];
    j6  = ctx->input[6];
    j7  = ctx->input[7];
    j8  = ctx->input[8];
    j9  = ctx->input[9];
    j10 = ctx->input[10];
    j11 = ctx->input[11];
    j12 = ctx->input[12];
    j13 = ctx->input[13];
    j14 = ctx->input[14];
    j15 = ctx->input[15];

    for (;;) {
        if (bytes < 64) {
            memset(tmp, 0, 64);
            for (i = 0; i < bytes; ++i) {
                tmp[i] = m[i];
            }
            m       = tmp;
            ctarget = c;
            c       = tmp;
        }
        x0  = j0;
        x1  = j1;
        x2  = j2;
        x3  = j3;
        x4  = j4;
        x5  = j5;
        x6  = j6;
        x7  = j7;
        x8  = j8;
        x9  = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        for (i = 20; i > 0; i -= 2) {
            QUARTERROUND(x0, x4, x8, x12)
            QUARTERROUND(x1, x5, x9, x13)
            QUARTERROUND(x2, x6, x10, x14)
            QUARTERROUND(x3, x7, x11, x15)
            QUARTERROUND(x0, x5, x10, x15)
            QUARTERROUND(x1, x6, x11, x12)
            QUARTERROUND(x2, x7, x8, x13)
            QUARTERROUND(x3, x4, x9, x14)
        }
        x0  = PLUS(x0, j0);
        x1  = PLUS(x1, j1);
        x2  = PLUS(x2, j2);
        x3  = PLUS(x3, j3);
        x4  = PLUS(x4, j4);
        x5  = PLUS(x5, j5);
        x6  = PLUS(x6, j6);
        x7  = PLUS(x7, j7);
        x8  = PLUS(x8, j8);
        x9  = PLUS(x9, j9);
        x10 = PLUS(x10, j10);
        x11 = PLUS(x11, j11);
        x12 = PLUS(x12, j12);
        x13 = PLUS(x13, j13);
        x14 = PLUS(x14, j14);
        x15 = PLUS(x15, j15);

        x0  = ((x0) ^ (load32_le(m + 0)));
        x1  = ((x1) ^ (load32_le(m + 4)));
        x2  = ((x2) ^ (load32_le(m + 8)));
        x3  = ((x3) ^ (load32_le(m + 12)));
        x4  = ((x4) ^ (load32_le(m + 16)));
        x5  = ((x5) ^ (load32_le(m + 20)));
        x6  = ((x6) ^ (load32_le(m + 24)));
        x7  = ((x7) ^ (load32_le(m + 28)));
        x8  = ((x8) ^ (load32_le(m + 32)));
        x9  = ((x9) ^ (load32_le(m + 36)));
        x10 = ((x10) ^ (load32_le(m + 40)));
        x11 = ((x11) ^ (load32_le(m + 44)));
        x12 = ((x12) ^ (load32_le(m + 48)));
        x13 = ((x13) ^ (load32_le(m + 52)));
        x14 = ((x14) ^ (load32_le(m + 56)));
        x15 = ((x15) ^ (load32_le(m + 60)));

        j12 = PLUSONE(j12);
        /* LCOV_EXCL_START */
        if (!j12) {
            j13 = PLUSONE(j13);
        }
        /* LCOV_EXCL_STOP */

        store32_le((c + 0), (x0));
        store32_le((c + 4), (x1));
        store32_le((c + 8), (x2));
        store32_le((c + 12), (x3));
        store32_le((c + 16), (x4));
        store32_le((c + 20), (x5));
        store32_le((c + 24), (x6));
        store32_le((c + 28), (x7));
        store32_le((c + 32), (x8));
        store32_le((c + 36), (x9));
        store32_le((c + 40), (x10));
        store32_le((c + 44), (x11));
        store32_le((c + 48), (x12));
        store32_le((c + 52), (x13));
        store32_le((c + 56), (x14));
        store32_le((c + 60), (x15));

        if (bytes <= 64) {
            if (bytes < 64) {
                for (i = 0; i < (unsigned int) bytes; ++i) {
                    ctarget[i] = c[i]; /* ctarget cannot be NULL */
                }
            }
            ctx->input[12] = j12;
            ctx->input[13] = j13;

            return;
        }
        bytes -= 64;
        c += 64;
        m += 64;
    }
}

static int
stream_ref(unsigned char *c, unsigned long long clen, const unsigned char *n,
           const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    static_assert(RUBIDIUM_STREAM_CHACHA20_KEYBYTES == 256 / 8);
    chacha_keysetup(&ctx, k);
    chacha_ivsetup(&ctx, n, NULL);
    memset(c, 0, clen);
    chacha20_encrypt_bytes(&ctx, c, c, clen);
    rubidium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
stream_ietf_ext_ref(unsigned char *c, unsigned long long clen,
                    const unsigned char *n, const unsigned char *k)
{
    struct chacha_ctx ctx;

    if (!clen) {
        return 0;
    }
    static_assert(RUBIDIUM_STREAM_CHACHA20_KEYBYTES == 256 / 8);
    chacha_keysetup(&ctx, k);
    chacha_ietf_ivsetup(&ctx, n, NULL);
    memset(c, 0, clen);
    chacha20_encrypt_bytes(&ctx, c, c, clen);
    rubidium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
stream_ref_xor_ic(unsigned char *c, const unsigned char *m,
                  unsigned long long mlen, const unsigned char *n, uint64_t ic,
                  const unsigned char *k)
{
    struct chacha_ctx ctx;
    uint8_t           ic_bytes[8];
    uint32_t          ic_high;
    uint32_t          ic_low;

    if (!mlen) {
        return 0;
    }
    ic_high = U32V(ic >> 32);
    ic_low  = U32V(ic);
    store32_le((&ic_bytes[0]), (ic_low));
    store32_le((&ic_bytes[4]), (ic_high));
    chacha_keysetup(&ctx, k);
    chacha_ivsetup(&ctx, n, ic_bytes);
    chacha20_encrypt_bytes(&ctx, m, c, mlen);
    rubidium_memzero(&ctx, sizeof ctx);

    return 0;
}

static int
stream_ietf_ext_ref_xor_ic(unsigned char *c, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *n,
                           uint32_t ic, const unsigned char *k)
{
    struct chacha_ctx ctx;
    uint8_t           ic_bytes[4];

    if (!mlen) {
        return 0;
    }
    store32_le((ic_bytes), (ic));
    chacha_keysetup(&ctx, k);
    chacha_ietf_ivsetup(&ctx, n, ic_bytes);
    chacha20_encrypt_bytes(&ctx, m, c, mlen);
    rubidium_memzero(&ctx, sizeof ctx);

    return 0;
}

struct rubidium_stream_chacha20_implementation
    rubidium_stream_chacha20_ref_implementation = {
        RUBIDIUM_C99(.stream =) stream_ref,
        RUBIDIUM_C99(.stream_ietf_ext =) stream_ietf_ext_ref,
        RUBIDIUM_C99(.stream_xor_ic =) stream_ref_xor_ic,
        RUBIDIUM_C99(.stream_ietf_ext_xor_ic =) stream_ietf_ext_ref_xor_ic
    };
