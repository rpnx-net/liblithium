#include <cstdint>
#include <stdlib.h>
#include <string.h>

#include "core_h2c.h"
#include "rubidium_core_ed25519.h"
#include "rubidium_hash_sha512.h"
#include "private/common.h"
#include "private/ed25519_ref10.h"
#include "randombytes.h"
#include "utils.h"

int
rubidium_core_ed25519_is_valid_point(const unsigned char *p)
{
    ge25519_p3 p_p3;

    if (_rubidium_ge25519_is_canonical(p) == 0 ||
            _rubidium_ge25519_has_small_order(p) != 0 ||
            _rubidium_ge25519_frombytes(&p_p3, p) != 0 ||
            _rubidium_ge25519_is_on_curve(&p_p3) == 0 ||
            _rubidium_ge25519_is_on_main_subgroup(&p_p3) == 0) {
        return 0;
    }
    return 1;
}

int
rubidium_core_ed25519_add(unsigned char *r,
                        const unsigned char *p, const unsigned char *q)
{
    ge25519_p3     p_p3, q_p3, r_p3;
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;

    if (_rubidium_ge25519_frombytes(&p_p3, p) != 0 || _rubidium_ge25519_is_on_curve(&p_p3) == 0 ||
            _rubidium_ge25519_frombytes(&q_p3, q) != 0 || _rubidium_ge25519_is_on_curve(&q_p3) == 0) {
        return -1;
    }
    _rubidium_ge25519_p3_to_cached(&q_cached, &q_p3);
    _rubidium_ge25519_add_cached(&r_p1p1, &p_p3, &q_cached);
    _rubidium_ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    _rubidium_ge25519_p3_tobytes(r, &r_p3);

    return 0;
}

int
rubidium_core_ed25519_sub(unsigned char *r,
                        const unsigned char *p, const unsigned char *q)
{
    ge25519_p3     p_p3, q_p3, r_p3;
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;

    if (_rubidium_ge25519_frombytes(&p_p3, p) != 0 || _rubidium_ge25519_is_on_curve(&p_p3) == 0 ||
            _rubidium_ge25519_frombytes(&q_p3, q) != 0 || _rubidium_ge25519_is_on_curve(&q_p3) == 0) {
        return -1;
    }
    _rubidium_ge25519_p3_to_cached(&q_cached, &q_p3);
    _rubidium_ge25519_sub_cached(&r_p1p1, &p_p3, &q_cached);
    _rubidium_ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    _rubidium_ge25519_p3_tobytes(r, &r_p3);

    return 0;
}

int
rubidium_core_ed25519_from_uniform(unsigned char *p, const unsigned char *r)
{
    _rubidium_ge25519_from_uniform(p, r);

    return 0;
}

#define HASH_GE_L 48U

static int
_string_to_points(unsigned char * const px, const size_t n,
                  const char *ctx, const unsigned char *msg, size_t msg_len,
                  int hash_alg)
{
    unsigned char h[rubidium_core_ed25519_HASHBYTES];
    unsigned char h_be[2U * HASH_GE_L];
    size_t        i, j;

    if (n > 2U) {
        abort(); /* LCOV_EXCL_LINE */
    }
    if (_rubidium_core_h2c_string_to_hash(h_be, n * HASH_GE_L, ctx, msg, msg_len,
                                hash_alg) != 0) {
        return -1;
    }
    static_assert(sizeof h >= HASH_GE_L);
    for (i = 0U; i < n; i++) {
        for (j = 0U; j < HASH_GE_L; j++) {
            h[j] = h_be[i * HASH_GE_L + HASH_GE_L - 1U - j];
        }
        memset(&h[j], 0, (sizeof h) - j);
        _rubidium_ge25519_from_hash(&px[i * rubidium_core_ed25519_BYTES], h);
    }
    return 0;
}

int
rubidium_core_ed25519_from_string(unsigned char p[rubidium_core_ed25519_BYTES],
                                const char *ctx, const unsigned char *msg,
                                size_t msg_len, int hash_alg)
{
    return _string_to_points(p, 1, ctx, msg, msg_len, hash_alg);
}

int
rubidium_core_ed25519_from_string_ro(unsigned char p[rubidium_core_ed25519_BYTES],
                                   const char *ctx, const unsigned char *msg,
                                   size_t msg_len, int hash_alg)
{
    unsigned char px[2 * rubidium_core_ed25519_BYTES];

    if (_string_to_points(px, 2, ctx, msg, msg_len, hash_alg) != 0) {
        return -1;
    }
    return rubidium_core_ed25519_add(p, &px[0], &px[rubidium_core_ed25519_BYTES]);
}

void
rubidium_core_ed25519_random(unsigned char *p)
{
    unsigned char h[rubidium_core_ed25519_UNIFORMBYTES];

    rubidium::randombytes_fill(h, sizeof h);
    (void) rubidium_core_ed25519_from_uniform(p, h);
}

void
rubidium_core_ed25519_scalar_random(unsigned char *r)
{
    do {
        rubidium::randombytes_fill(r, rubidium_core_ed25519_SCALARBYTES);
        r[rubidium_core_ed25519_SCALARBYTES - 1] &= 0x1f;
    } while (_rubidium_sc25519_is_canonical(r) == 0 ||
             rubidium_is_zero(r, rubidium_core_ed25519_SCALARBYTES));
}

int
rubidium_core_ed25519_scalar_invert(unsigned char *recip, const unsigned char *s)
{
    _rubidium_sc25519_invert(recip, s);

    return - rubidium_is_zero(s, rubidium_core_ed25519_SCALARBYTES);
}

/* 2^252+27742317777372353535851937790883648493 */
static const unsigned char L[] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

void
rubidium_core_ed25519_scalar_negate(unsigned char *neg, const unsigned char *s)
{
    unsigned char t_[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];
    unsigned char s_[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];

    static_assert(rubidium_core_ed25519_NONREDUCEDSCALARBYTES >=
                    2 * rubidium_core_ed25519_SCALARBYTES);
    memset(t_, 0, sizeof t_);
    memset(s_, 0, sizeof s_);
    memcpy(t_ + rubidium_core_ed25519_SCALARBYTES, L,
           rubidium_core_ed25519_SCALARBYTES);
    memcpy(s_, s, rubidium_core_ed25519_SCALARBYTES);
    rubidium_sub(t_, s_, sizeof t_);
    _rubidium_sc25519_reduce(t_);
    memcpy(neg, t_, rubidium_core_ed25519_SCALARBYTES);
}

void
rubidium_core_ed25519_scalar_complement(unsigned char *comp,
                                      const unsigned char *s)
{
    unsigned char t_[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];
    unsigned char s_[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];

    static_assert(rubidium_core_ed25519_NONREDUCEDSCALARBYTES >=
                    2 * rubidium_core_ed25519_SCALARBYTES);
    memset(t_, 0, sizeof t_);
    memset(s_, 0, sizeof s_);
    t_[0]++;
    memcpy(t_ + rubidium_core_ed25519_SCALARBYTES, L,
           rubidium_core_ed25519_SCALARBYTES);
    memcpy(s_, s, rubidium_core_ed25519_SCALARBYTES);
    rubidium_sub(t_, s_, sizeof t_);
    _rubidium_sc25519_reduce(t_);
    memcpy(comp, t_, rubidium_core_ed25519_SCALARBYTES);
}

void
rubidium_core_ed25519_scalar_add(unsigned char *z, const unsigned char *x,
                               const unsigned char *y)
{
    unsigned char x_[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];
    unsigned char y_[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];

    memset(x_, 0, sizeof x_);
    memset(y_, 0, sizeof y_);
    memcpy(x_, x, rubidium_core_ed25519_SCALARBYTES);
    memcpy(y_, y, rubidium_core_ed25519_SCALARBYTES);
    rubidium_add(x_, y_, rubidium_core_ed25519_SCALARBYTES);
    rubidium_core_ed25519_scalar_reduce(z, x_);
}

void
rubidium_core_ed25519_scalar_sub(unsigned char *z, const unsigned char *x,
                               const unsigned char *y)
{
    unsigned char yn[rubidium_core_ed25519_SCALARBYTES];

    rubidium_core_ed25519_scalar_negate(yn, y);
    rubidium_core_ed25519_scalar_add(z, x, yn);
}

void
rubidium_core_ed25519_scalar_mul(unsigned char *z, const unsigned char *x,
                               const unsigned char *y)
{
    _rubidium_sc25519_mul(z, x, y);
}

void
rubidium_core_ed25519_scalar_reduce(unsigned char *r,
                                  const unsigned char *s)
{
    unsigned char t[rubidium_core_ed25519_NONREDUCEDSCALARBYTES];

    memcpy(t, s, sizeof t);
    _rubidium_sc25519_reduce(t);
    memcpy(r, t, rubidium_core_ed25519_SCALARBYTES);
    rubidium_memzero(t, sizeof t);
}

int
rubidium_core_ed25519_scalar_is_canonical(const unsigned char *s)
{
    return _rubidium_sc25519_is_canonical(s);
}

size_t
rubidium_core_ed25519_bytes(void)
{
    return rubidium_core_ed25519_BYTES;
}

size_t
rubidium_core_ed25519_nonreducedscalarbytes(void)
{
    return rubidium_core_ed25519_NONREDUCEDSCALARBYTES;
}

size_t
rubidium_core_ed25519_uniformbytes(void)
{
    return rubidium_core_ed25519_UNIFORMBYTES;
}

size_t
rubidium_core_ed25519_hashbytes(void)
{
    return rubidium_core_ed25519_HASHBYTES;
}

size_t
rubidium_core_ed25519_scalarbytes(void)
{
    return rubidium_core_ed25519_SCALARBYTES;
}
