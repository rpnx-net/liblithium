
#include <assert.h>
#include <cstdint>
#include <string.h>

#include "core_h2c.h"
#include "rubidium_core_ed25519.h"
#include "rubidium_core_ristretto255.h"
#include "rubidium_hash_sha256.h"
#include "private/common.h"
#include "private/ed25519_ref10.h"
#include "randombytes.h"
#include "utils.h"

int
rubidium_core_ristretto255_is_valid_point(const unsigned char *p)
{
    ge25519_p3 p_p3;

    if (_rubidium_ristretto255_frombytes(&p_p3, p) != 0) {
        return 0;
    }
    return 1;
}

int
rubidium_core_ristretto255_add(unsigned char *r,
                             const unsigned char *p, const unsigned char *q)
{
    ge25519_p3     p_p3, q_p3, r_p3;
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;

    if (_rubidium_ristretto255_frombytes(&p_p3, p) != 0 ||
            _rubidium_ristretto255_frombytes(&q_p3, q) != 0) {
        return -1;
    }
    _rubidium_ge25519_p3_to_cached(&q_cached, &q_p3);
    _rubidium_ge25519_add_cached(&r_p1p1, &p_p3, &q_cached);
    _rubidium_ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    _rubidium_ristretto255_p3_tobytes(r, &r_p3);

    return 0;
}

int
rubidium_core_ristretto255_sub(unsigned char *r,
                             const unsigned char *p, const unsigned char *q)
{
    ge25519_p3     p_p3, q_p3, r_p3;
    ge25519_p1p1   r_p1p1;
    ge25519_cached q_cached;

    if (_rubidium_ristretto255_frombytes(&p_p3, p) != 0 ||
            _rubidium_ristretto255_frombytes(&q_p3, q) != 0) {
        return -1;
    }
    _rubidium_ge25519_p3_to_cached(&q_cached, &q_p3);
    _rubidium_ge25519_sub_cached(&r_p1p1, &p_p3, &q_cached);
    _rubidium_ge25519_p1p1_to_p3(&r_p3, &r_p1p1);
    _rubidium_ristretto255_p3_tobytes(r, &r_p3);

    return 0;
}

int
rubidium_core_ristretto255_from_hash(unsigned char *p, const unsigned char *r)
{
    _rubidium_ristretto255_from_hash(p, r);

    return 0;
}

static int
_string_to_element(unsigned char *p,
                   const char *ctx, const unsigned char *msg, size_t msg_len,
                   int hash_alg)
{
    unsigned char h[rubidium_core_ristretto255_HASHBYTES];

    if (_rubidium_core_h2c_string_to_hash(h, sizeof h, ctx, msg, msg_len,
                                hash_alg) != 0) {
        return -1;
    }
    _rubidium_ristretto255_from_hash(p, h);

    return 0;
}

int
rubidium_core_ristretto255_from_string(unsigned char p[rubidium_core_ristretto255_BYTES],
                                     const char *ctx, const unsigned char *msg,
                                     size_t msg_len, int hash_alg)
{
    return _string_to_element(p, ctx, msg, msg_len, hash_alg);
}

int
rubidium_core_ristretto255_from_string_ro(unsigned char p[rubidium_core_ristretto255_BYTES],
                                        const char *ctx, const unsigned char *msg,
                                        size_t msg_len, int hash_alg)
{
    return rubidium_core_ristretto255_from_string(p, ctx, msg, msg_len, hash_alg);
}

void
rubidium_core_ristretto255_random(unsigned char *p)
{
    unsigned char h[rubidium_core_ristretto255_HASHBYTES];

    rubidium::randombytes_fill(h, sizeof h);
    (void) rubidium_core_ristretto255_from_hash(p, h);
}

void
rubidium_core_ristretto255_scalar_random(unsigned char *r)
{
    rubidium_core_ed25519_scalar_random(r);
}

int
rubidium_core_ristretto255_scalar_invert(unsigned char *recip,
                                       const unsigned char *s)
{
    return rubidium_core_ed25519_scalar_invert(recip, s);
}

void
rubidium_core_ristretto255_scalar_negate(unsigned char *neg,
                                       const unsigned char *s)
{
    rubidium_core_ed25519_scalar_negate(neg, s);
}

void
rubidium_core_ristretto255_scalar_complement(unsigned char *comp,
                                           const unsigned char *s)
{
    rubidium_core_ed25519_scalar_complement(comp, s);
}

void
rubidium_core_ristretto255_scalar_add(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
{
    rubidium_core_ed25519_scalar_add(z, x, y);
}

void
rubidium_core_ristretto255_scalar_sub(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
{
    rubidium_core_ed25519_scalar_sub(z, x, y);
}

void
rubidium_core_ristretto255_scalar_mul(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
{
    _rubidium_sc25519_mul(z, x, y);
}

void
rubidium_core_ristretto255_scalar_reduce(unsigned char *r,
                                       const unsigned char *s)
{
    rubidium_core_ed25519_scalar_reduce(r, s);
}

int
rubidium_core_ristretto255_scalar_is_canonical(const unsigned char *s)
{
    return _rubidium_sc25519_is_canonical(s);
}

#define HASH_SC_L 48U

int
rubidium_core_ristretto255_scalar_from_string(unsigned char *s,
                                            const char *ctx, const unsigned char *msg,
                                            size_t msg_len, int hash_alg)
{
    unsigned char h[rubidium_core_ristretto255_NONREDUCEDSCALARBYTES];
    unsigned char h_be[HASH_SC_L];
    size_t        i;

    if (_rubidium_core_h2c_string_to_hash(h_be, sizeof h_be, ctx, msg, msg_len,
                                hash_alg) != 0) {
        return -1;
    }
    static_assert(sizeof h >= sizeof h_be);
    for (i = 0U; i < HASH_SC_L; i++) {
        h[i] = h_be[HASH_SC_L - 1U - i];
    }
    memset(&h[i], 0, (sizeof h) - i);
    rubidium_core_ristretto255_scalar_reduce(s, h);

    return 0;
}

size_t
rubidium_core_ristretto255_bytes(void)
{
    return rubidium_core_ristretto255_BYTES;
}

size_t
rubidium_core_ristretto255_nonreducedscalarbytes(void)
{
    return rubidium_core_ristretto255_NONREDUCEDSCALARBYTES;
}

size_t
rubidium_core_ristretto255_hashbytes(void)
{
    return rubidium_core_ristretto255_HASHBYTES;
}

size_t
rubidium_core_ristretto255_scalarbytes(void)
{
    return rubidium_core_ristretto255_SCALARBYTES;
}
