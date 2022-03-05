
#include <string.h>

#include "rubidium_hash_sha512.h"
#include "rubidium_scalarmult_curve25519.h"
#include "rubidium_sign_ed25519.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "randombytes.h"
#include "utils.h"

int
rubidium_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                 const unsigned char *seed)
{
    ge25519_p3 A;

    rubidium_hash_sha512(sk, seed, 32);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    _rubidium_ge25519_scalarmult_base(&A, sk);
    _rubidium_ge25519_p3_tobytes(pk, &A);

    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);

    return 0;
}

int
rubidium_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[32];
    int           ret;

    rubidium::randombytes_fill(seed, sizeof seed);
    ret = rubidium_sign_ed25519_seed_keypair(pk, sk, seed);
    rubidium_memzero(seed, sizeof seed);

    return ret;
}

int
rubidium_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                     const unsigned char *ed25519_pk)
{
    ge25519_p3 A;
    fe25519    x;
    fe25519    one_minus_y;

    if (_rubidium_ge25519_has_small_order(ed25519_pk) != 0 ||
            _rubidium_ge25519_frombytes_negate_vartime(&A, ed25519_pk) != 0 ||
            _rubidium_ge25519_is_on_main_subgroup(&A) == 0) {
        return -1;
    }
    fe25519_1(one_minus_y);
    fe25519_sub(one_minus_y, one_minus_y, A.Y);
    fe25519_1(x);
    fe25519_add(x, x, A.Y);
    _rubidium_fe25519_invert(one_minus_y, one_minus_y);
    fe25519_mul(x, x, one_minus_y);
    _rubidium_fe25519_tobytes(curve25519_pk, x);

    return 0;
}

int
rubidium_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                     const unsigned char *ed25519_sk)
{
    unsigned char h[rubidium_hash_sha512_BYTES];

    rubidium_hash_sha512(h, ed25519_sk, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memcpy(curve25519_sk, h, rubidium_scalarmult_curve25519_BYTES);
    rubidium_memzero(h, sizeof h);

    return 0;
}
