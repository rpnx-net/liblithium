
#include <string.h>

#include "rubidium_hash_sha512.h"
#include "rubidium_sign_ed25519.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "randombytes.h"
#include "utils.h"

void
_rubidium_sign_ed25519_ref10_hinit(rubidium_hash_sha512_state *hs, int prehashed)
{
    static const unsigned char DOM2PREFIX[32 + 2] = {
        'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
        'n', 'o', ' ',
        'E', 'd', '2', '5', '5', '1', '9', ' ',
        'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0
    };

    rubidium_hash_sha512_init(hs);
    if (prehashed) {
        rubidium_hash_sha512_update(hs, DOM2PREFIX, sizeof DOM2PREFIX);
    }
}

static inline void
_rubidium_sign_ed25519_clamp(unsigned char k[32])
{
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

#ifdef ED25519_NONDETERMINISTIC
/* r = hash(B || empty_labelset || Z || pad1 || k || pad2 || empty_labelset || K || extra || M) (mod q) */
static void
_rubidium_sign_ed25519_synthetic_r_hv(rubidium_hash_sha512_state *hs,
                                    unsigned char Z[32],
                                    const unsigned char sk[64])
{
    static const unsigned char B[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    };
    static const unsigned char zeros[128] = { 0x00 };
    static const unsigned char empty_labelset[3] = { 0x02, 0x00, 0x00 };

    rubidium_hash_sha512_update(hs, B, 32);
    rubidium_hash_sha512_update(hs, empty_labelset, 3);
    randombytes_buf(Z, 32);
    rubidium_hash_sha512_update(hs, Z, 32);
    rubidium_hash_sha512_update(hs, zeros, 128 - (32 + 3 + 32) % 128);
    rubidium_hash_sha512_update(hs, sk, 32);
    rubidium_hash_sha512_update(hs, zeros, 128 - 32 % 128);
    rubidium_hash_sha512_update(hs, empty_labelset, 3);
    rubidium_hash_sha512_update(hs, sk + 32, 32);
    /* empty extra */
}
#endif

int
_rubidium_sign_ed25519_detached(unsigned char *sig, std::size_t *siglen_p,
                              const unsigned char *m, std::size_t mlen,
                              const unsigned char *sk, int prehashed)
{
    rubidium_hash_sha512_state hs;
    unsigned char            az[64];
    unsigned char            nonce[64];
    unsigned char            hram[64];
    ge25519_p3               R;

    _rubidium_sign_ed25519_ref10_hinit(&hs, prehashed);

    rubidium_hash_sha512(az, sk, 32);
#ifdef ED25519_NONDETERMINISTIC
    _rubidium_sign_ed25519_synthetic_r_hv(&hs, nonce /* Z */, az);
#else
    rubidium_hash_sha512_update(&hs, az + 32, 32);
#endif

    rubidium_hash_sha512_update(&hs, m, mlen);
    rubidium_hash_sha512_final(&hs, nonce);

    memmove(sig + 32, sk + 32, 32);

    _rubidium_sc25519_reduce(nonce);
    _rubidium_ge25519_scalarmult_base(&R, nonce);
    _rubidium_ge25519_p3_tobytes(sig, &R);

    _rubidium_sign_ed25519_ref10_hinit(&hs, prehashed);
    rubidium_hash_sha512_update(&hs, sig, 64);
    rubidium_hash_sha512_update(&hs, m, mlen);
    rubidium_hash_sha512_final(&hs, hram);

    _rubidium_sc25519_reduce(hram);
    _rubidium_sign_ed25519_clamp(az);
    _rubidium_sc25519_muladd(sig + 32, hram, az, nonce);

    rubidium_memzero(az, sizeof az);
    rubidium_memzero(nonce, sizeof nonce);

    if (siglen_p != NULL) {
        *siglen_p = 64U;
    }
    return 0;
}

int
rubidium_sign_ed25519_detached(unsigned char *sig, std::size_t *siglen_p,
                             const unsigned char *m, std::size_t mlen,
                             const unsigned char *sk)
{
    return _rubidium_sign_ed25519_detached(sig, siglen_p, m, mlen, sk, 0);
}

int
rubidium_sign_ed25519(unsigned char *sm, std::size_t *smlen_p,
                    const unsigned char *m, std::size_t mlen,
                    const unsigned char *sk)
{
    std::size_t siglen;

    memmove(sm + rubidium_sign_ed25519_BYTES, m, mlen);
    /* LCOV_EXCL_START */
    if (rubidium_sign_ed25519_detached(
            sm, &siglen, sm + rubidium_sign_ed25519_BYTES, mlen, sk) != 0 ||
        siglen != rubidium_sign_ed25519_BYTES) {
        if (smlen_p != NULL) {
            *smlen_p = 0;
        }
        memset(sm, 0, mlen + rubidium_sign_ed25519_BYTES);
        return -1;
    }
    /* LCOV_EXCL_STOP */

    if (smlen_p != NULL) {
        *smlen_p = mlen + siglen;
    }
    return 0;
}
