
#include <limits.h>
#include <cstdint>
#include <string.h>

#include "rubidium_hash_sha512.h"
#include "rubidium_sign_ed25519.h"
#include "rubidium_verify_32.h"
#include "sign_ed25519_ref10.h"
#include "private/ed25519_ref10.h"
#include "utils.h"

int
_rubidium_sign_ed25519_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     std::size_t   mlen,
                                     const unsigned char *pk,
                                     int prehashed)
{
    rubidium_hash_sha512_state hs;
    unsigned char            h[64];
    unsigned char            rcheck[32];
    ge25519_p3               A;
    ge25519_p2               R;

#ifdef ED25519_COMPAT
    if (sig[63] & 224) {
        return -1;
    }
#else
    if ((sig[63] & 240) != 0 &&
            _rubidium_sc25519_is_canonical(sig + 32) == 0) {
        return -1;
    }
    if (_rubidium_ge25519_has_small_order(sig) != 0) {
        return -1;
    }
    if (_rubidium_ge25519_is_canonical(pk) == 0 ||
            _rubidium_ge25519_has_small_order(pk) != 0) {
        return -1;
    }
#endif
    if (_rubidium_ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }
    _rubidium_sign_ed25519_ref10_hinit(&hs, prehashed);
    rubidium_hash_sha512_update(&hs, sig, 32);
    rubidium_hash_sha512_update(&hs, pk, 32);
    rubidium_hash_sha512_update(&hs, m, mlen);
    rubidium_hash_sha512_final(&hs, h);
    _rubidium_sc25519_reduce(h);

    _rubidium_ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    _rubidium_ge25519_tobytes(rcheck, &R);

    return rubidium_verify_32(rcheck, sig) | (-(rcheck == sig)) |
           rubidium_memcmp(sig, rcheck, 32);
}

int
rubidium_sign_ed25519_verify_detached(const unsigned char *sig,
                                    const unsigned char *m,
                                    std::size_t   mlen,
                                    const unsigned char *pk)
{
    return _rubidium_sign_ed25519_verify_detached(sig, m, mlen, pk, 0);
}

int
rubidium_sign_ed25519_open(unsigned char *m, std::size_t *mlen_p,
                         const unsigned char *sm, std::size_t smlen,
                         const unsigned char *pk)
{
    std::size_t mlen;

    if (smlen < 64 || smlen - 64 > rubidium_sign_ed25519_MESSAGEBYTES_MAX) {
        goto badsig;
    }
    mlen = smlen - 64;
    if (rubidium_sign_ed25519_verify_detached(sm, sm + 64, mlen, pk) != 0) {
        if (m != NULL) {
            memset(m, 0, mlen);
        }
        goto badsig;
    }
    if (mlen_p != NULL) {
        *mlen_p = mlen;
    }
    if (m != NULL) {
        memmove(m, sm + 64, mlen);
    }
    return 0;

badsig:
    if (mlen_p != NULL) {
        *mlen_p = 0;
    }
    return -1;
}
