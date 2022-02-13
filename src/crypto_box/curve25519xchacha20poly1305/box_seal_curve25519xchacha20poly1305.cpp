
#include <string.h>

#include "crypto_box_curve25519xchacha20poly1305.h"
#include "crypto_generichash.h"
#include "private/common.h"
#include "utils.h"

static int
crypto_box_curve25519xchacha20poly1305_seal_nonce(unsigned char *nonce,
                                                  const unsigned char *pk1,
                                                  const unsigned char *pk2)
{
    crypto_generichash_state st;

    crypto_generichash_blake2b_init(&st, NULL, 0U,
                            crypto_box_curve25519xchacha20poly1305_NONCEBYTES);
    crypto_generichash_blake2b_update(&st, pk1,
                              crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    crypto_generichash_blake2b_update(&st, pk2,
                              crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    crypto_generichash_blake2b_final(&st, nonce,
                             crypto_box_curve25519xchacha20poly1305_NONCEBYTES);

    return 0;
}

int
crypto_box_curve25519xchacha20poly1305_seal(unsigned char *c, const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *pk)
{
    unsigned char nonce[crypto_box_curve25519xchacha20poly1305_NONCEBYTES];
    unsigned char epk[crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
    unsigned char esk[crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
    int           ret;

    if (lithium::crypto_box_curve25519xchacha20poly1305_keypair(epk, esk) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    crypto_box_curve25519xchacha20poly1305_seal_nonce(nonce, epk, pk);
    ret = lithium::crypto_box_curve25519xchacha20poly1305_easy(
         c + crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES, m, mlen,
         nonce, pk, esk);
    memcpy(c, epk, crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    lithium_memzero(esk, sizeof esk);
    lithium_memzero(epk, sizeof epk);
    lithium_memzero(nonce, sizeof nonce);

    return ret;
}

int
crypto_box_curve25519xchacha20poly1305_seal_open(unsigned char *m, const unsigned char *c,
                                                 unsigned long long clen,
                                                 const unsigned char *pk,
                                                 const unsigned char *sk)
{
    unsigned char nonce[crypto_box_curve25519xchacha20poly1305_NONCEBYTES];

    if (clen < crypto_box_curve25519xchacha20poly1305_SEALBYTES) {
        return -1;
    }
    crypto_box_curve25519xchacha20poly1305_seal_nonce(nonce, c, pk);

    COMPILER_ASSERT(crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES <
                    crypto_box_curve25519xchacha20poly1305_SEALBYTES);

    return lithium::crypto_box_curve25519xchacha20poly1305_open_easy(
         m, c + crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
         clen - crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
         nonce, c, sk);
}

size_t
crypto_box_curve25519xchacha20poly1305_sealbytes(void)
{
    return crypto_box_curve25519xchacha20poly1305_SEALBYTES;
}
