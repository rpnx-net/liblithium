
#include <string.h>

#include "rubidium_box_curve25519xchacha20poly1305.h"
#include "rubidium_generichash.h"
#include "private/common.h"
#include "utils.h"

static int
rubidium_box_curve25519xchacha20poly1305_seal_nonce(unsigned char *nonce,
                                                  const unsigned char *pk1,
                                                  const unsigned char *pk2)
{
    rubidium_generichash_state st;

    rubidium_generichash_blake2b_init(&st, NULL, 0U,
                            rubidium_box_curve25519xchacha20poly1305_NONCEBYTES);
    rubidium_generichash_blake2b_update(&st, pk1,
                              rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    rubidium_generichash_blake2b_update(&st, pk2,
                              rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    rubidium_generichash_blake2b_final(&st, nonce,
                             rubidium_box_curve25519xchacha20poly1305_NONCEBYTES);

    return 0;
}

int
rubidium_box_curve25519xchacha20poly1305_seal(unsigned char *c, const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *pk)
{
    unsigned char nonce[rubidium_box_curve25519xchacha20poly1305_NONCEBYTES];
    unsigned char epk[rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES];
    unsigned char esk[rubidium_box_curve25519xchacha20poly1305_SECRETKEYBYTES];
    int           ret;

    if (rubidium::rubidium_box_curve25519xchacha20poly1305_keypair(epk, esk) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    rubidium_box_curve25519xchacha20poly1305_seal_nonce(nonce, epk, pk);
    ret = rubidium::rubidium_box_curve25519xchacha20poly1305_easy(
         c + rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES, m, mlen,
         nonce, pk, esk);
    memcpy(c, epk, rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES);
    rubidium_memzero(esk, sizeof esk);
    rubidium_memzero(epk, sizeof epk);
    rubidium_memzero(nonce, sizeof nonce);

    return ret;
}

int
rubidium_box_curve25519xchacha20poly1305_seal_open(unsigned char *m, const unsigned char *c,
                                                 unsigned long long clen,
                                                 const unsigned char *pk,
                                                 const unsigned char *sk)
{
    unsigned char nonce[rubidium_box_curve25519xchacha20poly1305_NONCEBYTES];

    if (clen < rubidium_box_curve25519xchacha20poly1305_SEALBYTES) {
        return -1;
    }
    rubidium_box_curve25519xchacha20poly1305_seal_nonce(nonce, c, pk);

    COMPILER_ASSERT(rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES <
                    rubidium_box_curve25519xchacha20poly1305_SEALBYTES);

    return rubidium::rubidium_box_curve25519xchacha20poly1305_open_easy(
         m, c + rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
         clen - rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
         nonce, c, sk);
}

size_t
rubidium_box_curve25519xchacha20poly1305_sealbytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_SEALBYTES;
}
