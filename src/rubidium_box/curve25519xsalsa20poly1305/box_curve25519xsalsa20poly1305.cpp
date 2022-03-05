#include <string.h>

#include "rubidium_box_curve25519xsalsa20poly1305.h"
#include "rubidium_core_hsalsa20.h"
#include "rubidium_hash_sha512.h"
#include "rubidium_scalarmult_curve25519.h"
#include "rubidium_secretbox_xsalsa20poly1305.h"
#include "randombytes.h"
#include "utils.h"

int
rubidium_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char *pk,
                                                   unsigned char *sk,
                                                   const unsigned char *seed)
{
    unsigned char hash[64];

    rubidium_hash_sha512(hash, seed, 32);
    memcpy(sk, hash, 32);
    rubidium_memzero(hash, sizeof hash);

    return rubidium_scalarmult_curve25519_base(pk, sk);
}

int
rubidium_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                              unsigned char *sk)
{
    rubidium::randombytes_fill(reinterpret_cast<std::byte*>(sk), 32);

    return rubidium_scalarmult_curve25519_base(pk, sk);
}

int
rubidium_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
                                               const unsigned char *pk,
                                               const unsigned char *sk)
{
    static const unsigned char zero[16] = { 0 };
    unsigned char s[32];

    if (rubidium_scalarmult_curve25519(s, sk, pk) != 0) {
        return -1;
    }
    return rubidium_core_hsalsa20(k, zero, s, NULL);
}

int
rubidium_box_curve25519xsalsa20poly1305_afternm(unsigned char *c,
                                              const unsigned char *m,
                                              std::size_t mlen,
                                              const unsigned char *n,
                                              const unsigned char *k)
{
    return rubidium_secretbox_xsalsa20poly1305(c, m, mlen, n, k);
}

int
rubidium_box_curve25519xsalsa20poly1305_open_afternm(unsigned char *m,
                                                   const unsigned char *c,
                                                   std::size_t clen,
                                                   const unsigned char *n,
                                                   const unsigned char *k)
{
    return rubidium_secretbox_xsalsa20poly1305_open(m, c, clen, n, k);
}

int
rubidium_box_curve25519xsalsa20poly1305(unsigned char *c, const unsigned char *m,
                                      std::size_t   mlen,
                                      const unsigned char *n,
                                      const unsigned char *pk,
                                      const unsigned char *sk)
{
    unsigned char k[rubidium_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    int           ret;

    if (rubidium_box_curve25519xsalsa20poly1305_beforenm(k, pk, sk) != 0) {
        return -1;
    }
    ret = rubidium_box_curve25519xsalsa20poly1305_afternm(c, m, mlen, n, k);
    rubidium_memzero(k, sizeof k);

    return ret;
}

int
rubidium_box_curve25519xsalsa20poly1305_open(
    unsigned char *m, const unsigned char *c, std::size_t clen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
    unsigned char k[rubidium_box_curve25519xsalsa20poly1305_BEFORENMBYTES];
    int           ret;

    if (rubidium_box_curve25519xsalsa20poly1305_beforenm(k, pk, sk) != 0) {
        return -1;
    }
    ret = rubidium_box_curve25519xsalsa20poly1305_open_afternm(m, c, clen, n, k);
    rubidium_memzero(k, sizeof k);

    return ret;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_seedbytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_SEEDBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_publickeybytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_secretkeybytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_beforenmbytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_noncebytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_NONCEBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_zerobytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_ZEROBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_boxzerobytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_macbytes(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_MACBYTES;
}

size_t
rubidium_box_curve25519xsalsa20poly1305_messagebytes_max(void)
{
    return rubidium_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX;
}
