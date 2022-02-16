
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include "rubidium_box_curve25519xchacha20poly1305.h"
#include "rubidium_core_hchacha20.h"
#include "rubidium_hash_sha512.h"
#include "rubidium_scalarmult_curve25519.h"
#include "rubidium_secretbox_xchacha20poly1305.h"
#include "private/common.h"
#include "randombytes.h"
#include "utils.h"
#include <stdexcept>
namespace rubidium {
    int
    rubidium_box_curve25519xchacha20poly1305_seed_keypair(unsigned char *pk,
                                                        unsigned char *sk,
                                                        const unsigned char *seed)
    {
        unsigned char hash[64];

        rubidium_hash_sha512(hash, seed, 32);
        memcpy(sk, hash, 32);
        rubidium_memzero(hash, sizeof hash);

        return rubidium_scalarmult_curve25519_base(pk, sk);
    }
}

int
rubidium_box_curve25519xchacha20poly1305_keypair(unsigned char *pk,
                                               unsigned char *sk)
{
    randombytes_buf(sk, 32);

    return rubidium_scalarmult_curve25519_base(pk, sk);
}

int
rubidium_box_curve25519xchacha20poly1305_beforenm(unsigned char *k,
                                                const unsigned char *pk,
                                                const unsigned char *sk)
{
    static const unsigned char zero[16] = { 0 };
    unsigned char s[32];

    if (rubidium_scalarmult_curve25519(s, sk, pk) != 0) {
        return -1;
    }
    return rubidium_core_hchacha20(k, zero, s, NULL);
}

int
rubidium_box_curve25519xchacha20poly1305_detached_afternm(
    unsigned char *c, unsigned char *mac, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n, const unsigned char *k)
{
    return rubidium_secretbox_xchacha20poly1305_detached(c, mac, m, mlen, n, k);
}

int
rubidium_box_curve25519xchacha20poly1305_detached(
    unsigned char *c, unsigned char *mac, const unsigned char *m,
    unsigned long long mlen, const unsigned char *n, const unsigned char *pk,
    const unsigned char *sk)
{
    unsigned char k[rubidium_box_curve25519xchacha20poly1305_BEFORENMBYTES];
    int           ret;

    COMPILER_ASSERT(rubidium_box_curve25519xchacha20poly1305_BEFORENMBYTES >=
                    rubidium_secretbox_xchacha20poly1305_KEYBYTES);
    if (rubidium_box_curve25519xchacha20poly1305_beforenm(k, pk, sk) != 0) {
        return -1;
    }
    ret = rubidium_box_curve25519xchacha20poly1305_detached_afternm(c, mac, m,
                                                                  mlen, n, k);
    rubidium_memzero(k, sizeof k);

    return ret;
}

int
rubidium_box_curve25519xchacha20poly1305_easy_afternm(unsigned char *c,
                                                    const unsigned char *m,
                                                    unsigned long long mlen,
                                                    const unsigned char *n,
                                                    const unsigned char *k)
{
    if (mlen > rubidium_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("mlen > rubidium_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX");
    }
    return rubidium_box_curve25519xchacha20poly1305_detached_afternm(
        c + rubidium_box_curve25519xchacha20poly1305_MACBYTES, c, m, mlen, n, k);
}

int
rubidium_box_curve25519xchacha20poly1305_easy(
    unsigned char *c, const unsigned char *m, unsigned long long mlen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
    if (mlen > rubidium_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return rubidium_box_curve25519xchacha20poly1305_detached(
        c + rubidium_box_curve25519xchacha20poly1305_MACBYTES, c, m, mlen, n, pk,
        sk);
}

int
rubidium_box_curve25519xchacha20poly1305_open_detached_afternm(
    unsigned char *m, const unsigned char *c, const unsigned char *mac,
    unsigned long long clen, const unsigned char *n, const unsigned char *k)
{
    return rubidium_secretbox_xchacha20poly1305_open_detached(m, c, mac, clen, n,
                                                            k);
}

int
rubidium_box_curve25519xchacha20poly1305_open_detached(
    unsigned char *m, const unsigned char *c, const unsigned char *mac,
    unsigned long long clen, const unsigned char *n, const unsigned char *pk,
    const unsigned char *sk)
{
    unsigned char k[rubidium_box_curve25519xchacha20poly1305_BEFORENMBYTES];
    int           ret;

    if (rubidium_box_curve25519xchacha20poly1305_beforenm(k, pk, sk) != 0) {
        return -1;
    }
    ret = rubidium_box_curve25519xchacha20poly1305_open_detached_afternm(
        m, c, mac, clen, n, k);
    rubidium_memzero(k, sizeof k);

    return ret;
}

int
rubidium_box_curve25519xchacha20poly1305_open_easy_afternm(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *k)
{
    if (clen < rubidium_box_curve25519xchacha20poly1305_MACBYTES) {
        return -1;
    }
    return rubidium_box_curve25519xchacha20poly1305_open_detached_afternm(
        m, c + rubidium_box_curve25519xchacha20poly1305_MACBYTES, c,
        clen - rubidium_box_curve25519xchacha20poly1305_MACBYTES, n, k);
}

int
rubidium_box_curve25519xchacha20poly1305_open_easy(
    unsigned char *m, const unsigned char *c, unsigned long long clen,
    const unsigned char *n, const unsigned char *pk, const unsigned char *sk)
{
    if (clen < rubidium_box_curve25519xchacha20poly1305_MACBYTES) {
        return -1;
    }
    return rubidium_box_curve25519xchacha20poly1305_open_detached(
        m, c + rubidium_box_curve25519xchacha20poly1305_MACBYTES, c,
        clen - rubidium_box_curve25519xchacha20poly1305_MACBYTES, n, pk, sk);
}

size_t
rubidium_box_curve25519xchacha20poly1305_seedbytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_SEEDBYTES;
}

size_t
rubidium_box_curve25519xchacha20poly1305_publickeybytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES;
}

size_t
rubidium_box_curve25519xchacha20poly1305_secretkeybytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_SECRETKEYBYTES;
}

size_t
rubidium_box_curve25519xchacha20poly1305_beforenmbytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_BEFORENMBYTES;
}

size_t
rubidium_box_curve25519xchacha20poly1305_noncebytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_NONCEBYTES;
}

size_t
rubidium_box_curve25519xchacha20poly1305_macbytes(void)
{
    return rubidium_box_curve25519xchacha20poly1305_MACBYTES;
}

size_t
rubidium_box_curve25519xchacha20poly1305_messagebytes_max(void)
{
    return rubidium_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX;
}
