
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rubidium_auth_hmacsha256.h"
#include "rubidium_hash_sha256.h"
#include "rubidium_verify_32.h"
#include "randombytes.h"
#include "utils.h"

size_t
rubidium_auth_hmacsha256_bytes(void)
{
    return rubidium_auth_hmacsha256_BYTES;
}

size_t
rubidium_auth_hmacsha256_keybytes(void)
{
    return rubidium_auth_hmacsha256_KEYBYTES;
}

size_t
rubidium_auth_hmacsha256_statebytes(void)
{
    return sizeof(rubidium_auth_hmacsha256_state);
}

void
rubidium_auth_hmacsha256_keygen(unsigned char k[rubidium_auth_hmacsha256_KEYBYTES])
{
    randombytes_buf(k, rubidium_auth_hmacsha256_KEYBYTES);
}

int
rubidium_auth_hmacsha256_init(rubidium_auth_hmacsha256_state *state,
                            const unsigned char *key, size_t keylen)
{
    unsigned char pad[64];
    unsigned char khash[32];
    size_t        i;

    if (keylen > 64) {
        rubidium_hash_sha256_init(&state->ictx);
        rubidium_hash_sha256_update(&state->ictx, key, keylen);
        rubidium_hash_sha256_final(&state->ictx, khash);
        key    = khash;
        keylen = 32;
    }
    rubidium_hash_sha256_init(&state->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    rubidium_hash_sha256_update(&state->ictx, pad, 64);

    rubidium_hash_sha256_init(&state->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    rubidium_hash_sha256_update(&state->octx, pad, 64);

    rubidium_memzero((void *) pad, sizeof pad);
    rubidium_memzero((void *) khash, sizeof khash);

    return 0;
}

int
rubidium_auth_hmacsha256_update(rubidium_auth_hmacsha256_state *state,
                              const unsigned char *in, unsigned long long inlen)
{
    rubidium_hash_sha256_update(&state->ictx, in, inlen);

    return 0;
}

int
rubidium_auth_hmacsha256_final(rubidium_auth_hmacsha256_state *state,
                             unsigned char                *out)
{
    unsigned char ihash[32];

    rubidium_hash_sha256_final(&state->ictx, ihash);
    rubidium_hash_sha256_update(&state->octx, ihash, 32);
    rubidium_hash_sha256_final(&state->octx, out);

    rubidium_memzero((void *) ihash, sizeof ihash);

    return 0;
}

int
rubidium_auth_hmacsha256(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k)
{
    rubidium_auth_hmacsha256_state state;

    rubidium_auth_hmacsha256_init(&state, k, rubidium_auth_hmacsha256_KEYBYTES);
    rubidium_auth_hmacsha256_update(&state, in, inlen);
    rubidium_auth_hmacsha256_final(&state, out);

    return 0;
}

int
rubidium_auth_hmacsha256_verify(const unsigned char *h, const unsigned char *in,
                              unsigned long long inlen, const unsigned char *k)
{
    unsigned char correct[32];

    rubidium_auth_hmacsha256(correct, in, inlen, k);

    return rubidium_verify_32(h, correct) | (-(h == correct)) |
           rubidium_memcmp(correct, h, 32);
}
