
#include <cstddef>
#include <cstdint>
#include <string.h>

#include "rubidium_auth_hmacsha512.h"
#include "rubidium_hash_sha512.h"
#include "rubidium_verify_64.h"
#include "randombytes.h"
#include "utils.h"

size_t
rubidium_auth_hmacsha512_bytes(void)
{
    return rubidium_auth_hmacsha512_BYTES;
}

size_t
rubidium_auth_hmacsha512_keybytes(void)
{
    return rubidium_auth_hmacsha512_KEYBYTES;
}

size_t
rubidium_auth_hmacsha512_statebytes(void)
{
    return sizeof(rubidium_auth_hmacsha512_state);
}

void
rubidium_auth_hmacsha512_keygen(unsigned char k[rubidium_auth_hmacsha512_KEYBYTES])
{
    randombytes_buf(k, rubidium_auth_hmacsha512_KEYBYTES);
}

int
rubidium_auth_hmacsha512_init(rubidium_auth_hmacsha512_state *state,
                            const unsigned char *key, size_t keylen)
{
    unsigned char pad[128];
    unsigned char khash[64];
    size_t        i;

    if (keylen > 128) {
        rubidium_hash_sha512_init(&state->ictx);
        rubidium_hash_sha512_update(&state->ictx, key, keylen);
        rubidium_hash_sha512_final(&state->ictx, khash);
        key    = khash;
        keylen = 64;
    }
    rubidium_hash_sha512_init(&state->ictx);
    memset(pad, 0x36, 128);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    rubidium_hash_sha512_update(&state->ictx, pad, 128);

    rubidium_hash_sha512_init(&state->octx);
    memset(pad, 0x5c, 128);
    for (i = 0; i < keylen; i++) {
        pad[i] ^= key[i];
    }
    rubidium_hash_sha512_update(&state->octx, pad, 128);

    rubidium_memzero((void *) pad, sizeof pad);
    rubidium_memzero((void *) khash, sizeof khash);

    return 0;
}

int
rubidium_auth_hmacsha512_update(rubidium_auth_hmacsha512_state *state,
                              const unsigned char *in, std::size_t inlen)
{
    rubidium_hash_sha512_update(&state->ictx, in, inlen);

    return 0;
}

int
rubidium_auth_hmacsha512_final(rubidium_auth_hmacsha512_state *state,
                             unsigned char                *out)
{
    unsigned char ihash[64];

    rubidium_hash_sha512_final(&state->ictx, ihash);
    rubidium_hash_sha512_update(&state->octx, ihash, 64);
    rubidium_hash_sha512_final(&state->octx, out);

    rubidium_memzero((void *) ihash, sizeof ihash);

    return 0;
}

int
rubidium_auth_hmacsha512(unsigned char *out, const unsigned char *in,
                       std::size_t inlen, const unsigned char *k)
{
    rubidium_auth_hmacsha512_state state;

    rubidium_auth_hmacsha512_init(&state, k, rubidium_auth_hmacsha512_KEYBYTES);
    rubidium_auth_hmacsha512_update(&state, in, inlen);
    rubidium_auth_hmacsha512_final(&state, out);

    return 0;
}

int
rubidium_auth_hmacsha512_verify(const unsigned char *h, const unsigned char *in,
                              std::size_t inlen, const unsigned char *k)
{
    unsigned char correct[64];

    rubidium_auth_hmacsha512(correct, in, inlen, k);

    return rubidium_verify_64(h, correct) | (-(h == correct)) |
           rubidium_memcmp(correct, h, 64);
}
