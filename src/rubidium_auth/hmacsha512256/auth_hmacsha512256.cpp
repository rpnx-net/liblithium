
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rubidium_auth_hmacsha512.h"
#include "rubidium_auth_hmacsha512256.h"
#include "rubidium_hash_sha512.h"
#include "rubidium_verify_32.h"
#include "randombytes.h"
#include "utils.h"

size_t
rubidium_auth_hmacsha512256_bytes(void)
{
    return rubidium_auth_hmacsha512256_BYTES;
}

size_t
rubidium_auth_hmacsha512256_keybytes(void)
{
    return rubidium_auth_hmacsha512256_KEYBYTES;
}

size_t
rubidium_auth_hmacsha512256_statebytes(void)
{
    return sizeof(rubidium_auth_hmacsha512256_state);
}

void
rubidium_auth_hmacsha512256_keygen(
    unsigned char k[rubidium_auth_hmacsha512256_KEYBYTES])
{
    randombytes_buf(k, rubidium_auth_hmacsha512256_KEYBYTES);
}

int
rubidium_auth_hmacsha512256_init(rubidium_auth_hmacsha512256_state *state,
                               const unsigned char *key, size_t keylen)
{
    return rubidium_auth_hmacsha512_init((rubidium_auth_hmacsha512_state *) state,
                                       key, keylen);
}

int
rubidium_auth_hmacsha512256_update(rubidium_auth_hmacsha512256_state *state,
                                 const unsigned char             *in,
                                 unsigned long long               inlen)
{
    return rubidium_auth_hmacsha512_update((rubidium_auth_hmacsha512_state *) state,
                                         in, inlen);
}

int
rubidium_auth_hmacsha512256_final(rubidium_auth_hmacsha512256_state *state,
                                unsigned char                   *out)
{
    unsigned char out0[64];

    rubidium_auth_hmacsha512_final((rubidium_auth_hmacsha512_state *) state, out0);
    memcpy(out, out0, 32);

    return 0;
}

int
rubidium_auth_hmacsha512256(unsigned char *out, const unsigned char *in,
                          unsigned long long inlen, const unsigned char *k)
{
    rubidium_auth_hmacsha512256_state state;

    rubidium_auth_hmacsha512256_init(&state, k,
                                   rubidium_auth_hmacsha512256_KEYBYTES);
    rubidium_auth_hmacsha512256_update(&state, in, inlen);
    rubidium_auth_hmacsha512256_final(&state, out);

    return 0;
}

int
rubidium_auth_hmacsha512256_verify(const unsigned char *h,
                                 const unsigned char *in,
                                 unsigned long long   inlen,
                                 const unsigned char *k)
{
    unsigned char correct[32];

    rubidium_auth_hmacsha512256(correct, in, inlen, k);

    return rubidium_verify_32(h, correct) | (-(h == correct)) |
           rubidium_memcmp(correct, h, 32);
}
