
#include <string.h>

#include "rubidium_hash_sha512.h"
#include "rubidium_sign_ed25519.h"
#include "ref10/sign_ed25519_ref10.h"

size_t
rubidium_sign_ed25519ph_statebytes(void)
{
    return sizeof(rubidium_sign_ed25519ph_state);
}

size_t
rubidium_sign_ed25519_bytes(void)
{
    return rubidium_sign_ed25519_BYTES;
}

size_t
rubidium_sign_ed25519_seedbytes(void)
{
    return rubidium_sign_ed25519_SEEDBYTES;
}

size_t
rubidium_sign_ed25519_publickeybytes(void)
{
    return rubidium_sign_ed25519_PUBLICKEYBYTES;
}

size_t
rubidium_sign_ed25519_secretkeybytes(void)
{
    return rubidium_sign_ed25519_SECRETKEYBYTES;
}

size_t
rubidium_sign_ed25519_messagebytes_max(void)
{
    return rubidium_sign_ed25519_MESSAGEBYTES_MAX;
}

int
rubidium_sign_ed25519_sk_to_seed(unsigned char *seed, const unsigned char *sk)
{
    memmove(seed, sk, rubidium_sign_ed25519_SEEDBYTES);

    return 0;
}

int
rubidium_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
{
    memmove(pk, sk + rubidium_sign_ed25519_SEEDBYTES,
            rubidium_sign_ed25519_PUBLICKEYBYTES);
    return 0;
}

int
rubidium_sign_ed25519ph_init(rubidium_sign_ed25519ph_state *state)
{
    rubidium_hash_sha512_init(&state->hs);
    return 0;
}

int
rubidium_sign_ed25519ph_update(rubidium_sign_ed25519ph_state *state,
                             const unsigned char *m, std::size_t mlen)
{
    return rubidium_hash_sha512_update(&state->hs, m, mlen);
}

int
rubidium_sign_ed25519ph_final_create(rubidium_sign_ed25519ph_state *state,
                                   unsigned char               *sig,
                                   std::size_t          *siglen_p,
                                   const unsigned char         *sk)
{
    unsigned char ph[rubidium_hash_sha512_BYTES];

    rubidium_hash_sha512_final(&state->hs, ph);

    return _rubidium_sign_ed25519_detached(sig, siglen_p, ph, sizeof ph, sk, 1);
}

int
rubidium_sign_ed25519ph_final_verify(rubidium_sign_ed25519ph_state *state,
                                   const unsigned char         *sig,
                                   const unsigned char         *pk)
{
    unsigned char ph[rubidium_hash_sha512_BYTES];

    rubidium_hash_sha512_final(&state->hs, ph);

    return _rubidium_sign_ed25519_verify_detached(sig, ph, sizeof ph, pk, 1);
}
