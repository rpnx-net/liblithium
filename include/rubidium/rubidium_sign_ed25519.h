#ifndef rubidium_sign_ed25519_H
#define rubidium_sign_ed25519_H

#include <cstddef>
#include "rubidium_hash_sha512.h"
#include "export.h"



typedef struct rubidium_sign_ed25519ph_state {
    rubidium_hash_sha512_state hs;
} rubidium_sign_ed25519ph_state;


size_t rubidium_sign_ed25519ph_statebytes(void);

#define rubidium_sign_ed25519_BYTES 64U

size_t rubidium_sign_ed25519_bytes(void);

#define rubidium_sign_ed25519_SEEDBYTES 32U

size_t rubidium_sign_ed25519_seedbytes(void);

#define rubidium_sign_ed25519_PUBLICKEYBYTES 32U

size_t rubidium_sign_ed25519_publickeybytes(void);

#define rubidium_sign_ed25519_SECRETKEYBYTES (32U + 32U)

size_t rubidium_sign_ed25519_secretkeybytes(void);

#define rubidium_sign_ed25519_MESSAGEBYTES_MAX (RUBIDIUM_SIZE_MAX - rubidium_sign_ed25519_BYTES)

size_t rubidium_sign_ed25519_messagebytes_max(void);


int rubidium_sign_ed25519(unsigned char *sm, std::size_t *smlen_p,
                        const unsigned char *m, std::size_t mlen,
                        const unsigned char *sk)
            __attribute__ ((nonnull(1, 5)));


int rubidium_sign_ed25519_open(unsigned char *m, std::size_t *mlen_p,
                             const unsigned char *sm, std::size_t smlen,
                             const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5)));


int rubidium_sign_ed25519_detached(unsigned char *sig,
                                 std::size_t *siglen_p,
                                 const unsigned char *m,
                                 std::size_t mlen,
                                 const unsigned char *sk)
            __attribute__ ((nonnull(1, 5)));


int rubidium_sign_ed25519_verify_detached(const unsigned char *sig,
                                        const unsigned char *m,
                                        std::size_t mlen,
                                        const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));


int rubidium_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
            __attribute__ ((nonnull));


int rubidium_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed)
            __attribute__ ((nonnull));


int rubidium_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk)
            __attribute__ ((nonnull));


int rubidium_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk)
            __attribute__ ((nonnull));


int rubidium_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
            __attribute__ ((nonnull));


int rubidium_sign_ed25519ph_init(rubidium_sign_ed25519ph_state *state)
            __attribute__ ((nonnull));


int rubidium_sign_ed25519ph_update(rubidium_sign_ed25519ph_state *state,
                                 const unsigned char *m,
                                 std::size_t mlen)
            __attribute__ ((nonnull(1)));


int rubidium_sign_ed25519ph_final_create(rubidium_sign_ed25519ph_state *state,
                                       unsigned char *sig,
                                       std::size_t *siglen_p,
                                       const unsigned char *sk)
            __attribute__ ((nonnull(1, 2, 4)));


int rubidium_sign_ed25519ph_final_verify(rubidium_sign_ed25519ph_state *state,
                                       const unsigned char *sig,
                                       const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));



#endif
