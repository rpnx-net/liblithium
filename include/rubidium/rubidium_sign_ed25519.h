#ifndef rubidium_sign_ed25519_H
#define rubidium_sign_ed25519_H

#include <stddef.h>
#include "rubidium_hash_sha512.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef struct rubidium_sign_ed25519ph_state {
    rubidium_hash_sha512_state hs;
} rubidium_sign_ed25519ph_state;

RUBIDIUM_EXPORT
size_t rubidium_sign_ed25519ph_statebytes(void);

#define rubidium_sign_ed25519_BYTES 64U
RUBIDIUM_EXPORT
size_t rubidium_sign_ed25519_bytes(void);

#define rubidium_sign_ed25519_SEEDBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_sign_ed25519_seedbytes(void);

#define rubidium_sign_ed25519_PUBLICKEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_sign_ed25519_publickeybytes(void);

#define rubidium_sign_ed25519_SECRETKEYBYTES (32U + 32U)
RUBIDIUM_EXPORT
size_t rubidium_sign_ed25519_secretkeybytes(void);

#define rubidium_sign_ed25519_MESSAGEBYTES_MAX (RUBIDIUM_SIZE_MAX - rubidium_sign_ed25519_BYTES)
RUBIDIUM_EXPORT
size_t rubidium_sign_ed25519_messagebytes_max(void);

RUBIDIUM_EXPORT
int rubidium_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *sk)
            __attribute__ ((nonnull(1, 5)));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                             const unsigned char *sm, unsigned long long smlen,
                             const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5)));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_detached(unsigned char *sig,
                                 unsigned long long *siglen_p,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *sk)
            __attribute__ ((nonnull(1, 5)));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_verify_detached(const unsigned char *sig,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_pk_to_curve25519(unsigned char *curve25519_pk,
                                         const unsigned char *ed25519_pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_sk_to_curve25519(unsigned char *curve25519_sk,
                                         const unsigned char *ed25519_sk)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519ph_init(rubidium_sign_ed25519ph_state *state)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519ph_update(rubidium_sign_ed25519ph_state *state,
                                 const unsigned char *m,
                                 unsigned long long mlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519ph_final_create(rubidium_sign_ed25519ph_state *state,
                                       unsigned char *sig,
                                       unsigned long long *siglen_p,
                                       const unsigned char *sk)
            __attribute__ ((nonnull(1, 2, 4)));

RUBIDIUM_EXPORT
int rubidium_sign_ed25519ph_final_verify(rubidium_sign_ed25519ph_state *state,
                                       const unsigned char *sig,
                                       const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
