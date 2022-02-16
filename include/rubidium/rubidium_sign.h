#ifndef rubidium_sign_H
#define rubidium_sign_H

/*
 * THREAD SAFETY: rubidium_sign_keypair() is thread-safe,
 * provided that rubidium_init() was called before.
 *
 * Other functions, including rubidium_sign_seed_keypair() are always thread-safe.
 */

#include <cstddef>

#include "rubidium_sign_ed25519.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef rubidium_sign_ed25519ph_state rubidium_sign_state;


size_t  rubidium_sign_statebytes(void);

#define rubidium_sign_BYTES rubidium_sign_ed25519_BYTES

size_t  rubidium_sign_bytes(void);

#define rubidium_sign_SEEDBYTES rubidium_sign_ed25519_SEEDBYTES

size_t  rubidium_sign_seedbytes(void);

#define rubidium_sign_PUBLICKEYBYTES rubidium_sign_ed25519_PUBLICKEYBYTES

size_t  rubidium_sign_publickeybytes(void);

#define rubidium_sign_SECRETKEYBYTES rubidium_sign_ed25519_SECRETKEYBYTES

size_t  rubidium_sign_secretkeybytes(void);

#define rubidium_sign_MESSAGEBYTES_MAX rubidium_sign_ed25519_MESSAGEBYTES_MAX

size_t  rubidium_sign_messagebytes_max(void);

#define rubidium_sign_PRIMITIVE "ed25519"

const char *rubidium_sign_primitive(void);


int rubidium_sign_seed_keypair(unsigned char *pk, unsigned char *sk,
                             const unsigned char *seed)
            __attribute__ ((nonnull));


int rubidium_sign_keypair(unsigned char *pk, unsigned char *sk)
            __attribute__ ((nonnull));


int rubidium_sign(unsigned char *sm, std::size_t *smlen_p,
                const unsigned char *m, std::size_t mlen,
                const unsigned char *sk) __attribute__ ((nonnull(1, 5)));


int rubidium_sign_open(unsigned char *m, std::size_t *mlen_p,
                     const unsigned char *sm, std::size_t smlen,
                     const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5)));


int rubidium_sign_detached(unsigned char *sig, std::size_t *siglen_p,
                         const unsigned char *m, std::size_t mlen,
                         const unsigned char *sk) __attribute__ ((nonnull(1, 5)));


int rubidium_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                std::size_t mlen,
                                const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));


int rubidium_sign_init(rubidium_sign_state *state);


int rubidium_sign_update(rubidium_sign_state *state,
                       const unsigned char *m, std::size_t mlen)
            __attribute__ ((nonnull(1)));


int rubidium_sign_final_create(rubidium_sign_state *state, unsigned char *sig,
                             std::size_t *siglen_p,
                             const unsigned char *sk)
            __attribute__ ((nonnull(1, 2, 4)));


int rubidium_sign_final_verify(rubidium_sign_state *state, const unsigned char *sig,
                             const unsigned char *pk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
