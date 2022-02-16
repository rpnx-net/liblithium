
#ifndef rubidium_box_curve25519xchacha20poly1305_H
#define rubidium_box_curve25519xchacha20poly1305_H

#include <cstddef>
#include "rubidium_stream_xchacha20.h"
#include "export.h"

namespace rubidium {

#define rubidium_box_curve25519xchacha20poly1305_SEEDBYTES 32U


    size_t rubidium_box_curve25519xchacha20poly1305_seedbytes(void);

#define rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES 32U


    size_t rubidium_box_curve25519xchacha20poly1305_publickeybytes(void);

#define rubidium_box_curve25519xchacha20poly1305_SECRETKEYBYTES 32U


    size_t rubidium_box_curve25519xchacha20poly1305_secretkeybytes(void);

#define rubidium_box_curve25519xchacha20poly1305_BEFORENMBYTES 32U


    size_t rubidium_box_curve25519xchacha20poly1305_beforenmbytes(void);

#define rubidium_box_curve25519xchacha20poly1305_NONCEBYTES 24U


    size_t rubidium_box_curve25519xchacha20poly1305_noncebytes(void);

#define rubidium_box_curve25519xchacha20poly1305_MACBYTES 16U


    size_t rubidium_box_curve25519xchacha20poly1305_macbytes(void);

#define rubidium_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX \
    (rubidium_stream_xchacha20_MESSAGEBYTES_MAX - rubidium_box_curve25519xchacha20poly1305_MACBYTES)


    size_t rubidium_box_curve25519xchacha20poly1305_messagebytes_max(void);


    int rubidium_box_curve25519xchacha20poly1305_seed_keypair(unsigned char *pk,
                                                            unsigned char *sk,
                                                            const unsigned char *seed)
    __attribute__ ((nonnull));


    int rubidium_box_curve25519xchacha20poly1305_keypair(unsigned char *pk,
                                                       unsigned char *sk)
    __attribute__ ((nonnull));


    int rubidium_box_curve25519xchacha20poly1305_easy(unsigned char *c,
                                                    const unsigned char *m,
                                                    std::size_t mlen,
                                                    const unsigned char *n,
                                                    const unsigned char *pk,
                                                    const unsigned char *sk)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4, 5, 6)));


    int rubidium_box_curve25519xchacha20poly1305_open_easy(unsigned char *m,
                                                         const unsigned char *c,
                                                         std::size_t clen,
                                                         const unsigned char *n,
                                                         const unsigned char *pk,
                                                         const unsigned char *sk)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5, 6)));


    int rubidium_box_curve25519xchacha20poly1305_detached(unsigned char *c,
                                                        unsigned char *mac,
                                                        const unsigned char *m,
                                                        std::size_t mlen,
                                                        const unsigned char *n,
                                                        const unsigned char *pk,
                                                        const unsigned char *sk)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 2, 5, 6, 7)));


    int rubidium_box_curve25519xchacha20poly1305_open_detached(unsigned char *m,
                                                             const unsigned char *c,
                                                             const unsigned char *mac,
                                                             std::size_t clen,
                                                             const unsigned char *n,
                                                             const unsigned char *pk,
                                                             const unsigned char *sk)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 3, 5, 6, 7)));

/* -- Precomputation interface -- */


    int rubidium_box_curve25519xchacha20poly1305_beforenm(unsigned char *k,
                                                        const unsigned char *pk,
                                                        const unsigned char *sk)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


    int rubidium_box_curve25519xchacha20poly1305_easy_afternm(unsigned char *c,
                                                            const unsigned char *m,
                                                            std::size_t mlen,
                                                            const unsigned char *n,
                                                            const unsigned char *k)
    __attribute__ ((nonnull(1, 4, 5)));


    int rubidium_box_curve25519xchacha20poly1305_open_easy_afternm(unsigned char *m,
                                                                 const unsigned char *c,
                                                                 std::size_t clen,
                                                                 const unsigned char *n,
                                                                 const unsigned char *k)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));


    int rubidium_box_curve25519xchacha20poly1305_detached_afternm(unsigned char *c,
                                                                unsigned char *mac,
                                                                const unsigned char *m,
                                                                std::size_t mlen,
                                                                const unsigned char *n,
                                                                const unsigned char *k)
    __attribute__ ((nonnull(1, 2, 5, 6)));


    int rubidium_box_curve25519xchacha20poly1305_open_detached_afternm(unsigned char *m,
                                                                     const unsigned char *c,
                                                                     const unsigned char *mac,
                                                                     std::size_t clen,
                                                                     const unsigned char *n,
                                                                     const unsigned char *k)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 3, 5, 6)));

/* -- Ephemeral SK interface -- */

#define rubidium_box_curve25519xchacha20poly1305_SEALBYTES \
    (rubidium_box_curve25519xchacha20poly1305_PUBLICKEYBYTES + \
     rubidium_box_curve25519xchacha20poly1305_MACBYTES)


    size_t rubidium_box_curve25519xchacha20poly1305_sealbytes(void);


    int rubidium_box_curve25519xchacha20poly1305_seal(unsigned char *c,
                                                    const unsigned char *m,
                                                    std::size_t mlen,
                                                    const unsigned char *pk)
    __attribute__ ((nonnull(1, 4)));


    int rubidium_box_curve25519xchacha20poly1305_seal_open(unsigned char *m,
                                                         const unsigned char *c,
                                                         std::size_t clen,
                                                         const unsigned char *pk,
                                                         const unsigned char *sk)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));


}
#endif
