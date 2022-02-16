#ifndef rubidium_box_curve25519xsalsa20poly1305_H
#define rubidium_box_curve25519xsalsa20poly1305_H

#include <cstddef>
#include "rubidium_stream_xsalsa20.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_box_curve25519xsalsa20poly1305_SEEDBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_seedbytes(void);

#define rubidium_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_publickeybytes(void);

#define rubidium_box_curve25519xsalsa20poly1305_SECRETKEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_secretkeybytes(void);

#define rubidium_box_curve25519xsalsa20poly1305_BEFORENMBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_beforenmbytes(void);

#define rubidium_box_curve25519xsalsa20poly1305_NONCEBYTES 24U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_noncebytes(void);

#define rubidium_box_curve25519xsalsa20poly1305_MACBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_macbytes(void);

/* Only for the librubidium API - The NaCl compatibility API would require BOXZEROBYTES extra bytes */
#define rubidium_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX \
    (rubidium_stream_xsalsa20_MESSAGEBYTES_MAX - rubidium_box_curve25519xsalsa20poly1305_MACBYTES)
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_messagebytes_max(void);

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305_seed_keypair(unsigned char *pk,
                                                       unsigned char *sk,
                                                       const unsigned char *seed)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305_keypair(unsigned char *pk,
                                                  unsigned char *sk)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305_beforenm(unsigned char *k,
                                                   const unsigned char *pk,
                                                   const unsigned char *sk)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

/* -- NaCl compatibility interface ; Requires padding -- */

#define rubidium_box_curve25519xsalsa20poly1305_BOXZEROBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_boxzerobytes(void);

#define rubidium_box_curve25519xsalsa20poly1305_ZEROBYTES \
    (rubidium_box_curve25519xsalsa20poly1305_BOXZEROBYTES + \
     rubidium_box_curve25519xsalsa20poly1305_MACBYTES)
RUBIDIUM_EXPORT
size_t rubidium_box_curve25519xsalsa20poly1305_zerobytes(void)
            __attribute__ ((deprecated));

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305(unsigned char *c,
                                          const unsigned char *m,
                                          std::size_t mlen,
                                          const unsigned char *n,
                                          const unsigned char *pk,
                                          const unsigned char *sk)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4, 5, 6)));

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305_open(unsigned char *m,
                                               const unsigned char *c,
                                               std::size_t clen,
                                               const unsigned char *n,
                                               const unsigned char *pk,
                                               const unsigned char *sk)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5, 6)));

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305_afternm(unsigned char *c,
                                                  const unsigned char *m,
                                                  std::size_t mlen,
                                                  const unsigned char *n,
                                                  const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((nonnull(1, 4, 5)));

RUBIDIUM_EXPORT
int rubidium_box_curve25519xsalsa20poly1305_open_afternm(unsigned char *m,
                                                       const unsigned char *c,
                                                       std::size_t clen,
                                                       const unsigned char *n,
                                                       const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif
