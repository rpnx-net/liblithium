#ifndef crypto_secretbox_xchacha20poly1305_H
#define crypto_secretbox_xchacha20poly1305_H

#include <stddef.h>
#include "crypto_stream_xchacha20.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_secretbox_xchacha20poly1305_KEYBYTES 32U
LITHIUM_EXPORT
size_t crypto_secretbox_xchacha20poly1305_keybytes(void);

#define crypto_secretbox_xchacha20poly1305_NONCEBYTES 24U
LITHIUM_EXPORT
size_t crypto_secretbox_xchacha20poly1305_noncebytes(void);

#define crypto_secretbox_xchacha20poly1305_MACBYTES 16U
LITHIUM_EXPORT
size_t crypto_secretbox_xchacha20poly1305_macbytes(void);

#define crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX \
    (crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_secretbox_xchacha20poly1305_MACBYTES)
LITHIUM_EXPORT
size_t crypto_secretbox_xchacha20poly1305_messagebytes_max(void);

LITHIUM_EXPORT
int crypto_secretbox_xchacha20poly1305_easy(unsigned char *c,
                                            const unsigned char *m,
                                            unsigned long long mlen,
                                            const unsigned char *n,
                                            const unsigned char *k)
            __attribute__ ((nonnull(1, 4, 5)));

LITHIUM_EXPORT
int crypto_secretbox_xchacha20poly1305_open_easy(unsigned char *m,
                                                 const unsigned char *c,
                                                 unsigned long long clen,
                                                 const unsigned char *n,
                                                 const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

LITHIUM_EXPORT
int crypto_secretbox_xchacha20poly1305_detached(unsigned char *c,
                                                unsigned char *mac,
                                                const unsigned char *m,
                                                unsigned long long mlen,
                                                const unsigned char *n,
                                                const unsigned char *k)
            __attribute__ ((nonnull(1, 2, 5, 6)));

LITHIUM_EXPORT
int crypto_secretbox_xchacha20poly1305_open_detached(unsigned char *m,
                                                     const unsigned char *c,
                                                     const unsigned char *mac,
                                                     unsigned long long clen,
                                                     const unsigned char *n,
                                                     const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 3, 5, 6)));

#ifdef __cplusplus
}
#endif

#endif
