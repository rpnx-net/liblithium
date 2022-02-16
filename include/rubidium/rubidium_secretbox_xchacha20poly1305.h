#ifndef rubidium_secretbox_xchacha20poly1305_H
#define rubidium_secretbox_xchacha20poly1305_H

#include <cstddef>
#include "rubidium_stream_xchacha20.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_KEYBYTES 32U

size_t rubidium_secretbox_xchacha20poly1305_keybytes(void);

#define RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_NONCEBYTES 24U

size_t rubidium_secretbox_xchacha20poly1305_noncebytes(void);

#define RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES 16U

size_t rubidium_secretbox_xchacha20poly1305_macbytes(void);

#define RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MESSAGEBYTES_MAX \
    (rubidium_stream_xchacha20_MESSAGEBYTES_MAX - RUBIDIUM_SECRETBOX_XCHACHA20POLY1305_MACBYTES)

size_t rubidium_secretbox_xchacha20poly1305_messagebytes_max(void);


int rubidium_secretbox_xchacha20poly1305_easy(unsigned char *c,
                                            const unsigned char *m,
                                            std::size_t mlen,
                                            const unsigned char *n,
                                            const unsigned char *k)
            __attribute__ ((nonnull(1, 4, 5)));


int rubidium_secretbox_xchacha20poly1305_open_easy(unsigned char *m,
                                                 const unsigned char *c,
                                                 std::size_t clen,
                                                 const unsigned char *n,
                                                 const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));


int rubidium_secretbox_xchacha20poly1305_detached(unsigned char *c,
                                                unsigned char *mac,
                                                const unsigned char *m,
                                                std::size_t mlen,
                                                const unsigned char *n,
                                                const unsigned char *k)
            __attribute__ ((nonnull(1, 2, 5, 6)));


int rubidium_secretbox_xchacha20poly1305_open_detached(unsigned char *m,
                                                     const unsigned char *c,
                                                     const unsigned char *mac,
                                                     std::size_t clen,
                                                     const unsigned char *n,
                                                     const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 3, 5, 6)));

#ifdef __cplusplus
}
#endif

#endif
