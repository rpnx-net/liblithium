#ifndef crypto_secretbox_xsalsa20poly1305_H
#define crypto_secretbox_xsalsa20poly1305_H

#include <stddef.h>
#include "crypto_stream_xsalsa20.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_secretbox_xsalsa20poly1305_KEYBYTES 32U
LITHIUM_EXPORT
size_t crypto_secretbox_xsalsa20poly1305_keybytes(void);

#define crypto_secretbox_xsalsa20poly1305_NONCEBYTES 24U
LITHIUM_EXPORT
size_t crypto_secretbox_xsalsa20poly1305_noncebytes(void);

#define crypto_secretbox_xsalsa20poly1305_MACBYTES 16U
LITHIUM_EXPORT
size_t crypto_secretbox_xsalsa20poly1305_macbytes(void);

/* Only for the liblithium API - The NaCl compatibility API would require BOXZEROBYTES extra bytes */
#define crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX \
    (crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_secretbox_xsalsa20poly1305_MACBYTES)
LITHIUM_EXPORT
size_t crypto_secretbox_xsalsa20poly1305_messagebytes_max(void);

LITHIUM_EXPORT
void crypto_secretbox_xsalsa20poly1305_keygen(unsigned char k[crypto_secretbox_xsalsa20poly1305_KEYBYTES])
            __attribute__ ((nonnull));

/* -- NaCl compatibility interface ; Requires padding -- */

#define crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES 16U
LITHIUM_EXPORT
size_t crypto_secretbox_xsalsa20poly1305_boxzerobytes(void)
            __attribute__ ((deprecated));

#define crypto_secretbox_xsalsa20poly1305_ZEROBYTES \
    (crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES + \
     crypto_secretbox_xsalsa20poly1305_MACBYTES)
LITHIUM_EXPORT
size_t crypto_secretbox_xsalsa20poly1305_zerobytes(void)
            __attribute__ ((deprecated));

LITHIUM_EXPORT
int crypto_secretbox_xsalsa20poly1305(unsigned char *c,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *n,
                                      const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((nonnull(1, 4, 5)));

LITHIUM_EXPORT
int crypto_secretbox_xsalsa20poly1305_open(unsigned char *m,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *n,
                                           const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif
