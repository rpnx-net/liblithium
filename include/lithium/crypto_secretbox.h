#ifndef crypto_secretbox_H
#define crypto_secretbox_H

#include <stddef.h>

#include "crypto_secretbox_xsalsa20poly1305.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_secretbox_KEYBYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
LITHIUM_EXPORT
size_t  crypto_secretbox_keybytes(void);

#define crypto_secretbox_NONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
LITHIUM_EXPORT
size_t  crypto_secretbox_noncebytes(void);

#define crypto_secretbox_MACBYTES crypto_secretbox_xsalsa20poly1305_MACBYTES
LITHIUM_EXPORT
size_t  crypto_secretbox_macbytes(void);

#define crypto_secretbox_PRIMITIVE "xsalsa20poly1305"
LITHIUM_EXPORT
const char *crypto_secretbox_primitive(void);

#define crypto_secretbox_MESSAGEBYTES_MAX crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX
LITHIUM_EXPORT
size_t crypto_secretbox_messagebytes_max(void);

LITHIUM_EXPORT
int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
                          unsigned long long mlen, const unsigned char *n,
                          const unsigned char *k) __attribute__ ((nonnull(1, 4, 5)));

LITHIUM_EXPORT
int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                               unsigned long long clen, const unsigned char *n,
                               const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

LITHIUM_EXPORT
int crypto_secretbox_detached(unsigned char *c, unsigned char *mac,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n,
                              const unsigned char *k)
            __attribute__ ((nonnull(1, 2, 5, 6)));

LITHIUM_EXPORT
int crypto_secretbox_open_detached(unsigned char *m,
                                   const unsigned char *c,
                                   const unsigned char *mac,
                                   unsigned long long clen,
                                   const unsigned char *n,
                                   const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 3, 5, 6)));

LITHIUM_EXPORT
void crypto_secretbox_keygen(unsigned char k[crypto_secretbox_KEYBYTES])
            __attribute__ ((nonnull));

/* -- NaCl compatibility interface ; Requires padding -- */

#define crypto_secretbox_ZEROBYTES crypto_secretbox_xsalsa20poly1305_ZEROBYTES
LITHIUM_EXPORT
size_t  crypto_secretbox_zerobytes(void) __attribute__ ((deprecated));

#define crypto_secretbox_BOXZEROBYTES crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
LITHIUM_EXPORT
size_t  crypto_secretbox_boxzerobytes(void) __attribute__ ((deprecated));

LITHIUM_EXPORT
int crypto_secretbox(unsigned char *c, const unsigned char *m,
                     unsigned long long mlen, const unsigned char *n,
                     const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((nonnull(1, 4, 5)));

LITHIUM_EXPORT
int crypto_secretbox_open(unsigned char *m, const unsigned char *c,
                          unsigned long long clen, const unsigned char *n,
                          const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif
