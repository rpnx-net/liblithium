#ifndef rubidium_secretbox_xsalsa20poly1305_H
#define rubidium_secretbox_xsalsa20poly1305_H

#include <cstddef>
#include "rubidium_stream_xsalsa20.h"
#include "export.h"


#define rubidium_secretbox_xsalsa20poly1305_KEYBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_secretbox_xsalsa20poly1305_keybytes(void);

#define rubidium_secretbox_xsalsa20poly1305_NONCEBYTES 24U
RUBIDIUM_EXPORT
size_t rubidium_secretbox_xsalsa20poly1305_noncebytes(void);

#define rubidium_secretbox_xsalsa20poly1305_MACBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_secretbox_xsalsa20poly1305_macbytes(void);

/* Only for the librubidium API - The NaCl compatibility API would require BOXZEROBYTES extra bytes */
#define rubidium_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX \
    (rubidium_stream_xsalsa20_MESSAGEBYTES_MAX - rubidium_secretbox_xsalsa20poly1305_MACBYTES)
RUBIDIUM_EXPORT
size_t rubidium_secretbox_xsalsa20poly1305_messagebytes_max(void);

RUBIDIUM_EXPORT
void rubidium_secretbox_xsalsa20poly1305_keygen(unsigned char k[rubidium_secretbox_xsalsa20poly1305_KEYBYTES])
            __attribute__ ((nonnull));

/* -- NaCl compatibility interface ; Requires padding -- */

#define rubidium_secretbox_xsalsa20poly1305_BOXZEROBYTES 16U
RUBIDIUM_EXPORT
size_t rubidium_secretbox_xsalsa20poly1305_boxzerobytes(void)
            __attribute__ ((deprecated));

#define rubidium_secretbox_xsalsa20poly1305_ZEROBYTES \
    (rubidium_secretbox_xsalsa20poly1305_BOXZEROBYTES + \
     rubidium_secretbox_xsalsa20poly1305_MACBYTES)
RUBIDIUM_EXPORT
size_t rubidium_secretbox_xsalsa20poly1305_zerobytes(void)
            __attribute__ ((deprecated));

RUBIDIUM_EXPORT
int rubidium_secretbox_xsalsa20poly1305(unsigned char *c,
                                      const unsigned char *m,
                                      std::size_t mlen,
                                      const unsigned char *n,
                                      const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((nonnull(1, 4, 5)));

RUBIDIUM_EXPORT
int rubidium_secretbox_xsalsa20poly1305_open(unsigned char *m,
                                           const unsigned char *c,
                                           std::size_t clen,
                                           const unsigned char *n,
                                           const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));



#endif
