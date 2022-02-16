#ifndef rubidium_secretbox_H
#define rubidium_secretbox_H

#include <cstddef>

#include "rubidium_secretbox_xsalsa20poly1305.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_secretbox_KEYBYTES rubidium_secretbox_xsalsa20poly1305_KEYBYTES

size_t  rubidium_secretbox_keybytes(void);

#define rubidium_secretbox_NONCEBYTES rubidium_secretbox_xsalsa20poly1305_NONCEBYTES

size_t  rubidium_secretbox_noncebytes(void);

#define rubidium_secretbox_MACBYTES rubidium_secretbox_xsalsa20poly1305_MACBYTES

size_t  rubidium_secretbox_macbytes(void);

#define rubidium_secretbox_PRIMITIVE "xsalsa20poly1305"

const char *rubidium_secretbox_primitive(void);

#define rubidium_secretbox_MESSAGEBYTES_MAX rubidium_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX

size_t rubidium_secretbox_messagebytes_max(void);


int rubidium_secretbox_easy(unsigned char *c, const unsigned char *m,
                          std::size_t mlen, const unsigned char *n,
                          const unsigned char *k) __attribute__ ((nonnull(1, 4, 5)));


int rubidium_secretbox_open_easy(unsigned char *m, const unsigned char *c,
                               std::size_t clen, const unsigned char *n,
                               const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));


int rubidium_secretbox_detached(unsigned char *c, unsigned char *mac,
                              const unsigned char *m,
                              std::size_t mlen,
                              const unsigned char *n,
                              const unsigned char *k)
            __attribute__ ((nonnull(1, 2, 5, 6)));


int rubidium_secretbox_open_detached(unsigned char *m,
                                   const unsigned char *c,
                                   const unsigned char *mac,
                                   std::size_t clen,
                                   const unsigned char *n,
                                   const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 3, 5, 6)));


void rubidium_secretbox_keygen(unsigned char k[rubidium_secretbox_KEYBYTES])
            __attribute__ ((nonnull));

/* -- NaCl compatibility interface ; Requires padding -- */

#define rubidium_secretbox_ZEROBYTES rubidium_secretbox_xsalsa20poly1305_ZEROBYTES

size_t  rubidium_secretbox_zerobytes(void) __attribute__ ((deprecated));

#define rubidium_secretbox_BOXZEROBYTES rubidium_secretbox_xsalsa20poly1305_BOXZEROBYTES

size_t  rubidium_secretbox_boxzerobytes(void) __attribute__ ((deprecated));


int rubidium_secretbox(unsigned char *c, const unsigned char *m,
                     std::size_t mlen, const unsigned char *n,
                     const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((nonnull(1, 4, 5)));


int rubidium_secretbox_open(unsigned char *m, const unsigned char *c,
                          std::size_t clen, const unsigned char *n,
                          const unsigned char *k)
            __attribute__ ((deprecated)) __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(2, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif
