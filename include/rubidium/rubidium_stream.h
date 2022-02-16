#ifndef rubidium_stream_H
#define rubidium_stream_H

/*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the rubidium_box functions.
 */

#include <cstddef>

#include "rubidium_stream_xsalsa20.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_stream_KEYBYTES rubidium_stream_xsalsa20_KEYBYTES

size_t  rubidium_stream_keybytes(void);

#define rubidium_stream_NONCEBYTES rubidium_stream_xsalsa20_NONCEBYTES

size_t  rubidium_stream_noncebytes(void);

#define rubidium_stream_MESSAGEBYTES_MAX rubidium_stream_xsalsa20_MESSAGEBYTES_MAX

size_t  rubidium_stream_messagebytes_max(void);

#define rubidium_stream_PRIMITIVE "xsalsa20"

const char *rubidium_stream_primitive(void);


int rubidium_stream(unsigned char *c, std::size_t clen,
                  const unsigned char *n, const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_xor(unsigned char *c, const unsigned char *m,
                      std::size_t mlen, const unsigned char *n,
                      const unsigned char *k)
            __attribute__ ((nonnull));


void rubidium_stream_keygen(unsigned char k[rubidium_stream_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
