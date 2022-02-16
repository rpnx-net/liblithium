#ifndef rubidium_stream_salsa20_H
#define rubidium_stream_salsa20_H

/*
 *  WARNING: This is just a stream cipher. It is NOT authenticated encryption.
 *  While it provides some protection against eavesdropping, it does NOT
 *  provide any security against active attacks.
 *  Unless you know what you're doing, what you are looking for is probably
 *  the rubidium_box functions.
 */

#include <cstddef>
#include <cstdint>
#include "export.h"



#define rubidium_stream_salsa20_KEYBYTES 32U

size_t rubidium_stream_salsa20_keybytes(void);

#define rubidium_stream_salsa20_NONCEBYTES 8U

size_t rubidium_stream_salsa20_noncebytes(void);

#define rubidium_stream_salsa20_MESSAGEBYTES_MAX RUBIDIUM_SIZE_MAX

size_t rubidium_stream_salsa20_messagebytes_max(void);


int rubidium_stream_salsa20(unsigned char *c, std::size_t clen,
                          const unsigned char *n, const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_salsa20_xor(unsigned char *c, const unsigned char *m,
                              std::size_t mlen, const unsigned char *n,
                              const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_salsa20_xor_ic(unsigned char *c, const unsigned char *m,
                                 std::size_t mlen,
                                 const unsigned char *n, uint64_t ic,
                                 const unsigned char *k)
            __attribute__ ((nonnull));


void rubidium_stream_salsa20_keygen(unsigned char k[rubidium_stream_salsa20_KEYBYTES])
            __attribute__ ((nonnull));



#endif
