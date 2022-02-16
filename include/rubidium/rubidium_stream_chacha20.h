#ifndef rubidium_stream_chacha20_H
#define rubidium_stream_chacha20_H

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

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define RUBIDIUM_STREAM_CHACHA20_KEYBYTES 32U

size_t rubidium_stream_chacha20_keybytes(void);

#define rubidium_stream_chacha20_NONCEBYTES 8U

size_t rubidium_stream_chacha20_noncebytes(void);

#define rubidium_stream_chacha20_MESSAGEBYTES_MAX RUBIDIUM_SIZE_MAX

size_t rubidium_stream_chacha20_messagebytes_max(void);

/* ChaCha20 with a 64-bit nonce and a 64-bit counter, as originally designed */


int rubidium_stream_chacha20(unsigned char *c, std::size_t clen,
                           const unsigned char *n, const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                               std::size_t mlen, const unsigned char *n,
                               const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                                  std::size_t mlen,
                                  const unsigned char *n, uint64_t ic,
                                  const unsigned char *k)
            __attribute__ ((nonnull));


void rubidium_stream_chacha20_keygen(unsigned char k[RUBIDIUM_STREAM_CHACHA20_KEYBYTES])
            __attribute__ ((nonnull));

/* ChaCha20 with a 96-bit nonce and a 32-bit counter (IETF) */

#define rubidium_stream_chacha20_ietf_KEYBYTES 32U

size_t rubidium_stream_chacha20_ietf_keybytes(void);

#define rubidium_stream_chacha20_ietf_NONCEBYTES 12U

size_t rubidium_stream_chacha20_ietf_noncebytes(void);

#define rubidium_stream_chacha20_ietf_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX, 64ULL * (1ULL << 32))

size_t rubidium_stream_chacha20_ietf_messagebytes_max(void);


int rubidium_stream_chacha20_ietf(unsigned char *c, std::size_t clen,
                                const unsigned char *n, const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                    std::size_t mlen, const unsigned char *n,
                                    const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                       std::size_t mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k)
            __attribute__ ((nonnull));


void rubidium_stream_chacha20_ietf_keygen(unsigned char k[rubidium_stream_chacha20_ietf_KEYBYTES])
            __attribute__ ((nonnull));

/* Aliases */

#define rubidium_stream_chacha20_IETF_KEYBYTES rubidium_stream_chacha20_ietf_KEYBYTES
#define rubidium_stream_chacha20_IETF_NONCEBYTES rubidium_stream_chacha20_ietf_NONCEBYTES
#define rubidium_stream_chacha20_IETF_MESSAGEBYTES_MAX rubidium_stream_chacha20_ietf_MESSAGEBYTES_MAX

#ifdef __cplusplus
}
#endif

#endif
