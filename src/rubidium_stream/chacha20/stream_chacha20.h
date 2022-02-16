
#ifndef stream_chacha20_H
#define stream_chacha20_H

#include <cstdint>

typedef struct rubidium_stream_chacha20_implementation {
    int (*stream)(unsigned char *c, std::size_t clen,
                  const unsigned char *n, const unsigned char *k);
    int (*stream_ietf_ext)(unsigned char *c, std::size_t clen,
                           const unsigned char *n, const unsigned char *k);
    int (*stream_xor_ic)(unsigned char *c, const unsigned char *m,
                         std::size_t mlen,
                         const unsigned char *n, uint64_t ic,
                         const unsigned char *k);
    int (*stream_ietf_ext_xor_ic)(unsigned char *c, const unsigned char *m,
                                  std::size_t mlen,
                                  const unsigned char *n, uint32_t ic,
                                  const unsigned char *k);
} rubidium_stream_chacha20_implementation;

#endif
