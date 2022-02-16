#ifndef chacha20_ietf_ext_H
#define chacha20_ietf_ext_H

#include <cstdint>



/* The ietf_ext variant allows the internal counter to overflow into the IV */

int rubidium_stream_chacha20_ietf_ext(unsigned char *c, std::size_t clen,
                                    const unsigned char *n, const unsigned char *k);

int rubidium_stream_chacha20_ietf_ext_xor_ic(unsigned char *c, const unsigned char *m,
                                           std::size_t mlen,
                                           const unsigned char *n, uint32_t ic,
                                           const unsigned char *k);
#endif

