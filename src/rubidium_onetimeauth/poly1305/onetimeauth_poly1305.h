
#ifndef onetimeauth_poly1305_H
#define onetimeauth_poly1305_H

#include "rubidium_onetimeauth_poly1305.h"

typedef struct rubidium_onetimeauth_poly1305_implementation {
    int (*onetimeauth)(unsigned char *out, const unsigned char *in,
                       std::size_t inlen, const unsigned char *k);
    int (*onetimeauth_verify)(const unsigned char *h, const unsigned char *in,
                              std::size_t inlen, const unsigned char *k);
    int (*onetimeauth_init)(rubidium_onetimeauth_poly1305_state *state,
                            const unsigned char *              key);
    int (*onetimeauth_update)(rubidium_onetimeauth_poly1305_state *state,
                              const unsigned char *              in,
                              std::size_t                 inlen);
    int (*onetimeauth_final)(rubidium_onetimeauth_poly1305_state *state,
                             unsigned char *                    out);
} rubidium_onetimeauth_poly1305_implementation;

#endif
