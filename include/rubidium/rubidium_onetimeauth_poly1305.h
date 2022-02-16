#ifndef rubidium_onetimeauth_poly1305_H
#define rubidium_onetimeauth_poly1305_H



#include <cstdint>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>

#include "export.h"

typedef struct RUBIDIUM_ALIGN(16) rubidium_onetimeauth_poly1305_state {
    unsigned char opaque[256];
} rubidium_onetimeauth_poly1305_state;


size_t rubidium_onetimeauth_poly1305_statebytes(void);

#define rubidium_onetimeauth_poly1305_BYTES 16U

size_t rubidium_onetimeauth_poly1305_bytes(void);

#define RUBIDIUM_ONETIMEAUTH_POLY1305_KEYBYTES 32U

size_t rubidium_onetimeauth_poly1305_keybytes(void);


int rubidium_onetimeauth_poly1305(unsigned char *out,
                                const unsigned char *in,
                                std::size_t inlen,
                                const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));


int rubidium_onetimeauth_poly1305_verify(const unsigned char *h,
                                       const unsigned char *in,
                                       std::size_t inlen,
                                       const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));


int rubidium_onetimeauth_poly1305_init(rubidium_onetimeauth_poly1305_state *state,
                                     const unsigned char *key)
            __attribute__ ((nonnull));


int rubidium_onetimeauth_poly1305_update(rubidium_onetimeauth_poly1305_state *state,
                                       const unsigned char *in,
                                       std::size_t inlen)
            __attribute__ ((nonnull(1)));


int rubidium_onetimeauth_poly1305_final(rubidium_onetimeauth_poly1305_state *state,
                                      unsigned char *out)
            __attribute__ ((nonnull));


void rubidium_onetimeauth_poly1305_keygen(unsigned char k[RUBIDIUM_ONETIMEAUTH_POLY1305_KEYBYTES])
            __attribute__ ((nonnull));



#endif
