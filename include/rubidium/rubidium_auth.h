#ifndef rubidium_auth_H
#define rubidium_auth_H

#include <cstddef>

#include "rubidium_auth_hmacsha512256.h"
#include "export.h"



#define rubidium_auth_BYTES RUBIDIUM_AUTH_HMACSHA512256_BYTES

size_t  rubidium_auth_bytes(void);

#define rubidium_auth_KEYBYTES RUBIDIUM_AUTH_HMACSHA512256_KEYBYTES

size_t  rubidium_auth_keybytes(void);

#define rubidium_auth_PRIMITIVE "hmacsha512256"

const char *rubidium_auth_primitive(void);


int rubidium_auth(unsigned char *out, const unsigned char *in,
                std::size_t inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));


int rubidium_auth_verify(const unsigned char *h, const unsigned char *in,
                       std::size_t inlen, const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));


void rubidium_auth_keygen(unsigned char k[rubidium_auth_KEYBYTES])
            __attribute__ ((nonnull));



#endif
