#ifndef rubidium_auth_H
#define rubidium_auth_H

#include <stddef.h>

#include "rubidium_auth_hmacsha512256.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_auth_BYTES rubidium_auth_hmacsha512256_BYTES
RUBIDIUM_EXPORT
size_t  rubidium_auth_bytes(void);

#define rubidium_auth_KEYBYTES rubidium_auth_hmacsha512256_KEYBYTES
RUBIDIUM_EXPORT
size_t  rubidium_auth_keybytes(void);

#define rubidium_auth_PRIMITIVE "hmacsha512256"
RUBIDIUM_EXPORT
const char *rubidium_auth_primitive(void);

RUBIDIUM_EXPORT
int rubidium_auth(unsigned char *out, const unsigned char *in,
                unsigned long long inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
int rubidium_auth_verify(const unsigned char *h, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
void rubidium_auth_keygen(unsigned char k[rubidium_auth_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
