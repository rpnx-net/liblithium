#ifndef rubidium_onetimeauth_H
#define rubidium_onetimeauth_H

#include <cstddef>

#include "rubidium_onetimeauth_poly1305.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef rubidium_onetimeauth_poly1305_state rubidium_onetimeauth_state;

RUBIDIUM_EXPORT
size_t  rubidium_onetimeauth_statebytes(void);

#define rubidium_onetimeauth_BYTES rubidium_onetimeauth_poly1305_BYTES
RUBIDIUM_EXPORT
size_t  rubidium_onetimeauth_bytes(void);

#define rubidium_onetimeauth_KEYBYTES RUBIDIUM_ONETIMEAUTH_POLY1305_KEYBYTES
RUBIDIUM_EXPORT
size_t  rubidium_onetimeauth_keybytes(void);

#define rubidium_onetimeauth_PRIMITIVE "poly1305"
RUBIDIUM_EXPORT
const char *rubidium_onetimeauth_primitive(void);

RUBIDIUM_EXPORT
int rubidium_onetimeauth(unsigned char *out, const unsigned char *in,
                       std::size_t inlen, const unsigned char *k)
            __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
int rubidium_onetimeauth_verify(const unsigned char *h, const unsigned char *in,
                              std::size_t inlen, const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(1, 4)));

RUBIDIUM_EXPORT
int rubidium_onetimeauth_init(rubidium_onetimeauth_state *state,
                            const unsigned char *key) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_onetimeauth_update(rubidium_onetimeauth_state *state,
                              const unsigned char *in,
                              std::size_t inlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_onetimeauth_final(rubidium_onetimeauth_state *state,
                             unsigned char *out) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_onetimeauth_keygen(unsigned char k[rubidium_onetimeauth_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
