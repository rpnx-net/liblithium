#ifndef rubidium_scalarmult_H
#define rubidium_scalarmult_H

#include <cstddef>

#include "rubidium_scalarmult_curve25519.h"
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rubidium_scalarmult_BYTES rubidium_scalarmult_curve25519_BYTES

size_t  rubidium_scalarmult_bytes(void);

#define rubidium_scalarmult_SCALARBYTES rubidium_scalarmult_curve25519_SCALARBYTES

size_t  rubidium_scalarmult_scalarbytes(void);

#define rubidium_scalarmult_PRIMITIVE "curve25519"

const char *rubidium_scalarmult_primitive(void);


int rubidium_scalarmult_base(unsigned char *q, const unsigned char *n)
            __attribute__ ((nonnull));

/*
 * NOTE: Do not use the result of this function directly for key exchange.
 *
 * Hash the result with the public keys in order to compute a shared
 * secret key: H(q || client_pk || server_pk)
 *
 * Or unless this is not an option, use the rubidium_kx() API instead.
 */

int rubidium_scalarmult(unsigned char *q, const unsigned char *n,
                      const unsigned char *p)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
