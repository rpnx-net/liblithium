#ifndef rubidium_hash_H
#define rubidium_hash_H

/*
 * WARNING: Unless you absolutely need to use SHA512 for interoperability,
 * purposes, you might want to consider rubidium_generichash() instead.
 * Unlike SHA512, rubidium_generichash() is not vulnerable to length
 * extension attacks.
 */

#include <stddef.h>

#include "rubidium_hash_sha512.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_hash_BYTES rubidium_hash_sha512_BYTES
RUBIDIUM_EXPORT
size_t rubidium_hash_bytes(void);

RUBIDIUM_EXPORT
int rubidium_hash(unsigned char *out, const unsigned char *in,
                unsigned long long inlen) __attribute__ ((nonnull(1)));

#define rubidium_hash_PRIMITIVE "sha512"
RUBIDIUM_EXPORT
const char *rubidium_hash_primitive(void)
            __attribute__ ((warn_unused_result));

#ifdef __cplusplus
}
#endif

#endif
