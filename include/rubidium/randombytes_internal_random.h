
#ifndef randombytes_internal_random_H
#define randombytes_internal_random_H

#include "export.h"
#include "randombytes.h"

#ifdef __cplusplus
extern "C" {
#endif

RUBIDIUM_EXPORT
extern struct randombytes_implementation randombytes_internal_implementation;

/* Backwards compatibility with librubidium < 1.0.18 */
#define randombytes_salsa20_implementation randombytes_internal_implementation

#ifdef __cplusplus
}
#endif

#endif
