#ifndef rubidium_core_ed25519_H
#define rubidium_core_ed25519_H

#include <cstddef>
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rubidium_core_ed25519_BYTES 32

size_t rubidium_core_ed25519_bytes(void);

#define rubidium_core_ed25519_UNIFORMBYTES 32

size_t rubidium_core_ed25519_uniformbytes(void);

#define rubidium_core_ed25519_HASHBYTES 64

size_t rubidium_core_ed25519_hashbytes(void);

#define rubidium_core_ed25519_SCALARBYTES 32

size_t rubidium_core_ed25519_scalarbytes(void);

#define rubidium_core_ed25519_NONREDUCEDSCALARBYTES 64

size_t rubidium_core_ed25519_nonreducedscalarbytes(void);

#define rubidium_core_ed25519_H2CSHA256 1
#define rubidium_core_ed25519_H2CSHA512 2


int rubidium_core_ed25519_is_valid_point(const unsigned char *p)
            __attribute__ ((nonnull));


int rubidium_core_ed25519_add(unsigned char *r,
                            const unsigned char *p, const unsigned char *q)
            __attribute__ ((nonnull));


int rubidium_core_ed25519_sub(unsigned char *r,
                            const unsigned char *p, const unsigned char *q)
            __attribute__ ((nonnull));


int rubidium_core_ed25519_from_uniform(unsigned char *p, const unsigned char *r)
            __attribute__ ((nonnull));


int rubidium_core_ed25519_from_string(unsigned char p[rubidium_core_ed25519_BYTES],
                                    const char *ctx, const unsigned char *msg,
                                    size_t msg_len, int hash_alg)
            __attribute__ ((nonnull(1)));


int rubidium_core_ed25519_from_string_ro(unsigned char p[rubidium_core_ed25519_BYTES],
                                       const char *ctx, const unsigned char *msg,
                                       size_t msg_len, int hash_alg)
            __attribute__ ((nonnull(1)));


void rubidium_core_ed25519_random(unsigned char *p)
            __attribute__ ((nonnull));


void rubidium_core_ed25519_scalar_random(unsigned char *r)
            __attribute__ ((nonnull));


int rubidium_core_ed25519_scalar_invert(unsigned char *recip, const unsigned char *s)
            __attribute__ ((nonnull));


void rubidium_core_ed25519_scalar_negate(unsigned char *neg, const unsigned char *s)
            __attribute__ ((nonnull));


void rubidium_core_ed25519_scalar_complement(unsigned char *comp, const unsigned char *s)
            __attribute__ ((nonnull));


void rubidium_core_ed25519_scalar_add(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
            __attribute__ ((nonnull));


void rubidium_core_ed25519_scalar_sub(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
            __attribute__ ((nonnull));


void rubidium_core_ed25519_scalar_mul(unsigned char *z, const unsigned char *x,
                                    const unsigned char *y)
            __attribute__ ((nonnull));

/*
 * The interval `s` is sampled from should be at least 317 bits to ensure almost
 * uniformity of `r` over `L`.
 */

void rubidium_core_ed25519_scalar_reduce(unsigned char *r, const unsigned char *s)
            __attribute__ ((nonnull));


int rubidium_core_ed25519_scalar_is_canonical(const unsigned char *s)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
