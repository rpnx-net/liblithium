#ifndef rubidium_core_ristretto255_H
#define rubidium_core_ristretto255_H

#include <cstddef>
#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#define rubidium_core_ristretto255_BYTES 32
RUBIDIUM_EXPORT
size_t rubidium_core_ristretto255_bytes(void);

#define rubidium_core_ristretto255_HASHBYTES 64
RUBIDIUM_EXPORT
size_t rubidium_core_ristretto255_hashbytes(void);

#define rubidium_core_ristretto255_SCALARBYTES 32
RUBIDIUM_EXPORT
size_t rubidium_core_ristretto255_scalarbytes(void);

#define rubidium_core_ristretto255_NONREDUCEDSCALARBYTES 64
RUBIDIUM_EXPORT
size_t rubidium_core_ristretto255_nonreducedscalarbytes(void);

#define rubidium_core_ristretto255_H2CSHA256 1
#define rubidium_core_ristretto255_H2CSHA512 2

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_is_valid_point(const unsigned char *p)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_add(unsigned char *r,
                                 const unsigned char *p, const unsigned char *q)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_sub(unsigned char *r,
                                 const unsigned char *p, const unsigned char *q)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_from_hash(unsigned char *p,
                                       const unsigned char *r)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_from_string(unsigned char p[rubidium_core_ristretto255_BYTES],
                                         const char *ctx,
                                         const unsigned char *msg,
                                         size_t msg_len, int hash_alg)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_from_string_ro(unsigned char p[rubidium_core_ristretto255_BYTES],
                                            const char *ctx,
                                            const unsigned char *msg,
                                            size_t msg_len, int hash_alg)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_random(unsigned char *p)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_random(unsigned char *r)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_scalar_invert(unsigned char *recip,
                                           const unsigned char *s)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_negate(unsigned char *neg,
                                            const unsigned char *s)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_complement(unsigned char *comp,
                                                const unsigned char *s)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_add(unsigned char *z,
                                         const unsigned char *x,
                                         const unsigned char *y)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_sub(unsigned char *z,
                                         const unsigned char *x,
                                         const unsigned char *y)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_mul(unsigned char *z,
                                         const unsigned char *x,
                                         const unsigned char *y)
            __attribute__ ((nonnull));

/*
 * The interval `s` is sampled from should be at least 317 bits to ensure almost
 * uniformity of `r` over `L`.
 */
RUBIDIUM_EXPORT
void rubidium_core_ristretto255_scalar_reduce(unsigned char *r,
                                            const unsigned char *s)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_core_ristretto255_scalar_is_canonical(const unsigned char *s)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
