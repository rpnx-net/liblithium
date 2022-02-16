
#ifndef rubidium_utils_H
#define rubidium_utils_H

#include <cstddef>

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RUBIDIUM_C99
# if defined(__cplusplus) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L
#  define RUBIDIUM_C99(X)
# else
#  define RUBIDIUM_C99(X) X
# endif
#endif

RUBIDIUM_EXPORT
void rubidium_memzero(void * const pnt, const size_t len);

/*
 * WARNING: rubidium_memcmp() must be used to verify if two secret keys
 * are equal, in constant time.
 * It returns 0 if the keys are equal, and -1 if they differ.
 * This function is not designed for lexicographical comparisons.
 */
RUBIDIUM_EXPORT
int rubidium_memcmp(const void * const b1_, const void * const b2_, size_t len)
            __attribute__ ((warn_unused_result));

/*
 * rubidium_compare() returns -1 if b1_ < b2_, 1 if b1_ > b2_ and 0 if b1_ == b2_
 * It is suitable for lexicographical comparisons, or to compare nonces
 * and counters stored in little-endian format.
 * However, it is slower than rubidium_memcmp().
 */
RUBIDIUM_EXPORT
int rubidium_compare(const unsigned char *b1_, const unsigned char *b2_,
                   size_t len) __attribute__ ((warn_unused_result));

RUBIDIUM_EXPORT
int rubidium_is_zero(const unsigned char *n, const size_t nlen);

RUBIDIUM_EXPORT
void rubidium_increment(unsigned char *n, const size_t nlen);

RUBIDIUM_EXPORT
void rubidium_add(unsigned char *a, const unsigned char *b, const size_t len);

RUBIDIUM_EXPORT
void rubidium_sub(unsigned char *a, const unsigned char *b, const size_t len);

RUBIDIUM_EXPORT
char *rubidium_bin2hex(char * const hex, const size_t hex_maxlen,
                     const unsigned char * const bin, const size_t bin_len)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
                   const char * const hex, const size_t hex_len,
                   const char * const ignore, size_t * const bin_len,
                   const char ** const hex_end)
            __attribute__ ((nonnull(1)));

#define rubidium_base64_VARIANT_ORIGINAL            1
#define rubidium_base64_VARIANT_ORIGINAL_NO_PADDING 3
#define rubidium_base64_VARIANT_URLSAFE             5
#define rubidium_base64_VARIANT_URLSAFE_NO_PADDING  7

/*
 * Computes the required length to encode BIN_LEN bytes as a base64 string
 * using the given variant. The computed length includes a trailing \0.
 */
#define rubidium_base64_ENCODED_LEN(BIN_LEN, VARIANT) \
    (((BIN_LEN) / 3U) * 4U + \
    ((((BIN_LEN) - ((BIN_LEN) / 3U) * 3U) | (((BIN_LEN) - ((BIN_LEN) / 3U) * 3U) >> 1)) & 1U) * \
     (4U - (~((((VARIANT) & 2U) >> 1) - 1U) & (3U - ((BIN_LEN) - ((BIN_LEN) / 3U) * 3U)))) + 1U)

RUBIDIUM_EXPORT
size_t rubidium_base64_encoded_len(const size_t bin_len, const int variant);

RUBIDIUM_EXPORT
char *rubidium_bin2base64(char * const b64, const size_t b64_maxlen,
                        const unsigned char * const bin, const size_t bin_len,
                        const int variant) __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_base642bin(unsigned char * const bin, const size_t bin_maxlen,
                      const char * const b64, const size_t b64_len,
                      const char * const ignore, size_t * const bin_len,
                      const char ** const b64_end, const int variant)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_mlock(void * const addr, const size_t len)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_munlock(void * const addr, const size_t len)
            __attribute__ ((nonnull));

/* WARNING: rubidium_malloc() and rubidium_allocarray() are not general-purpose
 * allocation functions.
 *
 * They return a pointer to a region filled with 0xd0 bytes, immediately
 * followed by a guard page.
 * As a result, accessing a single byte after the requested allocation size
 * will intentionally trigger a segmentation fault.
 *
 * A canary and an additional guard page placed before the beginning of the
 * region may also kill the process if a buffer underflow is detected.
 *
 * The memory layout is:
 * [unprotected region size (read only)][guard page (no access)][unprotected pages (read/write)][guard page (no access)]
 * With the layout of the unprotected pages being:
 * [optional padding][16-bytes canary][user region]
 *
 * However:
 * - These functions are significantly slower than standard functions
 * - Each allocation requires 3 or 4 additional pages
 * - The returned address will not be aligned if the allocation size is not
 *   a multiple of the required alignment. For this reason, these functions
 *   are designed to store data, such as secret keys and messages.
 *
 * rubidium_malloc() can be used to allocate any librubidium data structure.
 *
 * The rubidium_generichash_state structure is packed and its length is
 * either 357 or 361 bytes. For this reason, when using rubidium_malloc() to
 * allocate a rubidium_generichash_state structure, padding must be added in
 * order to ensure proper alignment. rubidium_generichash_statebytes()
 * returns the rounded up structure size, and should be preferred to sizeof():
 * state = rubidium_malloc(rubidium_generichash_statebytes());
 */

RUBIDIUM_EXPORT
void *rubidium_malloc(const size_t size)
            __attribute__ ((malloc));

RUBIDIUM_EXPORT
void *rubidium_allocarray(size_t count, size_t size)
            __attribute__ ((malloc));

RUBIDIUM_EXPORT
void rubidium_free(void *ptr);

RUBIDIUM_EXPORT
int rubidium_mprotect_noaccess(void *ptr) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_mprotect_readonly(void *ptr) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_mprotect_readwrite(void *ptr) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_pad(size_t *padded_buflen_p, unsigned char *buf,
               size_t unpadded_buflen, size_t blocksize, size_t max_buflen)
            __attribute__ ((nonnull(2)));

RUBIDIUM_EXPORT
int rubidium_unpad(size_t *unpadded_buflen_p, const unsigned char *buf,
                 size_t padded_buflen, size_t blocksize)
            __attribute__ ((nonnull(2)));

/* -------- */

int _rubidium_alloc_init(void);

#ifdef __cplusplus
}
#endif

#endif
