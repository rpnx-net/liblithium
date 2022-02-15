
#ifndef randombytes_H
#define randombytes_H

#include <cstddef>
#include <cstdint>


#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

typedef struct randombytes_implementation {
    const char *(*implementation_name)(void); /* required */
    uint32_t    (*random)(void);              /* required */
    void        (*stir)(void);                /* optional */
    uint32_t    (*uniform)(const uint32_t upper_bound); /* optional, a default implementation will be used if NULL */
    void        (*buf)(void * const buf, const size_t size); /* required */
    int         (*close)(void);               /* optional */
} randombytes_implementation;

#define randombytes_BYTES_MAX RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX, 0xffffffffUL)

#define randombytes_SEEDBYTES 32U
RUBIDIUM_EXPORT
size_t randombytes_seedbytes(void);

RUBIDIUM_EXPORT
void randombytes_buf(void * const buf, const size_t size)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
void randombytes_buf_deterministic(void * const buf, const size_t size,
                                   const unsigned char seed[randombytes_SEEDBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
uint32_t randombytes_random(void);

RUBIDIUM_EXPORT
uint32_t randombytes_uniform(const uint32_t upper_bound);

RUBIDIUM_EXPORT
void randombytes_stir(void);

RUBIDIUM_EXPORT
int randombytes_close(void);

RUBIDIUM_EXPORT
int randombytes_set_implementation(const randombytes_implementation *impl)
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
const char *randombytes_implementation_name(void);

/* -- NaCl compatibility interface -- */

RUBIDIUM_EXPORT
void randombytes(unsigned char * const buf, const unsigned long long buf_len)
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
