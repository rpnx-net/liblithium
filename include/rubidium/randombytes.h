
#ifndef randombytes_H
#define randombytes_H

#include <cstddef>
#include <cstdint>


#include "export.h"


#define randombytes_SEEDBYTES 32U
RUBIDIUM_EXPORT
size_t randombytes_seedbytes(void);

RUBIDIUM_EXPORT
void randombytes_buf(void * const buf, const size_t size)
            __attribute__ ((nonnull));




RUBIDIUM_EXPORT
uint32_t randombytes_uniform(const uint32_t upper_bound);

RUBIDIUM_EXPORT
void randombytes_stir(void);

RUBIDIUM_EXPORT
int randombytes_close(void);




/* -- NaCl compatibility interface -- */

RUBIDIUM_EXPORT
void randombytes(unsigned char * const buf, const unsigned long long buf_len)
            __attribute__ ((nonnull));



#endif
