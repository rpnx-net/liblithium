
#ifndef randombytes_H
#define randombytes_H

#include <cstddef>
#include <cstdint>


#include "export.h"


#define randombytes_SEEDBYTES 32U

size_t randombytes_seedbytes(void);


void randombytes_buf(void * const buf, const size_t size)
            __attribute__ ((nonnull));





uint32_t randombytes_uniform(const uint32_t upper_bound);


void randombytes_stir(void);


int randombytes_close(void);




/* -- NaCl compatibility interface -- */


void randombytes(unsigned char * const buf, const std::size_t buf_len)
            __attribute__ ((nonnull));



#endif
