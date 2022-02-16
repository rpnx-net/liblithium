#ifndef rubidium_verify_32_H
#define rubidium_verify_32_H

#include <cstddef>
#include "export.h"



#define rubidium_verify_32_BYTES 32U

size_t rubidium_verify_32_bytes(void);


int rubidium_verify_32(const unsigned char *x, const unsigned char *y)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));



#endif
