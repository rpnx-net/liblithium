#ifndef rubidium_verify_16_H
#define rubidium_verify_16_H

#include <cstddef>
#include "export.h"



#define rubidium_verify_16_BYTES 16U

size_t rubidium_verify_16_bytes(void);


int rubidium_verify_16(const unsigned char *x, const unsigned char *y)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));



#endif
