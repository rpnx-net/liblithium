#ifndef rubidium_verify_64_H
#define rubidium_verify_64_H

#include <cstddef>
#include "export.h"



#define rubidium_verify_64_BYTES 64U

size_t rubidium_verify_64_bytes(void);


int rubidium_verify_64(const unsigned char *x, const unsigned char *y)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));



#endif
