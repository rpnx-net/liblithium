#ifndef rubidium_core_salsa20_H
#define rubidium_core_salsa20_H

#include <cstddef>
#include "export.h"



#define rubidium_core_salsa20_OUTPUTBYTES 64U

size_t rubidium_core_salsa20_outputbytes(void);

#define rubidium_core_salsa20_INPUTBYTES 16U

size_t rubidium_core_salsa20_inputbytes(void);

#define rubidium_core_salsa20_KEYBYTES 32U

size_t rubidium_core_salsa20_keybytes(void);

#define rubidium_core_salsa20_CONSTBYTES 16U

size_t rubidium_core_salsa20_constbytes(void);


int rubidium_core_salsa20(unsigned char *out, const unsigned char *in,
                        const unsigned char *k, const unsigned char *c)
            __attribute__ ((nonnull(1, 2, 3)));



#endif
