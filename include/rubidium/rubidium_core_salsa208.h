#ifndef rubidium_core_salsa208_H
#define rubidium_core_salsa208_H

#include <cstddef>
#include "export.h"



#define rubidium_core_salsa208_OUTPUTBYTES 64U

size_t rubidium_core_salsa208_outputbytes(void)
            __attribute__ ((deprecated));

#define rubidium_core_salsa208_INPUTBYTES 16U

size_t rubidium_core_salsa208_inputbytes(void)
            __attribute__ ((deprecated));

#define rubidium_core_salsa208_KEYBYTES 32U

size_t rubidium_core_salsa208_keybytes(void)
            __attribute__ ((deprecated));

#define rubidium_core_salsa208_CONSTBYTES 16U

size_t rubidium_core_salsa208_constbytes(void)
            __attribute__ ((deprecated));


int rubidium_core_salsa208(unsigned char *out, const unsigned char *in,
                         const unsigned char *k, const unsigned char *c)
            __attribute__ ((nonnull(1, 2, 3)));



#endif
