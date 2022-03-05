
#include <errno.h>
#include <stdlib.h>

#include "rubidium_aead_aegis128l.h"
#include "private/common.h"
#include "randombytes.h"
namespace rubidium
{
    void rubidium_aead_aegis128l_keygen(unsigned char k[rubidium_aead_aegis128l_KEYBYTES]) {
        rubidium::randombytes_fill(k, rubidium_aead_aegis128l_KEYBYTES);
    }
}