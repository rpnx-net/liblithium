
#include <stdint.h>
#include <stdlib.h>

#include "rubidium_core_hchacha20.h"
#include "private/common.h"

#define QUARTERROUND(A, B, C, D)     \
  do {                               \
      A += B; D = std::rotl<std::uint32_t>(D ^ A, 16); \
      C += D; B = std::rotl<std::uint32_t>(B ^ C, 12); \
      A += B; D = std::rotl<std::uint32_t>(D ^ A,  8); \
      C += D; B = std::rotl<std::uint32_t>(B ^ C,  7); \
  } while(0)

int
rubidium_core_hchacha20(unsigned char *out, const unsigned char *in,
                      const unsigned char *k, const unsigned char *c)
{
    int      i;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;

    if (c == NULL) {
        x0 = 0x61707865;
        x1 = 0x3320646e;
        x2 = 0x79622d32;
        x3 = 0x6b206574;
    } else {
        x0 = load32_le(c + 0);
        x1 = load32_le(c + 4);
        x2 = load32_le(c + 8);
        x3 = load32_le(c + 12);
    }
    x4  = load32_le(k + 0);
    x5  = load32_le(k + 4);
    x6  = load32_le(k + 8);
    x7  = load32_le(k + 12);
    x8  = load32_le(k + 16);
    x9  = load32_le(k + 20);
    x10 = load32_le(k + 24);
    x11 = load32_le(k + 28);
    x12 = load32_le(in + 0);
    x13 = load32_le(in + 4);
    x14 = load32_le(in + 8);
    x15 = load32_le(in + 12);

    for (i = 0; i < 10; i++) {
        QUARTERROUND(x0, x4,  x8, x12);
        QUARTERROUND(x1, x5,  x9, x13);
        QUARTERROUND(x2, x6, x10, x14);
        QUARTERROUND(x3, x7, x11, x15);
        QUARTERROUND(x0, x5, x10, x15);
        QUARTERROUND(x1, x6, x11, x12);
        QUARTERROUND(x2, x7,  x8, x13);
        QUARTERROUND(x3, x4,  x9, x14);
    }

    store32_le((out + 0), (x0));
    store32_le((out + 4), (x1));
    store32_le((out + 8), (x2));
    store32_le((out + 12), (x3));
    store32_le((out + 16), (x12));
    store32_le((out + 20), (x13));
    store32_le((out + 24), (x14));
    store32_le((out + 28), (x15));

    return 0;
}

size_t
rubidium_core_hchacha20_outputbytes(void)
{
    return rubidium_core_hchacha20_OUTPUTBYTES;
}

size_t
rubidium_core_hchacha20_inputbytes(void)
{
    return rubidium_core_hchacha20_INPUTBYTES;
}

size_t
rubidium_core_hchacha20_keybytes(void)
{
    return rubidium_core_hchacha20_KEYBYTES;
}

size_t
rubidium_core_hchacha20_constbytes(void)
{
    return rubidium_core_hchacha20_CONSTBYTES;
}
