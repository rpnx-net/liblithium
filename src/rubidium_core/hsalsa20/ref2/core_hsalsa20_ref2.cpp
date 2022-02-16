/*
version 20080912
D. J. Bernstein
Public domain.
*/

#include <cstdint>
#include <stdlib.h>

#include "rubidium_core_hsalsa20.h"
#include "private/common.h"

#define ROUNDS 20
#define U32C(v) (v##U)

int
rubidium_core_hsalsa20(unsigned char *out,
                     const unsigned char *in,
                     const unsigned char *k,
                     const unsigned char *c)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8,
             x9, x10, x11, x12, x13, x14,  x15;
    int      i;

    if (c == NULL) {
        x0 = U32C(0x61707865);
        x5 = U32C(0x3320646e);
        x10 = U32C(0x79622d32);
        x15 = U32C(0x6b206574);
    } else {
        x0 = load32_le(c + 0);
        x5 = load32_le(c + 4);
        x10 = load32_le(c + 8);
        x15 = load32_le(c + 12);
    }
    x1 = load32_le(k + 0);
    x2 = load32_le(k + 4);
    x3 = load32_le(k + 8);
    x4 = load32_le(k + 12);
    x11 = load32_le(k + 16);
    x12 = load32_le(k + 20);
    x13 = load32_le(k + 24);
    x14 = load32_le(k + 28);
    x6 = load32_le(in + 0);
    x7 = load32_le(in + 4);
    x8 = load32_le(in + 8);
    x9 = load32_le(in + 12);

    for (i = ROUNDS; i > 0; i -= 2) {
        x4 ^= std::rotl<std::uint32_t>(x0 + x12, 7);
        x8 ^= std::rotl<std::uint32_t>(x4 + x0, 9);
        x12 ^= std::rotl<std::uint32_t>(x8 + x4, 13);
        x0 ^= std::rotl<std::uint32_t>(x12 + x8, 18);
        x9 ^= std::rotl<std::uint32_t>(x5 + x1, 7);
        x13 ^= std::rotl<std::uint32_t>(x9 + x5, 9);
        x1 ^= std::rotl<std::uint32_t>(x13 + x9, 13);
        x5 ^= std::rotl<std::uint32_t>(x1 + x13, 18);
        x14 ^= std::rotl<std::uint32_t>(x10 + x6, 7);
        x2 ^= std::rotl<std::uint32_t>(x14 + x10, 9);
        x6 ^= std::rotl<std::uint32_t>(x2 + x14, 13);
        x10 ^= std::rotl<std::uint32_t>(x6 + x2, 18);
        x3 ^= std::rotl<std::uint32_t>(x15 + x11, 7);
        x7 ^= std::rotl<std::uint32_t>(x3 + x15, 9);
        x11 ^= std::rotl<std::uint32_t>(x7 + x3, 13);
        x15 ^= std::rotl<std::uint32_t>(x11 + x7, 18);
        x1 ^= std::rotl<std::uint32_t>(x0 + x3, 7);
        x2 ^= std::rotl<std::uint32_t>(x1 + x0, 9);
        x3 ^= std::rotl<std::uint32_t>(x2 + x1, 13);
        x0 ^= std::rotl<std::uint32_t>(x3 + x2, 18);
        x6 ^= std::rotl<std::uint32_t>(x5 + x4, 7);
        x7 ^= std::rotl<std::uint32_t>(x6 + x5, 9);
        x4 ^= std::rotl<std::uint32_t>(x7 + x6, 13);
        x5 ^= std::rotl<std::uint32_t>(x4 + x7, 18);
        x11 ^= std::rotl<std::uint32_t>(x10 + x9, 7);
        x8 ^= std::rotl<std::uint32_t>(x11 + x10, 9);
        x9 ^= std::rotl<std::uint32_t>(x8 + x11, 13);
        x10 ^= std::rotl<std::uint32_t>(x9 + x8, 18);
        x12 ^= std::rotl<std::uint32_t>(x15 + x14, 7);
        x13 ^= std::rotl<std::uint32_t>(x12 + x15, 9);
        x14 ^= std::rotl<std::uint32_t>(x13 + x12, 13);
        x15 ^= std::rotl<std::uint32_t>(x14 + x13, 18);
    }

    store32_le((out + 0), (x0));
    store32_le((out + 4), (x5));
    store32_le((out + 8), (x10));
    store32_le((out + 12), (x15));
    store32_le((out + 16), (x6));
    store32_le((out + 20), (x7));
    store32_le((out + 24), (x8));
    store32_le((out + 28), (x9));

    return 0;
}
