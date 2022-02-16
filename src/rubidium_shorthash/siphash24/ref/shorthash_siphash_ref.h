#ifndef shorthash_siphash_H
#define shorthash_siphash_H

#include "private/common.h"

#define SIPROUND             \
    do {                     \
        v0 += v1;            \
        v1 = std::rotl<std::uint64_t>(v1, 13); \
        v1 ^= v0;            \
        v0 = std::rotl<std::uint64_t>(v0, 32); \
        v2 += v3;            \
        v3 = std::rotl<std::uint64_t>(v3, 16); \
        v3 ^= v2;            \
        v0 += v3;            \
        v3 = std::rotl<std::uint64_t>(v3, 21); \
        v3 ^= v0;            \
        v2 += v1;            \
        v1 = std::rotl<std::uint64_t>(v1, 17); \
        v1 ^= v2;            \
        v2 = std::rotl<std::uint64_t>(v2, 32); \
    } while (0)

#endif
