
#include "randombytes.h"

#include <random>

std::uint32_t rubidium::randombytes_uniform(const uint32_t upper_bound)
{
    thread_local std::random_device r;
    std::uniform_int_distribution<uint32_t> dist(0, upper_bound-1);
    return dist(r);
}

void rubidium::randombytes_fill(std::byte * buf, std::size_t size)
{
    thread_local std::random_device r;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (std::size_t i = 0; i != size; i++) {
        ((std::byte *)buf)[i] = std::byte(dist(r));
    }
}
