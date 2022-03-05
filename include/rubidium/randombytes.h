#ifndef RUBIDIUM_RANDOMBYTES_HPP
#define RUBIDIUM_RANDOMBYTES_HPP

#include <cstddef>
#include <cstdint>
#include <utility>

namespace rubidium
{
    void randombytes_fill(std::byte * buff, std::size_t count);
    inline void randombytes_fill(signed char * buff, std::size_t count)
    {
        randombytes_fill((std::byte*) buff, count);
    }
    inline void randombytes_fill(unsigned char * buff, std::size_t count)
    {
        randombytes_fill((std::byte*) buff, count);
    }

    std::uint32_t randombytes_uniform(std::uint32_t upper_bound);
}

#endif
