
#include "randombytes.h"

#include <random>

uint32_t
randombytes_uniform(const uint32_t upper_bound)
{
    thread_local std::random_device r;
    std::uniform_int_distribution<uint32_t> dist(0, upper_bound-1);
    return dist(r);
}

void
randombytes_buf(void * buf, const size_t size)
{
    thread_local std::random_device r;
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (std::size_t i = 0; i != size; i++) {
        ((std::byte *)buf)[i] = std::byte(dist(r));
    }
}




void
randombytes(unsigned char * const buf, const std::size_t buf_len)
{
    randombytes_buf(buf, (size_t) buf_len);
}
