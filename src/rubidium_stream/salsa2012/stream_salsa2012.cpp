#include "rubidium_stream_salsa2012.h"
#include "randombytes.h"

size_t
rubidium_stream_salsa2012_keybytes(void)
{
    return rubidium_stream_salsa2012_KEYBYTES;
}

size_t
rubidium_stream_salsa2012_noncebytes(void)
{
    return rubidium_stream_salsa2012_NONCEBYTES;
}

size_t
rubidium_stream_salsa2012_messagebytes_max(void)
{
    return rubidium_stream_salsa2012_MESSAGEBYTES_MAX;
}

void
rubidium_stream_salsa2012_keygen(unsigned char k[rubidium_stream_salsa2012_KEYBYTES])
{
    rubidium::randombytes_fill(reinterpret_cast<std::byte*>(k), rubidium_stream_salsa2012_KEYBYTES);
}
