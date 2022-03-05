#include "rubidium_stream_salsa208.h"
#include "randombytes.h"

size_t
rubidium_stream_salsa208_keybytes(void)
{
    return rubidium_stream_salsa208_KEYBYTES;
}

size_t
rubidium_stream_salsa208_noncebytes(void)
{
    return rubidium_stream_salsa208_NONCEBYTES;
}

size_t
rubidium_stream_salsa208_messagebytes_max(void)
{
    return rubidium_stream_salsa208_MESSAGEBYTES_MAX;
}

void
rubidium_stream_salsa208_keygen(unsigned char k[rubidium_stream_salsa208_KEYBYTES])
{
    rubidium::randombytes_fill(k, rubidium_stream_salsa208_KEYBYTES);
}
