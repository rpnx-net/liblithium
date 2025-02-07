
#include <cstdint>

#include "utils.h"

#include "../stream_salsa20.h"
#include "salsa20_xmm6.h"

#ifdef HAVE_AMD64_ASM


extern int stream_salsa20_xmm6(unsigned char *c, unsigned long long clen,
                               const unsigned char *n, const unsigned char *k);

extern int stream_salsa20_xmm6_xor_ic(unsigned char *c, const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *n,
                                      uint64_t ic, const unsigned char *k);


struct rubidium_stream_salsa20_implementation
    rubidium_stream_salsa20_xmm6_implementation = {
        RUBIDIUM_C99(.stream =) stream_salsa20_xmm6,
        RUBIDIUM_C99(.stream_xor_ic =) stream_salsa20_xmm6_xor_ic,
    };

#endif
