#include "rubidium_stream_chacha20.h"

#include "private/chacha20_ietf_ext.h"
#include "private/common.h"
#include "private/implementations.h"
#include "randombytes.h"
#include "runtime.h"
#include "stream_chacha20.h"

#include "ref/chacha20_ref.h"
#if defined(HAVE_AVX2INTRIN_H) && defined(HAVE_EMMINTRIN_H) && \
    defined(HAVE_TMMINTRIN_H) && defined(HAVE_SMMINTRIN_H)
# include "dolbeau/chacha20_dolbeau-avx2.h"
#endif
#if defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
# include "dolbeau/chacha20_dolbeau-ssse3.h"
#endif
#include <stdexcept>

static const rubidium_stream_chacha20_implementation *implementation =
    &rubidium_stream_chacha20_ref_implementation;

size_t
rubidium_stream_chacha20_keybytes(void) {
    return RUBIDIUM_STREAM_CHACHA20_KEYBYTES;
}

size_t
rubidium_stream_chacha20_noncebytes(void) {
    return rubidium_stream_chacha20_NONCEBYTES;
}

size_t
rubidium_stream_chacha20_messagebytes_max(void)
{
    return rubidium_stream_chacha20_MESSAGEBYTES_MAX;
}

size_t
rubidium_stream_chacha20_ietf_keybytes(void) {
    return rubidium_stream_chacha20_ietf_KEYBYTES;
}

size_t
rubidium_stream_chacha20_ietf_noncebytes(void) {
    return rubidium_stream_chacha20_ietf_NONCEBYTES;
}

size_t
rubidium_stream_chacha20_ietf_messagebytes_max(void)
{
    return rubidium_stream_chacha20_ietf_MESSAGEBYTES_MAX;
}

int
rubidium_stream_chacha20(unsigned char *c, std::size_t clen,
                       const unsigned char *n, const unsigned char *k)
{
    if (clen > rubidium_stream_chacha20_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("clen > rubidium_stream_chacha20_MESSAGEBYTES_MAX");
    }
    return implementation->stream(c, clen, n, k);
}

int
rubidium_stream_chacha20_xor_ic(unsigned char *c, const unsigned char *m,
                              std::size_t mlen,
                              const unsigned char *n, uint64_t ic,
                              const unsigned char *k)
{
    if (mlen > rubidium_stream_chacha20_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return implementation->stream_xor_ic(c, m, mlen, n, ic, k);
}

int
rubidium_stream_chacha20_xor(unsigned char *c, const unsigned char *m,
                           std::size_t mlen, const unsigned char *n,
                           const unsigned char *k)
{
    if (mlen > rubidium_stream_chacha20_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return implementation->stream_xor_ic(c, m, mlen, n, 0U, k);
}

int
rubidium_stream_chacha20_ietf_ext(unsigned char *c, std::size_t clen,
                                const unsigned char *n, const unsigned char *k)
{
    if (clen > rubidium_stream_chacha20_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return implementation->stream_ietf_ext(c, clen, n, k);
}

int
rubidium_stream_chacha20_ietf_ext_xor_ic(unsigned char *c, const unsigned char *m,
                                       std::size_t mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k)
{
    if (mlen > rubidium_stream_chacha20_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return implementation->stream_ietf_ext_xor_ic(c, m, mlen, n, ic, k);
}

static int
rubidium_stream_chacha20_ietf_ext_xor(unsigned char *c, const unsigned char *m,
                                    std::size_t mlen, const unsigned char *n,
                                    const unsigned char *k)
{
    if (mlen > rubidium_stream_chacha20_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return implementation->stream_ietf_ext_xor_ic(c, m, mlen, n, 0U, k);
}

int
rubidium_stream_chacha20_ietf(unsigned char *c, std::size_t clen,
                            const unsigned char *n, const unsigned char *k)
{
    if (clen > rubidium_stream_chacha20_ietf_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return rubidium_stream_chacha20_ietf_ext(c, clen, n, k);
}

int
rubidium_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                   std::size_t mlen,
                                   const unsigned char *n, uint32_t ic,
                                   const unsigned char *k)
{
    if ((std::size_t) ic >
        (64ULL * (1ULL << 32)) / 64ULL - (mlen + 63ULL) / 64ULL) {
        throw std::invalid_argument("");
    }
    return rubidium_stream_chacha20_ietf_ext_xor_ic(c, m, mlen, n, ic, k);
}

int
rubidium_stream_chacha20_ietf_xor(unsigned char *c, const unsigned char *m,
                                std::size_t mlen, const unsigned char *n,
                                const unsigned char *k)
{
    if (mlen > rubidium_stream_chacha20_ietf_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    return rubidium_stream_chacha20_ietf_ext_xor(c, m, mlen, n, k);
}

void
rubidium_stream_chacha20_ietf_keygen(unsigned char k[rubidium_stream_chacha20_ietf_KEYBYTES])
{
    rubidium::randombytes_fill(k, rubidium_stream_chacha20_ietf_KEYBYTES);
}

void
rubidium_stream_chacha20_keygen(unsigned char k[RUBIDIUM_STREAM_CHACHA20_KEYBYTES])
{
    rubidium::randombytes_fill(k, RUBIDIUM_STREAM_CHACHA20_KEYBYTES);
}

int
_rubidium_stream_chacha20_pick_best_implementation(void)
{
    implementation = &rubidium_stream_chacha20_ref_implementation;
#if defined(HAVE_AVX2INTRIN_H) && defined(HAVE_EMMINTRIN_H) && \
    defined(HAVE_TMMINTRIN_H) && defined(HAVE_SMMINTRIN_H)
    if (rubidium_runtime_has_avx2()) {
        implementation = &rubidium_stream_chacha20_dolbeau_avx2_implementation;
        return 0;
    }
#endif
#if defined(HAVE_EMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
    if (rubidium_runtime_has_ssse3()) {
        implementation = &rubidium_stream_chacha20_dolbeau_ssse3_implementation;
        return 0;
    }
#endif
    return 0;
}
