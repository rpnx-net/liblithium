
#include "rubidium_scalarmult_curve25519.h"
#include "private/implementations.h"
#include "scalarmult_curve25519.h"
#include "runtime.h"

#ifdef HAVE_AVX_ASM
# include "sandy2x/curve25519_sandy2x.h"
#endif
#include "ref10/x25519_ref10.h"
static const rubidium_scalarmult_curve25519_implementation *implementation =
    &rubidium_scalarmult_curve25519_ref10_implementation;

int
rubidium_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    size_t                 i;
    volatile unsigned char d = 0;

    if (implementation->mult(q, n, p) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    for (i = 0; i < rubidium_scalarmult_curve25519_BYTES; i++) {
        d |= q[i];
    }
    return -(1 & ((d - 1) >> 8));
}

int
rubidium_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    return rubidium_scalarmult_curve25519_ref10_implementation
        .mult_base(q, n);
}

size_t
rubidium_scalarmult_curve25519_bytes(void)
{
    return rubidium_scalarmult_curve25519_BYTES;
}

size_t
rubidium_scalarmult_curve25519_scalarbytes(void)
{
    return rubidium_scalarmult_curve25519_SCALARBYTES;
}

int
_rubidium_scalarmult_curve25519_pick_best_implementation(void)
{
    implementation = &rubidium_scalarmult_curve25519_ref10_implementation;

#ifdef HAVE_AVX_ASM
    if (rubidium_runtime_has_avx()) {
        implementation = &rubidium_scalarmult_curve25519_sandy2x_implementation;
    }
#endif
    return 0;
}
