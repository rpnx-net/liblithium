
#include "poly1305_donna.h"
#include "rubidium_verify_16.h"
#include "private/common.h"
#include "utils.h"

#ifdef HAVE_TI_MODE
#include "poly1305_donna64.h"
#else
#include "poly1305_donna32.h"
#endif
#include "../onetimeauth_poly1305.h"

static void
poly1305_update(poly1305_state_internal_t *st, const unsigned char *m,
                std::size_t bytes)
{
    std::size_t i;

    /* handle leftover */
    if (st->leftover) {
        std::size_t want = (poly1305_block_size - st->leftover);

        if (want > bytes) {
            want = bytes;
        }
        for (i = 0; i < want; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < poly1305_block_size) {
            return;
        }
        poly1305_blocks(st, st->buffer, poly1305_block_size);
        st->leftover = 0;
    }

    /* process full blocks */
    if (bytes >= poly1305_block_size) {
        std::size_t want = (bytes & ~(poly1305_block_size - 1));

        poly1305_blocks(st, m, want);
        m += want;
        bytes -= want;
    }

    /* store leftover */
    if (bytes) {
        for (i = 0; i < bytes; i++) {
            st->buffer[st->leftover + i] = m[i];
        }
        st->leftover += bytes;
    }
}

static int
rubidium_onetimeauth_poly1305_donna(unsigned char *out, const unsigned char *m,
                                  std::size_t   inlen,
                                  const unsigned char *key)
{
    RUBIDIUM_ALIGN(64) poly1305_state_internal_t state;

    poly1305_init(&state, key);
    poly1305_update(&state, m, inlen);
    poly1305_finish(&state, out);

    return 0;
}

static int
rubidium_onetimeauth_poly1305_donna_init(rubidium_onetimeauth_poly1305_state *state,
                                       const unsigned char *key)
{
    static_assert(sizeof(rubidium_onetimeauth_poly1305_state) >=
        sizeof(poly1305_state_internal_t));
    poly1305_init((poly1305_state_internal_t *) (void *) state, key);

    return 0;
}

static int
rubidium_onetimeauth_poly1305_donna_update(
    rubidium_onetimeauth_poly1305_state *state, const unsigned char *in,
    std::size_t inlen)
{
    poly1305_update((poly1305_state_internal_t *) (void *) state, in, inlen);

    return 0;
}

static int
rubidium_onetimeauth_poly1305_donna_final(
    rubidium_onetimeauth_poly1305_state *state, unsigned char *out)
{
    poly1305_finish((poly1305_state_internal_t *) (void *) state, out);

    return 0;
}

static int
rubidium_onetimeauth_poly1305_donna_verify(const unsigned char *h,
                                         const unsigned char *in,
                                         std::size_t   inlen,
                                         const unsigned char *k)
{
    unsigned char correct[16];

    rubidium_onetimeauth_poly1305_donna(correct, in, inlen, k);

    return rubidium_verify_16(h, correct);
}

rubidium_onetimeauth_poly1305_implementation
    rubidium_onetimeauth_poly1305_donna_implementation = {
    rubidium_onetimeauth_poly1305_donna,

    rubidium_onetimeauth_poly1305_donna_verify,
    rubidium_onetimeauth_poly1305_donna_init,

    rubidium_onetimeauth_poly1305_donna_update,
    rubidium_onetimeauth_poly1305_donna_final
    };
