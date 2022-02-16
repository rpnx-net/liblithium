#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdexcept>


#include "rubidium_aead_chacha20poly1305.h"
#include "rubidium_aead_xchacha20poly1305.h"
#include "rubidium_core_hchacha20.h"
#include "rubidium_onetimeauth_poly1305.h"
#include "rubidium_secretstream_xchacha20poly1305.h"
#include "randombytes.h"
#include "utils.h"

#include "private/common.h"

#define rubidium_secretstream_xchacha20poly1305_COUNTERBYTES  4U
#define rubidium_secretstream_xchacha20poly1305_INONCEBYTES   8U

#define STATE_COUNTER(STATE) ((STATE)->nonce)
#define STATE_INONCE(STATE)  ((STATE)->nonce + \
                              rubidium_secretstream_xchacha20poly1305_COUNTERBYTES)

static const unsigned char _pad0[16] = { 0 };

static inline void
_rubidium_secretstream_xchacha20poly1305_counter_reset
    (rubidium_secretstream_xchacha20poly1305_state *state)
{
    memset(STATE_COUNTER(state), 0,
           rubidium_secretstream_xchacha20poly1305_COUNTERBYTES);
    STATE_COUNTER(state)[0] = 1;
}

void
rubidium_secretstream_xchacha20poly1305_keygen
   (unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
{
    randombytes_buf(k, rubidium_secretstream_xchacha20poly1305_KEYBYTES);
}

int
rubidium_secretstream_xchacha20poly1305_init_push
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char out[rubidium_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
{
    static_assert(rubidium_secretstream_xchacha20poly1305_HEADERBYTES ==
                    rubidium_core_hchacha20_INPUTBYTES +
                    rubidium_secretstream_xchacha20poly1305_INONCEBYTES);
    static_assert(rubidium_secretstream_xchacha20poly1305_HEADERBYTES ==
                    rubidium_aead_xchacha20poly1305_ietf_NPUBBYTES);
    static_assert(sizeof state->nonce ==
                    rubidium_secretstream_xchacha20poly1305_INONCEBYTES +
                    rubidium_secretstream_xchacha20poly1305_COUNTERBYTES);

    randombytes_buf(out, rubidium_secretstream_xchacha20poly1305_HEADERBYTES);
    rubidium_core_hchacha20(state->k, out, k, NULL);
    _rubidium_secretstream_xchacha20poly1305_counter_reset(state);
    memcpy(STATE_INONCE(state), out + rubidium_core_hchacha20_INPUTBYTES,
           rubidium_secretstream_xchacha20poly1305_INONCEBYTES);
    memset(state->_pad, 0, sizeof state->_pad);

    return 0;
}

int
rubidium_secretstream_xchacha20poly1305_init_pull
   (rubidium_secretstream_xchacha20poly1305_state *state,
    const unsigned char in[rubidium_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
{
    rubidium_core_hchacha20(state->k, in, k, NULL);
    _rubidium_secretstream_xchacha20poly1305_counter_reset(state);
    memcpy(STATE_INONCE(state), in + rubidium_core_hchacha20_INPUTBYTES,
           rubidium_secretstream_xchacha20poly1305_INONCEBYTES);
    memset(state->_pad, 0, sizeof state->_pad);

    return 0;
}

void
rubidium_secretstream_xchacha20poly1305_rekey
    (rubidium_secretstream_xchacha20poly1305_state *state)
{
    unsigned char new_key_and_inonce[rubidium_stream_chacha20_ietf_KEYBYTES +
                                     rubidium_secretstream_xchacha20poly1305_INONCEBYTES];
    size_t        i;

    for (i = 0U; i < rubidium_stream_chacha20_ietf_KEYBYTES; i++) {
        new_key_and_inonce[i] = state->k[i];
    }
    for (i = 0U; i < rubidium_secretstream_xchacha20poly1305_INONCEBYTES; i++) {
        new_key_and_inonce[rubidium_stream_chacha20_ietf_KEYBYTES + i] =
            STATE_INONCE(state)[i];
    }
    rubidium_stream_chacha20_ietf_xor(new_key_and_inonce, new_key_and_inonce,
                                    sizeof new_key_and_inonce,
                                    state->nonce, state->k);
    for (i = 0U; i < rubidium_stream_chacha20_ietf_KEYBYTES; i++) {
        state->k[i] = new_key_and_inonce[i];
    }
    for (i = 0U; i < rubidium_secretstream_xchacha20poly1305_INONCEBYTES; i++) {
        STATE_INONCE(state)[i] =
            new_key_and_inonce[rubidium_stream_chacha20_ietf_KEYBYTES + i];
    }
    _rubidium_secretstream_xchacha20poly1305_counter_reset(state);
}

int
rubidium_secretstream_xchacha20poly1305_push
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char *out, unsigned long long *outlen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen, unsigned char tag)
{
    rubidium_onetimeauth_poly1305_state poly1305_state;
    unsigned char                     block[64U];
    unsigned char                     slen[8U];
    unsigned char                    *c;
    unsigned char                    *mac;

    if (outlen_p != NULL) {
        *outlen_p = 0U;
    }
    static_assert(rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX
                    <= rubidium_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX);
    if (mlen > rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("mlen > rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX");
    }
    rubidium_stream_chacha20_ietf(block, sizeof block, state->nonce, state->k);
    rubidium_onetimeauth_poly1305_init(&poly1305_state, block);
    rubidium_memzero(block, sizeof block);

    rubidium_onetimeauth_poly1305_update(&poly1305_state, ad, adlen);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, _pad0,
                                       (0x10 - adlen) & 0xf);
    memset(block, 0, sizeof block);
    block[0] = tag;

    rubidium_stream_chacha20_ietf_xor_ic(block, block, sizeof block,
                                       state->nonce, 1U, state->k);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, block, sizeof block);
    out[0] = block[0];

    c = out + (sizeof tag);
    rubidium_stream_chacha20_ietf_xor_ic(c, m, mlen, state->nonce, 2U, state->k);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, c, mlen);
    rubidium_onetimeauth_poly1305_update
        (&poly1305_state, _pad0, (0x10 - (sizeof block) + mlen) & 0xf);
    /* should have been (0x10 - (sizeof block + mlen)) & 0xf to keep input blocks aligned */

    STORE64_LE(slen, (uint64_t) adlen);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);
    STORE64_LE(slen, (sizeof block) + mlen);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);

    mac = c + mlen;
    rubidium_onetimeauth_poly1305_final(&poly1305_state, mac);
    rubidium_memzero(&poly1305_state, sizeof poly1305_state);

    static_assert(rubidium_onetimeauth_poly1305_BYTES >=
                    rubidium_secretstream_xchacha20poly1305_INONCEBYTES);
    XOR_BUF(STATE_INONCE(state), mac,
            rubidium_secretstream_xchacha20poly1305_INONCEBYTES);
    rubidium_increment(STATE_COUNTER(state),
                     rubidium_secretstream_xchacha20poly1305_COUNTERBYTES);
    if ((tag & rubidium_secretstream_xchacha20poly1305_TAG_REKEY) != 0 ||
        rubidium_is_zero(STATE_COUNTER(state),
                       rubidium_secretstream_xchacha20poly1305_COUNTERBYTES)) {
        rubidium_secretstream_xchacha20poly1305_rekey(state);
    }
    if (outlen_p != NULL) {
        *outlen_p = rubidium_secretstream_xchacha20poly1305_ABYTES + mlen;
    }
    return 0;
}

int
rubidium_secretstream_xchacha20poly1305_pull
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char *m, unsigned long long *mlen_p, unsigned char *tag_p,
    const unsigned char *in, unsigned long long inlen,
    const unsigned char *ad, unsigned long long adlen)
{
    rubidium_onetimeauth_poly1305_state poly1305_state;
    unsigned char                     block[64U];
    unsigned char                     slen[8U];
    unsigned char                     mac[rubidium_onetimeauth_poly1305_BYTES];
    const unsigned char              *c;
    const unsigned char              *stored_mac;
    unsigned long long                mlen;
    unsigned char                     tag;

    if (mlen_p != NULL) {
        *mlen_p = 0U;
    }
    if (tag_p != NULL) {
        *tag_p = 0xff;
    }
    if (inlen < rubidium_secretstream_xchacha20poly1305_ABYTES) {
        return -1;
    }
    mlen = inlen - rubidium_secretstream_xchacha20poly1305_ABYTES;
    if (mlen > rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX) {
        throw std::invalid_argument("");
    }
    rubidium_stream_chacha20_ietf(block, sizeof block, state->nonce, state->k);
    rubidium_onetimeauth_poly1305_init(&poly1305_state, block);
    rubidium_memzero(block, sizeof block);

    rubidium_onetimeauth_poly1305_update(&poly1305_state, ad, adlen);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, _pad0,
                                       (0x10 - adlen) & 0xf);

    memset(block, 0, sizeof block);
    block[0] = in[0];
    rubidium_stream_chacha20_ietf_xor_ic(block, block, sizeof block,
                                       state->nonce, 1U, state->k);
    tag = block[0];
    block[0] = in[0];
    rubidium_onetimeauth_poly1305_update(&poly1305_state, block, sizeof block);

    c = in + (sizeof tag);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, c, mlen);
    rubidium_onetimeauth_poly1305_update
        (&poly1305_state, _pad0, (0x10 - (sizeof block) + mlen) & 0xf);
    /* should have been (0x10 - (sizeof block + mlen)) & 0xf to keep input blocks aligned */

    STORE64_LE(slen, (uint64_t) adlen);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);
    STORE64_LE(slen, (sizeof block) + mlen);
    rubidium_onetimeauth_poly1305_update(&poly1305_state, slen, sizeof slen);

    rubidium_onetimeauth_poly1305_final(&poly1305_state, mac);
    rubidium_memzero(&poly1305_state, sizeof poly1305_state);

    stored_mac = c + mlen;
    if (rubidium_memcmp(mac, stored_mac, sizeof mac) != 0) {
        rubidium_memzero(mac, sizeof mac);
        return -1;
    }

    rubidium_stream_chacha20_ietf_xor_ic(m, c, mlen, state->nonce, 2U, state->k);
    XOR_BUF(STATE_INONCE(state), mac,
            rubidium_secretstream_xchacha20poly1305_INONCEBYTES);
    rubidium_increment(STATE_COUNTER(state),
                     rubidium_secretstream_xchacha20poly1305_COUNTERBYTES);
    if ((tag & rubidium_secretstream_xchacha20poly1305_TAG_REKEY) != 0 ||
        rubidium_is_zero(STATE_COUNTER(state),
                       rubidium_secretstream_xchacha20poly1305_COUNTERBYTES)) {
        rubidium_secretstream_xchacha20poly1305_rekey(state);
    }
    if (mlen_p != NULL) {
        *mlen_p = mlen;
    }
    if (tag_p != NULL) {
        *tag_p = tag;
    }
    return 0;
}

size_t
rubidium_secretstream_xchacha20poly1305_statebytes(void)
{
    return sizeof(rubidium_secretstream_xchacha20poly1305_state);
}

size_t
rubidium_secretstream_xchacha20poly1305_abytes(void)
{
    return rubidium_secretstream_xchacha20poly1305_ABYTES;
}

size_t
rubidium_secretstream_xchacha20poly1305_headerbytes(void)
{
    return rubidium_secretstream_xchacha20poly1305_HEADERBYTES;
}

size_t
rubidium_secretstream_xchacha20poly1305_keybytes(void)
{
    return rubidium_secretstream_xchacha20poly1305_KEYBYTES;
}

size_t
rubidium_secretstream_xchacha20poly1305_messagebytes_max(void)
{
    return rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX;
}

unsigned char
rubidium_secretstream_xchacha20poly1305_tag_message(void)
{
    return rubidium_secretstream_xchacha20poly1305_TAG_MESSAGE;
}

unsigned char
rubidium_secretstream_xchacha20poly1305_tag_push(void)
{
    return rubidium_secretstream_xchacha20poly1305_TAG_PUSH;
}

unsigned char
rubidium_secretstream_xchacha20poly1305_tag_rekey(void)
{
    return rubidium_secretstream_xchacha20poly1305_TAG_REKEY;
}

unsigned char
rubidium_secretstream_xchacha20poly1305_tag_final(void)
{
    return rubidium_secretstream_xchacha20poly1305_TAG_FINAL;
}
