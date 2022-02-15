#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "rubidium_generichash_blake2b.h"
#include "private/common.h"
#include "utils.h"

#include "blake2b-long.h"

int
_rubidium_blake2b_long(void *pout, size_t outlen, const void *in, size_t inlen)
{
    uint8_t *out = (uint8_t *) pout;
    rubidium_generichash_blake2b_state blake_state;
    uint8_t outlen_bytes[4 /* sizeof(uint32_t) */] = { 0 };
    int     ret = -1;

    if (outlen > UINT32_MAX) {
        goto fail; /* LCOV_EXCL_LINE */
    }

    /* Ensure little-endian byte order! */
    STORE32_LE(outlen_bytes, (uint32_t) outlen);

#define TRY(statement)   \
    do {                 \
        ret = statement; \
        if (ret < 0) {   \
            goto fail;   \
        }                \
    } while ((void) 0, 0)

    if (outlen <= rubidium_generichash_blake2b_BYTES_MAX) {
        TRY(rubidium_generichash_blake2b_init(&blake_state, NULL, 0U, outlen));
        TRY(rubidium_generichash_blake2b_update(&blake_state, outlen_bytes,
                                              sizeof(outlen_bytes)));
        TRY(rubidium_generichash_blake2b_update(
            &blake_state, (const unsigned char *) in, inlen));
        TRY(rubidium_generichash_blake2b_final(&blake_state, out, outlen));
    } else {
        uint32_t toproduce;
        uint8_t  out_buffer[rubidium_generichash_blake2b_BYTES_MAX];
        uint8_t  in_buffer[rubidium_generichash_blake2b_BYTES_MAX];
        TRY(rubidium_generichash_blake2b_init(
            &blake_state, NULL, 0U, rubidium_generichash_blake2b_BYTES_MAX));
        TRY(rubidium_generichash_blake2b_update(&blake_state, outlen_bytes,
                                              sizeof(outlen_bytes)));
        TRY(rubidium_generichash_blake2b_update(
            &blake_state, (const unsigned char *) in, inlen));
        TRY(rubidium_generichash_blake2b_final(
            &blake_state, out_buffer, rubidium_generichash_blake2b_BYTES_MAX));
        memcpy(out, out_buffer, rubidium_generichash_blake2b_BYTES_MAX / 2);
        out += rubidium_generichash_blake2b_BYTES_MAX / 2;
        toproduce =
            (uint32_t) outlen - rubidium_generichash_blake2b_BYTES_MAX / 2;

        while (toproduce > rubidium_generichash_blake2b_BYTES_MAX) {
            memcpy(in_buffer, out_buffer, rubidium_generichash_blake2b_BYTES_MAX);
            TRY(rubidium_generichash_blake2b(
                out_buffer, rubidium_generichash_blake2b_BYTES_MAX, in_buffer,
                rubidium_generichash_blake2b_BYTES_MAX, NULL, 0U));
            memcpy(out, out_buffer, rubidium_generichash_blake2b_BYTES_MAX / 2);
            out += rubidium_generichash_blake2b_BYTES_MAX / 2;
            toproduce -= rubidium_generichash_blake2b_BYTES_MAX / 2;
        }

        memcpy(in_buffer, out_buffer, rubidium_generichash_blake2b_BYTES_MAX);
        TRY(rubidium_generichash_blake2b(out_buffer, toproduce, in_buffer,
                                       rubidium_generichash_blake2b_BYTES_MAX,
                                       NULL, 0U));
        memcpy(out, out_buffer, toproduce);
    }
fail:
    rubidium_memzero(&blake_state, sizeof(blake_state));
    return ret;
#undef TRY
}
