#include <errno.h>
#include <string.h>

#include "rubidium_auth_hmacsha512.h"
#include "rubidium_kdf.h"
#include "rubidium_kdf_hkdf_sha512.h"
#include "randombytes.h"
#include "utils.h"

int
rubidium_kdf_hkdf_sha512_extract(
    unsigned char prk[rubidium_kdf_hkdf_sha512_KEYBYTES],
    const unsigned char *salt, size_t salt_len, const unsigned char *ikm,
    size_t ikm_len)
{
    rubidium_auth_hmacsha512_state st;

    rubidium_auth_hmacsha512_init(&st, salt, salt_len);
    rubidium_auth_hmacsha512_update(&st, ikm, ikm_len);
    rubidium_auth_hmacsha512_final(&st, prk);
    rubidium_memzero(&st, sizeof st);

    return 0;
}

void
rubidium_kdf_hkdf_sha512_keygen(unsigned char prk[rubidium_kdf_hkdf_sha512_KEYBYTES])
{
    rubidium::randombytes_fill(prk, rubidium_kdf_hkdf_sha512_KEYBYTES);
}

int
rubidium_kdf_hkdf_sha512_expand(unsigned char *out, size_t out_len,
                              const char *ctx, size_t ctx_len,
                              const unsigned char prk[rubidium_kdf_hkdf_sha512_KEYBYTES])
{
    rubidium_auth_hmacsha512_state st;
    unsigned char                tmp[rubidium_auth_hmacsha512_BYTES];
    size_t                       i;
    size_t                       left;
    unsigned char                counter = 1U;

    if (out_len > rubidium_kdf_hkdf_sha512_BYTES_MAX) {
        errno = EINVAL;
        return -1;
    }
    for (i = (size_t) 0U; i + rubidium_auth_hmacsha512_BYTES <= out_len;
         i += rubidium_auth_hmacsha512_BYTES) {
        rubidium_auth_hmacsha512_init(&st, prk, rubidium_kdf_hkdf_sha512_KEYBYTES);
        if (i != (size_t) 0U) {
            rubidium_auth_hmacsha512_update(&st,
                                          &out[i - rubidium_auth_hmacsha512_BYTES],
                                          rubidium_auth_hmacsha512_BYTES);
        }
        rubidium_auth_hmacsha512_update(&st,
                                      (const unsigned char *) ctx, ctx_len);
        rubidium_auth_hmacsha512_update(&st, &counter, (size_t) 1U);
        rubidium_auth_hmacsha512_final(&st, &out[i]);
        counter++;
    }
    if ((left = out_len & (rubidium_auth_hmacsha512_BYTES - 1U)) != (size_t) 0U) {
        rubidium_auth_hmacsha512_init(&st, prk, rubidium_kdf_hkdf_sha512_KEYBYTES);
        if (i != (size_t) 0U) {
            rubidium_auth_hmacsha512_update(&st,
                                          &out[i - rubidium_auth_hmacsha512_BYTES],
                                          rubidium_auth_hmacsha512_BYTES);
        }
        rubidium_auth_hmacsha512_update(&st,
                                      (const unsigned char *) ctx, ctx_len);
        rubidium_auth_hmacsha512_update(&st, &counter, (size_t) 1U);
        rubidium_auth_hmacsha512_final(&st, tmp);
        memcpy(&out[i], tmp, left);
        rubidium_memzero(tmp, sizeof tmp);
    }
    rubidium_memzero(&st, sizeof st);

    return 0;
}

size_t
rubidium_kdf_hkdf_sha512_keybytes(void)
{
    return rubidium_kdf_hkdf_sha512_KEYBYTES;
}

size_t
rubidium_kdf_hkdf_sha512_bytes_min(void)
{
    return rubidium_kdf_hkdf_sha512_BYTES_MIN;
}

size_t
rubidium_kdf_hkdf_sha512_bytes_max(void)
{
    return rubidium_kdf_hkdf_sha512_BYTES_MAX;
}
