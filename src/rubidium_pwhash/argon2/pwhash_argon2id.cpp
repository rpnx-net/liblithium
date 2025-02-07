
#include <errno.h>
#include <limits.h>
#include <cstddef>
#include <cstdint>
#include <string.h>

#include "argon2-core.h"
#include "argon2.h"
#include "rubidium_pwhash_argon2id.h"
#include "private/common.h"
#include "randombytes.h"
#include "utils.h"

#define STR_HASHBYTES 32U

int
rubidium_pwhash_argon2id_alg_argon2id13(void)
{
    return rubidium_pwhash_argon2id_ALG_ARGON2ID13;
}

size_t
rubidium_pwhash_argon2id_bytes_min(void)
{
    static_assert(rubidium_pwhash_argon2id_BYTES_MIN >= ARGON2_MIN_OUTLEN);
    return rubidium_pwhash_argon2id_BYTES_MIN;
}

size_t
rubidium_pwhash_argon2id_bytes_max(void)
{
    static_assert(rubidium_pwhash_argon2id_BYTES_MAX <= ARGON2_MAX_OUTLEN);
    return rubidium_pwhash_argon2id_BYTES_MAX;
}

size_t
rubidium_pwhash_argon2id_passwd_min(void)
{
    static_assert(rubidium_pwhash_argon2id_PASSWD_MIN >= ARGON2_MIN_PWD_LENGTH);
    return rubidium_pwhash_argon2id_PASSWD_MIN;
}

size_t
rubidium_pwhash_argon2id_passwd_max(void)
{
    static_assert(rubidium_pwhash_argon2id_PASSWD_MAX <= ARGON2_MAX_PWD_LENGTH);
    return rubidium_pwhash_argon2id_PASSWD_MAX;
}

size_t
rubidium_pwhash_argon2id_saltbytes(void)
{
    static_assert(rubidium_pwhash_argon2id_SALTBYTES >= ARGON2_MIN_SALT_LENGTH);
    static_assert(rubidium_pwhash_argon2id_SALTBYTES <= ARGON2_MAX_SALT_LENGTH);
    return rubidium_pwhash_argon2id_SALTBYTES;
}

size_t
rubidium_pwhash_argon2id_strbytes(void)
{
    return rubidium_pwhash_argon2id_STRBYTES;
}

const char*
rubidium_pwhash_argon2id_strprefix(void)
{
    return rubidium_pwhash_argon2id_STRPREFIX;
}

std::size_t
rubidium_pwhash_argon2id_opslimit_min(void)
{
    static_assert(rubidium_pwhash_argon2id_OPSLIMIT_MIN >= ARGON2_MIN_TIME);
    return rubidium_pwhash_argon2id_OPSLIMIT_MIN;
}

std::size_t
rubidium_pwhash_argon2id_opslimit_max(void)
{
    static_assert(rubidium_pwhash_argon2id_OPSLIMIT_MAX <= ARGON2_MAX_TIME);
    return rubidium_pwhash_argon2id_OPSLIMIT_MAX;
}

size_t
rubidium_pwhash_argon2id_memlimit_min(void)
{
    static_assert((rubidium_pwhash_argon2id_MEMLIMIT_MIN / 1024U) >= ARGON2_MIN_MEMORY);
    return rubidium_pwhash_argon2id_MEMLIMIT_MIN;
}

size_t
rubidium_pwhash_argon2id_memlimit_max(void)
{
    static_assert((rubidium_pwhash_argon2id_MEMLIMIT_MAX / 1024U) <= ARGON2_MAX_MEMORY);
    return rubidium_pwhash_argon2id_MEMLIMIT_MAX;
}

std::size_t
rubidium_pwhash_argon2id_opslimit_interactive(void)
{
    return rubidium_pwhash_argon2id_OPSLIMIT_INTERACTIVE;
}

size_t
rubidium_pwhash_argon2id_memlimit_interactive(void)
{
    return rubidium_pwhash_argon2id_MEMLIMIT_INTERACTIVE;
}

std::size_t
rubidium_pwhash_argon2id_opslimit_moderate(void)
{
    return rubidium_pwhash_argon2id_OPSLIMIT_MODERATE;
}

size_t
rubidium_pwhash_argon2id_memlimit_moderate(void)
{
    return rubidium_pwhash_argon2id_MEMLIMIT_MODERATE;
}

std::size_t
rubidium_pwhash_argon2id_opslimit_sensitive(void)
{
    return rubidium_pwhash_argon2id_OPSLIMIT_SENSITIVE;
}

size_t
rubidium_pwhash_argon2id_memlimit_sensitive(void)
{
    return rubidium_pwhash_argon2id_MEMLIMIT_SENSITIVE;
}

int
rubidium_pwhash_argon2id(unsigned char *const out, std::size_t outlen,
                       const char *const passwd, std::size_t passwdlen,
                       const unsigned char *const salt,
                       std::size_t opslimit, size_t memlimit, int alg)
{
    memset(out, 0, outlen);
    if (outlen > rubidium_pwhash_argon2id_BYTES_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (outlen < rubidium_pwhash_argon2id_BYTES_MIN) {
        errno = EINVAL;
        return -1;
    }
    if (passwdlen > rubidium_pwhash_argon2id_PASSWD_MAX ||
        opslimit > rubidium_pwhash_argon2id_OPSLIMIT_MAX ||
        memlimit > rubidium_pwhash_argon2id_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (passwdlen < rubidium_pwhash_argon2id_PASSWD_MIN ||
        opslimit < rubidium_pwhash_argon2id_OPSLIMIT_MIN ||
        memlimit < rubidium_pwhash_argon2id_MEMLIMIT_MIN) {
        errno = EINVAL;
        return -1;
    }
    if ((const void *) out == (const void *) passwd) {
        errno = EINVAL;
        return -1;
    }
    switch (alg) {
    case rubidium_pwhash_argon2id_ALG_ARGON2ID13:
        if (_rubidium_argon2id_hash_raw((uint32_t) opslimit, (uint32_t) (memlimit / 1024U),
                              (uint32_t) 1U, passwd, (size_t) passwdlen, salt,
                              (size_t) rubidium_pwhash_argon2id_SALTBYTES, out,
                              (size_t) outlen) != ARGON2_OK) {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

int
rubidium_pwhash_argon2id_str(char out[rubidium_pwhash_argon2id_STRBYTES],
                           const char *const passwd,
                           std::size_t passwdlen,
                           std::size_t opslimit, size_t memlimit)
{
    unsigned char salt[rubidium_pwhash_argon2id_SALTBYTES];

    memset(out, 0, rubidium_pwhash_argon2id_STRBYTES);
    if (passwdlen > rubidium_pwhash_argon2id_PASSWD_MAX ||
        opslimit > rubidium_pwhash_argon2id_OPSLIMIT_MAX ||
        memlimit > rubidium_pwhash_argon2id_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if (passwdlen < rubidium_pwhash_argon2id_PASSWD_MIN ||
        opslimit < rubidium_pwhash_argon2id_OPSLIMIT_MIN ||
        memlimit < rubidium_pwhash_argon2id_MEMLIMIT_MIN) {
        errno = EINVAL;
        return -1;
    }
    rubidium::randombytes_fill(salt, sizeof salt);
    if (_rubidium_argon2id_hash_encoded((uint32_t) opslimit, (uint32_t) (memlimit / 1024U),
                              (uint32_t) 1U, passwd, (size_t) passwdlen, salt,
                              sizeof salt, STR_HASHBYTES, out,
                              rubidium_pwhash_argon2id_STRBYTES) != ARGON2_OK) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}

int
rubidium_pwhash_argon2id_str_verify(const char * str,
                                  const char * const passwd,
                                  std::size_t passwdlen)
{
    int verify_ret;

    if (passwdlen > rubidium_pwhash_argon2id_PASSWD_MAX) {
        errno = EFBIG;
        return -1;
    }
    /* LCOV_EXCL_START */
    if (passwdlen < rubidium_pwhash_argon2id_PASSWD_MIN) {
        errno = EINVAL;
        return -1;
    }
    /* LCOV_EXCL_STOP */

    verify_ret = _rubidium_argon2id_verify(str, passwd, (size_t) passwdlen);
    if (verify_ret == ARGON2_OK) {
        return 0;
    }
    if (verify_ret == ARGON2_VERIFY_MISMATCH) {
        errno = EINVAL;
    }
    return -1;
}
