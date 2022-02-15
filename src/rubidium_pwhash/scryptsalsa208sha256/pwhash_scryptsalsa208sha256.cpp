
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rubidium_pwhash_scryptsalsa208sha256.h"
#include "rubidium_scrypt.h"
#include "private/common.h"
#include "randombytes.h"
#include "utils.h"

#define SETTING_SIZE(saltbytes)                                              \
    ((sizeof "$7$" - 1U) + (1U /* N_log2 */) + (5U /* r */) + (5U /* p */) + \
     BYTES2CHARS(saltbytes))

static int
pickparams(unsigned long long opslimit, const size_t memlimit,
           uint32_t *const N_log2, uint32_t *const p, uint32_t *const r)
{
    unsigned long long maxN;
    unsigned long long maxrp;

    if (opslimit < 32768) {
        opslimit = 32768;
    }
    *r = 8;
    if (opslimit < memlimit / 32) {
        *p = 1;
        maxN = opslimit / (*r * 4);
        for (*N_log2 = 1; *N_log2 < 63; *N_log2 += 1) {
            if ((uint64_t)(1) << *N_log2 > maxN / 2) {
                break;
            }
        }
    } else {
        maxN = memlimit / ((size_t) *r * 128);
        for (*N_log2 = 1; *N_log2 < 63; *N_log2 += 1) {
            if ((uint64_t)(1) << *N_log2 > maxN / 2) {
                break;
            }
        }
        maxrp = (opslimit / 4) / ((uint64_t)(1) << *N_log2);
        /* LCOV_EXCL_START */
        if (maxrp > 0x3fffffff) {
            maxrp = 0x3fffffff;
        }
        /* LCOV_EXCL_STOP */
        *p = (uint32_t)(maxrp) / *r;
    }
    return 0;
}

static size_t
rubidium_strnlen(const char *str, size_t maxlen)
{
    size_t i = 0U;

    while (i < maxlen && str[i] != 0) {
        i++;
    }
    return i;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_bytes_min(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_BYTES_MIN;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_bytes_max(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_BYTES_MAX;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_passwd_min(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_PASSWD_MIN;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_passwd_max(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_PASSWD_MAX;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_saltbytes(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_SALTBYTES;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_strbytes(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_STRBYTES;
}

const char *
rubidium_pwhash_scryptsalsa208sha256_strprefix(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_STRPREFIX;
}

unsigned long long
rubidium_pwhash_scryptsalsa208sha256_opslimit_min(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN;
}

unsigned long long
rubidium_pwhash_scryptsalsa208sha256_opslimit_max(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_memlimit_min(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_memlimit_max(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX;
}

unsigned long long
rubidium_pwhash_scryptsalsa208sha256_opslimit_interactive(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_memlimit_interactive(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;
}

unsigned long long
rubidium_pwhash_scryptsalsa208sha256_opslimit_sensitive(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE;
}

size_t
rubidium_pwhash_scryptsalsa208sha256_memlimit_sensitive(void)
{
    return rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE;
}

int
rubidium_pwhash_scryptsalsa208sha256(unsigned char *const       out,
                                   unsigned long long         outlen,
                                   const char *const          passwd,
                                   unsigned long long         passwdlen,
                                   const unsigned char *const salt,
                                   unsigned long long opslimit, size_t memlimit)
{
    uint32_t N_log2;
    uint32_t p;
    uint32_t r;

    memset(out, 0, outlen);
    if (passwdlen > rubidium_pwhash_scryptsalsa208sha256_PASSWD_MAX ||
        outlen > rubidium_pwhash_scryptsalsa208sha256_BYTES_MAX) {
        errno = EFBIG; /* LCOV_EXCL_LINE */
        return -1;     /* LCOV_EXCL_LINE */
    }
    if (outlen < rubidium_pwhash_scryptsalsa208sha256_BYTES_MIN ||
        pickparams(opslimit, memlimit, &N_log2, &p, &r) != 0) {
        errno = EINVAL; /* LCOV_EXCL_LINE */
        return -1;      /* LCOV_EXCL_LINE */
    }
    if ((const void *) out == (const void *) passwd) {
        errno = EINVAL;
        return -1;
    }
    return rubidium_pwhash_scryptsalsa208sha256_ll(
        (const uint8_t *) passwd, (size_t) passwdlen, (const uint8_t *) salt,
        rubidium_pwhash_scryptsalsa208sha256_SALTBYTES, (uint64_t)(1) << N_log2,
        r, p, out, (size_t) outlen);
}

int
rubidium_pwhash_scryptsalsa208sha256_str(
    char              out[rubidium_pwhash_scryptsalsa208sha256_STRBYTES],
    const char *const passwd, unsigned long long passwdlen,
    unsigned long long opslimit, size_t memlimit)
{
    uint8_t salt[rubidium_pwhash_scryptsalsa208sha256_STRSALTBYTES];
    char    setting[rubidium_pwhash_scryptsalsa208sha256_STRSETTINGBYTES + 1U];
    escrypt_local_t escrypt_local;
    uint32_t        N_log2;
    uint32_t        p;
    uint32_t        r;

    memset(out, 0, rubidium_pwhash_scryptsalsa208sha256_STRBYTES);
    if (passwdlen > rubidium_pwhash_scryptsalsa208sha256_PASSWD_MAX) {
        errno = EFBIG; /* LCOV_EXCL_LINE */
        return -1;     /* LCOV_EXCL_LINE */
    }
    if (passwdlen < rubidium_pwhash_scryptsalsa208sha256_PASSWD_MIN ||
        pickparams(opslimit, memlimit, &N_log2, &p, &r) != 0) {
        errno = EINVAL; /* LCOV_EXCL_LINE */
        return -1;      /* LCOV_EXCL_LINE */
    }
    randombytes_buf(salt, sizeof salt);
    if (escrypt_gensalt_r(N_log2, r, p, salt, sizeof salt, (uint8_t *) setting,
                          sizeof setting) == NULL) {
        errno = EINVAL; /* LCOV_EXCL_LINE */
        return -1;      /* LCOV_EXCL_LINE */
    }
    if (escrypt_init_local(&escrypt_local) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    if (escrypt_r(&escrypt_local, (const uint8_t *) passwd, (size_t) passwdlen,
                  (const uint8_t *) setting, (uint8_t *) out,
                  rubidium_pwhash_scryptsalsa208sha256_STRBYTES) == NULL) {
        /* LCOV_EXCL_START */
        escrypt_free_local(&escrypt_local);
        errno = EINVAL;
        return -1;
        /* LCOV_EXCL_STOP */
    }
    escrypt_free_local(&escrypt_local);

    COMPILER_ASSERT(
        SETTING_SIZE(rubidium_pwhash_scryptsalsa208sha256_STRSALTBYTES) ==
        rubidium_pwhash_scryptsalsa208sha256_STRSETTINGBYTES);
    COMPILER_ASSERT(
        rubidium_pwhash_scryptsalsa208sha256_STRSETTINGBYTES + 1U +
            rubidium_pwhash_scryptsalsa208sha256_STRHASHBYTES_ENCODED + 1U ==
        rubidium_pwhash_scryptsalsa208sha256_STRBYTES);

    return 0;
}

int
rubidium_pwhash_scryptsalsa208sha256_str_verify(
    const char        *str,
    const char *const passwd, unsigned long long passwdlen)
{
    char            wanted[rubidium_pwhash_scryptsalsa208sha256_STRBYTES];
    escrypt_local_t escrypt_local;
    int             ret = -1;

    if (rubidium_strnlen(str, rubidium_pwhash_scryptsalsa208sha256_STRBYTES) !=
        rubidium_pwhash_scryptsalsa208sha256_STRBYTES - 1U) {
        return -1;
    }
    if (escrypt_init_local(&escrypt_local) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    memset(wanted, 0, sizeof wanted);
    if (escrypt_r(&escrypt_local, (const uint8_t *) passwd, (size_t) passwdlen,
                  (const uint8_t *) str, (uint8_t *) wanted,
                  sizeof wanted) == NULL) {
        escrypt_free_local(&escrypt_local);
        return -1;
    }
    escrypt_free_local(&escrypt_local);
    ret = rubidium_memcmp(wanted, str, sizeof wanted);
    rubidium_memzero(wanted, sizeof wanted);

    return ret;
}

int
rubidium_pwhash_scryptsalsa208sha256_str_needs_rehash(
    const char * str,
    unsigned long long opslimit, size_t memlimit)
{
    uint32_t N_log2, N_log2_;
    uint32_t p, p_;
    uint32_t r, r_;

    if (pickparams(opslimit, memlimit, &N_log2, &p, &r) != 0) {
        errno = EINVAL;
        return -1;
    }
    if (rubidium_strnlen(str, rubidium_pwhash_scryptsalsa208sha256_STRBYTES) !=
        rubidium_pwhash_scryptsalsa208sha256_STRBYTES - 1U) {
        errno = EINVAL;
        return -1;
    }
    if (escrypt_parse_setting((const uint8_t *) str,
                              &N_log2_, &r_, &p_) == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (N_log2 != N_log2_ || r != r_ || p != p_) {
        return 1;
    }
    return 0;
}
