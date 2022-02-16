#ifndef rubidium_pwhash_argon2id_H
#define rubidium_pwhash_argon2id_H

#include <limits.h>
#include <cstddef>
#include <cstdint>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_pwhash_argon2id_ALG_ARGON2ID13 2

int rubidium_pwhash_argon2id_alg_argon2id13(void);

#define rubidium_pwhash_argon2id_BYTES_MIN 16U

size_t rubidium_pwhash_argon2id_bytes_min(void);

#define rubidium_pwhash_argon2id_BYTES_MAX RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX, 4294967295U)

size_t rubidium_pwhash_argon2id_bytes_max(void);

#define rubidium_pwhash_argon2id_PASSWD_MIN 0U

size_t rubidium_pwhash_argon2id_passwd_min(void);

#define rubidium_pwhash_argon2id_PASSWD_MAX 4294967295U

size_t rubidium_pwhash_argon2id_passwd_max(void);

#define rubidium_pwhash_argon2id_SALTBYTES 16U

size_t rubidium_pwhash_argon2id_saltbytes(void);

#define rubidium_pwhash_argon2id_STRBYTES 128U

size_t rubidium_pwhash_argon2id_strbytes(void);

#define rubidium_pwhash_argon2id_STRPREFIX "$argon2id$"

const char *rubidium_pwhash_argon2id_strprefix(void);

#define rubidium_pwhash_argon2id_OPSLIMIT_MIN 1U

std::size_t rubidium_pwhash_argon2id_opslimit_min(void);

#define rubidium_pwhash_argon2id_OPSLIMIT_MAX 4294967295U

std::size_t rubidium_pwhash_argon2id_opslimit_max(void);

#define rubidium_pwhash_argon2id_MEMLIMIT_MIN 8192U

size_t rubidium_pwhash_argon2id_memlimit_min(void);

#define rubidium_pwhash_argon2id_MEMLIMIT_MAX \
    ((SIZE_MAX >= 4398046510080U) ? 4398046510080U : (SIZE_MAX >= 2147483648U) ? 2147483648U : 32768U)

size_t rubidium_pwhash_argon2id_memlimit_max(void);

#define rubidium_pwhash_argon2id_OPSLIMIT_INTERACTIVE 2U

std::size_t rubidium_pwhash_argon2id_opslimit_interactive(void);

#define rubidium_pwhash_argon2id_MEMLIMIT_INTERACTIVE 67108864U

size_t rubidium_pwhash_argon2id_memlimit_interactive(void);

#define rubidium_pwhash_argon2id_OPSLIMIT_MODERATE 3U

std::size_t rubidium_pwhash_argon2id_opslimit_moderate(void);

#define rubidium_pwhash_argon2id_MEMLIMIT_MODERATE 268435456U

size_t rubidium_pwhash_argon2id_memlimit_moderate(void);

#define rubidium_pwhash_argon2id_OPSLIMIT_SENSITIVE 4U

std::size_t rubidium_pwhash_argon2id_opslimit_sensitive(void);

#define rubidium_pwhash_argon2id_MEMLIMIT_SENSITIVE 1073741824U

size_t rubidium_pwhash_argon2id_memlimit_sensitive(void);


int rubidium_pwhash_argon2id(unsigned char * const out,
                           std::size_t outlen,
                           const char * const passwd,
                           std::size_t passwdlen,
                           const unsigned char * const salt,
                           std::size_t opslimit, size_t memlimit,
                           int alg)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_argon2id_str(char out[rubidium_pwhash_argon2id_STRBYTES],
                               const char * const passwd,
                               std::size_t passwdlen,
                               std::size_t opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_argon2id_str_verify(const char * str,
                                      const char * const passwd,
                                      std::size_t passwdlen)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));


int rubidium_pwhash_argon2id_str_needs_rehash(const char * str,
                                            std::size_t opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
