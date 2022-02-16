#ifndef rubidium_pwhash_argon2i_H
#define rubidium_pwhash_argon2i_H

#include <limits.h>
#include <cstddef>
#include <cstdint>

#include "export.h"



#define rubidium_pwhash_argon2i_ALG_ARGON2I13 1

int rubidium_pwhash_argon2i_alg_argon2i13(void);

#define rubidium_pwhash_argon2i_BYTES_MIN 16U

size_t rubidium_pwhash_argon2i_bytes_min(void);

#define rubidium_pwhash_argon2i_BYTES_MAX RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX, 4294967295U)

size_t rubidium_pwhash_argon2i_bytes_max(void);

#define rubidium_pwhash_argon2i_PASSWD_MIN 0U

size_t rubidium_pwhash_argon2i_passwd_min(void);

#define rubidium_pwhash_argon2i_PASSWD_MAX 4294967295U

size_t rubidium_pwhash_argon2i_passwd_max(void);

#define rubidium_pwhash_argon2i_SALTBYTES 16U

size_t rubidium_pwhash_argon2i_saltbytes(void);

#define rubidium_pwhash_argon2i_STRBYTES 128U

size_t rubidium_pwhash_argon2i_strbytes(void);

#define rubidium_pwhash_argon2i_STRPREFIX "$argon2i$"

const char *rubidium_pwhash_argon2i_strprefix(void);

#define rubidium_pwhash_argon2i_OPSLIMIT_MIN 3U

std::size_t rubidium_pwhash_argon2i_opslimit_min(void);

#define rubidium_pwhash_argon2i_OPSLIMIT_MAX 4294967295U

std::size_t rubidium_pwhash_argon2i_opslimit_max(void);

#define rubidium_pwhash_argon2i_MEMLIMIT_MIN 8192U

size_t rubidium_pwhash_argon2i_memlimit_min(void);

#define rubidium_pwhash_argon2i_MEMLIMIT_MAX \
    ((SIZE_MAX >= 4398046510080U) ? 4398046510080U : (SIZE_MAX >= 2147483648U) ? 2147483648U : 32768U)

size_t rubidium_pwhash_argon2i_memlimit_max(void);

#define rubidium_pwhash_argon2i_OPSLIMIT_INTERACTIVE 4U

std::size_t rubidium_pwhash_argon2i_opslimit_interactive(void);

#define rubidium_pwhash_argon2i_MEMLIMIT_INTERACTIVE 33554432U

size_t rubidium_pwhash_argon2i_memlimit_interactive(void);

#define rubidium_pwhash_argon2i_OPSLIMIT_MODERATE 6U

std::size_t rubidium_pwhash_argon2i_opslimit_moderate(void);

#define rubidium_pwhash_argon2i_MEMLIMIT_MODERATE 134217728U

size_t rubidium_pwhash_argon2i_memlimit_moderate(void);

#define rubidium_pwhash_argon2i_OPSLIMIT_SENSITIVE 8U

std::size_t rubidium_pwhash_argon2i_opslimit_sensitive(void);

#define rubidium_pwhash_argon2i_MEMLIMIT_SENSITIVE 536870912U

size_t rubidium_pwhash_argon2i_memlimit_sensitive(void);


int rubidium_pwhash_argon2i(unsigned char * const out,
                          std::size_t outlen,
                          const char * const passwd,
                          std::size_t passwdlen,
                          const unsigned char * const salt,
                          std::size_t opslimit, size_t memlimit,
                          int alg)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_argon2i_str(char out[rubidium_pwhash_argon2i_STRBYTES],
                              const char * const passwd,
                              std::size_t passwdlen,
                              std::size_t opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_argon2i_str_verify(const char * str,
                                     const char * const passwd,
                                     std::size_t passwdlen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_argon2i_str_needs_rehash(const char * str,
                                           std::size_t opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));



#endif
