#ifndef rubidium_pwhash_scryptsalsa208sha256_H
#define rubidium_pwhash_scryptsalsa208sha256_H

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

#define rubidium_pwhash_scryptsalsa208sha256_BYTES_MIN 16U

size_t rubidium_pwhash_scryptsalsa208sha256_bytes_min(void);

#define rubidium_pwhash_scryptsalsa208sha256_BYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX, 0x1fffffffe0ULL)

size_t rubidium_pwhash_scryptsalsa208sha256_bytes_max(void);

#define rubidium_pwhash_scryptsalsa208sha256_PASSWD_MIN 0U

size_t rubidium_pwhash_scryptsalsa208sha256_passwd_min(void);

#define rubidium_pwhash_scryptsalsa208sha256_PASSWD_MAX RUBIDIUM_SIZE_MAX

size_t rubidium_pwhash_scryptsalsa208sha256_passwd_max(void);

#define rubidium_pwhash_scryptsalsa208sha256_SALTBYTES 32U

size_t rubidium_pwhash_scryptsalsa208sha256_saltbytes(void);

#define rubidium_pwhash_scryptsalsa208sha256_STRBYTES 102U

size_t rubidium_pwhash_scryptsalsa208sha256_strbytes(void);

#define rubidium_pwhash_scryptsalsa208sha256_STRPREFIX "$7$"

const char *rubidium_pwhash_scryptsalsa208sha256_strprefix(void);

#define rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN 32768U

std::size_t rubidium_pwhash_scryptsalsa208sha256_opslimit_min(void);

#define rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX 4294967295U

std::size_t rubidium_pwhash_scryptsalsa208sha256_opslimit_max(void);

#define rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN 16777216U

size_t rubidium_pwhash_scryptsalsa208sha256_memlimit_min(void);

#define rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX \
    RUBIDIUM_MIN(SIZE_MAX, 68719476736ULL)

size_t rubidium_pwhash_scryptsalsa208sha256_memlimit_max(void);

#define rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE 524288U

std::size_t rubidium_pwhash_scryptsalsa208sha256_opslimit_interactive(void);

#define rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE 16777216U

size_t rubidium_pwhash_scryptsalsa208sha256_memlimit_interactive(void);

#define rubidium_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE 33554432U

std::size_t rubidium_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);

#define rubidium_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE 1073741824U

size_t rubidium_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);


int rubidium_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                       std::size_t outlen,
                                       const char * const passwd,
                                       std::size_t passwdlen,
                                       const unsigned char * const salt,
                                       std::size_t opslimit,
                                       size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_scryptsalsa208sha256_str(char out[rubidium_pwhash_scryptsalsa208sha256_STRBYTES],
                                           const char * const passwd,
                                           std::size_t passwdlen,
                                           std::size_t opslimit,
                                           size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_scryptsalsa208sha256_str_verify(const char * str,
                                                  const char * const passwd,
                                                  std::size_t passwdlen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd, size_t passwdlen,
                                          const uint8_t * salt, size_t saltlen,
                                          uint64_t N, uint32_t r, uint32_t p,
                                          uint8_t * buf, size_t buflen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));


int rubidium_pwhash_scryptsalsa208sha256_str_needs_rehash(const char * str,
                                                        std::size_t opslimit,
                                                        size_t memlimit)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
