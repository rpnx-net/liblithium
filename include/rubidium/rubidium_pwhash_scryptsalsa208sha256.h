#ifndef crypto_pwhash_scryptsalsa208sha256_H
#define crypto_pwhash_scryptsalsa208sha256_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_pwhash_scryptsalsa208sha256_BYTES_MIN 16U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_bytes_min(void);

#define crypto_pwhash_scryptsalsa208sha256_BYTES_MAX \
    LITHIUM_MIN(LITHIUM_SIZE_MAX, 0x1fffffffe0ULL)
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_bytes_max(void);

#define crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN 0U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_passwd_min(void);

#define crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX LITHIUM_SIZE_MAX
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_passwd_max(void);

#define crypto_pwhash_scryptsalsa208sha256_SALTBYTES 32U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_saltbytes(void);

#define crypto_pwhash_scryptsalsa208sha256_STRBYTES 102U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_strbytes(void);

#define crypto_pwhash_scryptsalsa208sha256_STRPREFIX "$7$"
LITHIUM_EXPORT
const char *crypto_pwhash_scryptsalsa208sha256_strprefix(void);

#define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN 32768U
LITHIUM_EXPORT
unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_min(void);

#define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX 4294967295U
LITHIUM_EXPORT
unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_max(void);

#define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN 16777216U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_min(void);

#define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX \
    LITHIUM_MIN(SIZE_MAX, 68719476736ULL)
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_max(void);

#define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE 524288U
LITHIUM_EXPORT
unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(void);

#define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE 16777216U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(void);

#define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE 33554432U
LITHIUM_EXPORT
unsigned long long crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(void);

#define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE 1073741824U
LITHIUM_EXPORT
size_t crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(void);

LITHIUM_EXPORT
int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                       unsigned long long outlen,
                                       const char * const passwd,
                                       unsigned long long passwdlen,
                                       const unsigned char * const salt,
                                       unsigned long long opslimit,
                                       size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

LITHIUM_EXPORT
int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                           const char * const passwd,
                                           unsigned long long passwdlen,
                                           unsigned long long opslimit,
                                           size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

LITHIUM_EXPORT
int crypto_pwhash_scryptsalsa208sha256_str_verify(const char * str,
                                                  const char * const passwd,
                                                  unsigned long long passwdlen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

LITHIUM_EXPORT
int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd, size_t passwdlen,
                                          const uint8_t * salt, size_t saltlen,
                                          uint64_t N, uint32_t r, uint32_t p,
                                          uint8_t * buf, size_t buflen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

LITHIUM_EXPORT
int crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(const char * str,
                                                        unsigned long long opslimit,
                                                        size_t memlimit)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
