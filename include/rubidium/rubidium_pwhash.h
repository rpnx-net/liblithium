#ifndef rubidium_pwhash_H
#define rubidium_pwhash_H

#include <stddef.h>

#include "rubidium_pwhash_argon2i.h"
#include "rubidium_pwhash_argon2id.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_pwhash_ALG_ARGON2I13 rubidium_pwhash_argon2i_ALG_ARGON2I13
RUBIDIUM_EXPORT
int rubidium_pwhash_alg_argon2i13(void);

#define rubidium_pwhash_ALG_ARGON2ID13 rubidium_pwhash_argon2id_ALG_ARGON2ID13
RUBIDIUM_EXPORT
int rubidium_pwhash_alg_argon2id13(void);

#define rubidium_pwhash_ALG_DEFAULT rubidium_pwhash_ALG_ARGON2ID13
RUBIDIUM_EXPORT
int rubidium_pwhash_alg_default(void);

#define rubidium_pwhash_BYTES_MIN rubidium_pwhash_argon2id_BYTES_MIN
RUBIDIUM_EXPORT
size_t rubidium_pwhash_bytes_min(void);

#define rubidium_pwhash_BYTES_MAX rubidium_pwhash_argon2id_BYTES_MAX
RUBIDIUM_EXPORT
size_t rubidium_pwhash_bytes_max(void);

#define rubidium_pwhash_PASSWD_MIN rubidium_pwhash_argon2id_PASSWD_MIN
RUBIDIUM_EXPORT
size_t rubidium_pwhash_passwd_min(void);

#define rubidium_pwhash_PASSWD_MAX rubidium_pwhash_argon2id_PASSWD_MAX
RUBIDIUM_EXPORT
size_t rubidium_pwhash_passwd_max(void);

#define rubidium_pwhash_SALTBYTES rubidium_pwhash_argon2id_SALTBYTES
RUBIDIUM_EXPORT
size_t rubidium_pwhash_saltbytes(void);

#define rubidium_pwhash_STRBYTES rubidium_pwhash_argon2id_STRBYTES
RUBIDIUM_EXPORT
size_t rubidium_pwhash_strbytes(void);

#define rubidium_pwhash_STRPREFIX rubidium_pwhash_argon2id_STRPREFIX
RUBIDIUM_EXPORT
const char *rubidium_pwhash_strprefix(void);

#define rubidium_pwhash_OPSLIMIT_MIN rubidium_pwhash_argon2id_OPSLIMIT_MIN
RUBIDIUM_EXPORT
unsigned long long rubidium_pwhash_opslimit_min(void);

#define rubidium_pwhash_OPSLIMIT_MAX rubidium_pwhash_argon2id_OPSLIMIT_MAX
RUBIDIUM_EXPORT
unsigned long long rubidium_pwhash_opslimit_max(void);

#define rubidium_pwhash_MEMLIMIT_MIN rubidium_pwhash_argon2id_MEMLIMIT_MIN
RUBIDIUM_EXPORT
size_t rubidium_pwhash_memlimit_min(void);

#define rubidium_pwhash_MEMLIMIT_MAX rubidium_pwhash_argon2id_MEMLIMIT_MAX
RUBIDIUM_EXPORT
size_t rubidium_pwhash_memlimit_max(void);

#define rubidium_pwhash_OPSLIMIT_INTERACTIVE rubidium_pwhash_argon2id_OPSLIMIT_INTERACTIVE
RUBIDIUM_EXPORT
unsigned long long rubidium_pwhash_opslimit_interactive(void);

#define rubidium_pwhash_MEMLIMIT_INTERACTIVE rubidium_pwhash_argon2id_MEMLIMIT_INTERACTIVE
RUBIDIUM_EXPORT
size_t rubidium_pwhash_memlimit_interactive(void);

#define rubidium_pwhash_OPSLIMIT_MODERATE rubidium_pwhash_argon2id_OPSLIMIT_MODERATE
RUBIDIUM_EXPORT
unsigned long long rubidium_pwhash_opslimit_moderate(void);

#define rubidium_pwhash_MEMLIMIT_MODERATE rubidium_pwhash_argon2id_MEMLIMIT_MODERATE
RUBIDIUM_EXPORT
size_t rubidium_pwhash_memlimit_moderate(void);

#define rubidium_pwhash_OPSLIMIT_SENSITIVE rubidium_pwhash_argon2id_OPSLIMIT_SENSITIVE
RUBIDIUM_EXPORT
unsigned long long rubidium_pwhash_opslimit_sensitive(void);

#define rubidium_pwhash_MEMLIMIT_SENSITIVE rubidium_pwhash_argon2id_MEMLIMIT_SENSITIVE
RUBIDIUM_EXPORT
size_t rubidium_pwhash_memlimit_sensitive(void);

/*
 * With this function, do not forget to store all parameters, including the
 * algorithm identifier in order to produce deterministic output.
 * The rubidium_pwhash_* definitions, including rubidium_pwhash_ALG_DEFAULT,
 * may change.
 */
RUBIDIUM_EXPORT
int rubidium_pwhash(unsigned char * const out, unsigned long long outlen,
                  const char * const passwd, unsigned long long passwdlen,
                  const unsigned char * const salt,
                  unsigned long long opslimit, size_t memlimit, int alg)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

/*
 * The output string already includes all the required parameters, including
 * the algorithm identifier. The string is all that has to be stored in
 * order to verify a password.
 */
RUBIDIUM_EXPORT
int rubidium_pwhash_str(char out[rubidium_pwhash_STRBYTES],
                      const char * const passwd, unsigned long long passwdlen,
                      unsigned long long opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_pwhash_str_alg(char out[rubidium_pwhash_STRBYTES],
                          const char * const passwd, unsigned long long passwdlen,
                          unsigned long long opslimit, size_t memlimit, int alg)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_pwhash_str_verify(const char *str,
                             const char * const passwd,
                             unsigned long long passwdlen)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_pwhash_str_needs_rehash(const char *str,
                                   unsigned long long opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

#define rubidium_pwhash_PRIMITIVE "argon2i"
RUBIDIUM_EXPORT
const char *rubidium_pwhash_primitive(void)
            __attribute__ ((warn_unused_result));

#ifdef __cplusplus
}
#endif

#endif
