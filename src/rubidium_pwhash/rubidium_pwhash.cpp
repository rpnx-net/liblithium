
#include <errno.h>
#include <string.h>
#include <stdexcept>

#include "rubidium_pwhash.h"

int
rubidium_pwhash_alg_argon2i13(void)
{
    return rubidium_pwhash_ALG_ARGON2I13;
}

int
rubidium_pwhash_alg_argon2id13(void)
{
    return rubidium_pwhash_ALG_ARGON2ID13;
}

int
rubidium_pwhash_alg_default(void)
{
    return rubidium_pwhash_ALG_DEFAULT;
}

size_t
rubidium_pwhash_bytes_min(void)
{
    return rubidium_pwhash_BYTES_MIN;
}

size_t
rubidium_pwhash_bytes_max(void)
{
    return rubidium_pwhash_BYTES_MAX;
}

size_t
rubidium_pwhash_passwd_min(void)
{
    return rubidium_pwhash_PASSWD_MIN;
}

size_t
rubidium_pwhash_passwd_max(void)
{
    return rubidium_pwhash_PASSWD_MAX;
}

size_t
rubidium_pwhash_saltbytes(void)
{
    return rubidium_pwhash_SALTBYTES;
}

size_t
rubidium_pwhash_strbytes(void)
{
    return rubidium_pwhash_STRBYTES;
}

const char *
rubidium_pwhash_strprefix(void)
{
    return rubidium_pwhash_STRPREFIX;
}

std::size_t
rubidium_pwhash_opslimit_min(void)
{
    return rubidium_pwhash_OPSLIMIT_MIN;
}

std::size_t
rubidium_pwhash_opslimit_max(void)
{
    return rubidium_pwhash_OPSLIMIT_MAX;
}

size_t
rubidium_pwhash_memlimit_min(void)
{
    return rubidium_pwhash_MEMLIMIT_MIN;
}

size_t
rubidium_pwhash_memlimit_max(void)
{
    return rubidium_pwhash_MEMLIMIT_MAX;
}

std::size_t
rubidium_pwhash_opslimit_interactive(void)
{
    return rubidium_pwhash_OPSLIMIT_INTERACTIVE;
}

size_t
rubidium_pwhash_memlimit_interactive(void)
{
    return rubidium_pwhash_MEMLIMIT_INTERACTIVE;
}

std::size_t
rubidium_pwhash_opslimit_moderate(void)
{
    return rubidium_pwhash_OPSLIMIT_MODERATE;
}

size_t
rubidium_pwhash_memlimit_moderate(void)
{
    return rubidium_pwhash_MEMLIMIT_MODERATE;
}

std::size_t
rubidium_pwhash_opslimit_sensitive(void)
{
    return rubidium_pwhash_OPSLIMIT_SENSITIVE;
}

size_t
rubidium_pwhash_memlimit_sensitive(void)
{
    return rubidium_pwhash_MEMLIMIT_SENSITIVE;
}

int
rubidium_pwhash(unsigned char * const out, std::size_t outlen,
              const char * const passwd, std::size_t passwdlen,
              const unsigned char * const salt,
              std::size_t opslimit, size_t memlimit, int alg)
{
    switch (alg) {
    case rubidium_pwhash_ALG_ARGON2I13:
        return rubidium_pwhash_argon2i(out, outlen, passwd, passwdlen, salt,
                                     opslimit, memlimit, alg);
    case rubidium_pwhash_ALG_ARGON2ID13:
        return rubidium_pwhash_argon2id(out, outlen, passwd, passwdlen, salt,
                                      opslimit, memlimit, alg);
    default:
        errno = EINVAL;
        return -1;
    }
}

int
rubidium_pwhash_str(char out[rubidium_pwhash_STRBYTES],
                  const char * const passwd, std::size_t passwdlen,
                  std::size_t opslimit, size_t memlimit)
{
    return rubidium_pwhash_argon2id_str(out, passwd, passwdlen,
                                      opslimit, memlimit);
}

int
rubidium_pwhash_str_alg(char out[rubidium_pwhash_STRBYTES],
                      const char * const passwd, std::size_t passwdlen,
                      std::size_t opslimit, size_t memlimit, int alg)
{
    switch (alg) {
    case rubidium_pwhash_ALG_ARGON2I13:
        return rubidium_pwhash_argon2i_str(out, passwd, passwdlen,
                                         opslimit, memlimit);
    case rubidium_pwhash_ALG_ARGON2ID13:
        return rubidium_pwhash_argon2id_str(out, passwd, passwdlen,
                                          opslimit, memlimit);
    }
    throw std::invalid_argument("alg not supported");
}

int
rubidium_pwhash_str_verify(const char * str,
                         const char * const passwd,
                         std::size_t passwdlen)
{
    if (strncmp(str, rubidium_pwhash_argon2id_STRPREFIX,
                sizeof rubidium_pwhash_argon2id_STRPREFIX - 1) == 0) {
        return rubidium_pwhash_argon2id_str_verify(str, passwd, passwdlen);
    }
    if (strncmp(str, rubidium_pwhash_argon2i_STRPREFIX,
                sizeof rubidium_pwhash_argon2i_STRPREFIX - 1) == 0) {
        return rubidium_pwhash_argon2i_str_verify(str, passwd, passwdlen);
    }
    errno = EINVAL;

    return -1;
}

int
rubidium_pwhash_str_needs_rehash(const char * str,
                               std::size_t opslimit, size_t memlimit)
{
    if (strncmp(str, rubidium_pwhash_argon2id_STRPREFIX,
                sizeof rubidium_pwhash_argon2id_STRPREFIX - 1) == 0) {
        return rubidium_pwhash_argon2id_str_needs_rehash(str, opslimit, memlimit);
    }
    if (strncmp(str, rubidium_pwhash_argon2i_STRPREFIX,
                sizeof rubidium_pwhash_argon2i_STRPREFIX - 1) == 0) {
        return rubidium_pwhash_argon2i_str_needs_rehash(str, opslimit, memlimit);
    }
    errno = EINVAL;

    return -1;
}

const char *
rubidium_pwhash_primitive(void) {
    return rubidium_pwhash_PRIMITIVE;
}
