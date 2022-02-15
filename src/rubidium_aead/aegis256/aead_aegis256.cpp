
#include <errno.h>
#include <stdlib.h>

#include "rubidium_aead_aegis256.h"
#include "private/common.h"
#include "randombytes.h"

size_t
rubidium_aead_aegis256_keybytes(void)
{
    return rubidium_aead_aegis256_KEYBYTES;
}

size_t
rubidium_aead_aegis256_nsecbytes(void)
{
    return rubidium_aead_aegis256_NSECBYTES;
}

size_t
rubidium_aead_aegis256_npubbytes(void)
{
    return rubidium_aead_aegis256_NPUBBYTES;
}

size_t
rubidium_aead_aegis256_abytes(void)
{
    return rubidium_aead_aegis256_ABYTES;
}

size_t
rubidium_aead_aegis256_messagebytes_max(void)
{
    return rubidium_aead_aegis256_MESSAGEBYTES_MAX;
}

void
rubidium_aead_aegis256_keygen(unsigned char k[rubidium_aead_aegis256_KEYBYTES])
{
    randombytes_buf(k, rubidium_aead_aegis256_KEYBYTES);
}

#if !((defined(HAVE_TMMINTRIN_H) && defined(HAVE_WMMINTRIN_H)) || \
      defined(HAVE_ARMRUBIDIUM))

#ifndef ENOSYS
# define ENOSYS ENXIO
#endif

int
rubidium_aead_aegis256_encrypt_detached(unsigned char *c, unsigned char *mac,
                                      unsigned long long *maclen_p, const unsigned char *m,
                                      unsigned long long mlen, const unsigned char *ad,
                                      unsigned long long adlen, const unsigned char *nsec,
                                      const unsigned char *npub, const unsigned char *k)
{
    errno = ENOSYS;
    return -1;
}

int
rubidium_aead_aegis256_encrypt(unsigned char *c, unsigned long long *clen_p, const unsigned char *m,
                             unsigned long long mlen, const unsigned char *ad,
                             unsigned long long adlen, const unsigned char *nsec,
                             const unsigned char *npub, const unsigned char *k)
{
    errno = ENOSYS;
    return -1;
}

int
rubidium_aead_aegis256_decrypt_detached(unsigned char *m, unsigned char *nsec, const unsigned char *c,
                                      unsigned long long clen, const unsigned char *mac,
                                      const unsigned char *ad, unsigned long long adlen,
                                      const unsigned char *npub, const unsigned char *k)
{
    errno = ENOSYS;
    return -1;
}

int
rubidium_aead_aegis256_decrypt(unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec,
                             const unsigned char *c, unsigned long long clen,
                             const unsigned char *ad, unsigned long long adlen,
                             const unsigned char *npub, const unsigned char *k)
{
    errno = ENOSYS;
    return -1;
}

int
rubidium_aead_aegis256_is_available(void)
{
    return 0;
}

#endif
