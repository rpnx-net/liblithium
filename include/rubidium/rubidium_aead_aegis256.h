#ifndef rubidium_aead_aegis256_H
#define rubidium_aead_aegis256_H

#include <stddef.h>
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

RUBIDIUM_EXPORT
int rubidium_aead_aegis256_is_available(void);

#define rubidium_aead_aegis256_KEYBYTES  32U
RUBIDIUM_EXPORT
size_t rubidium_aead_aegis256_keybytes(void);

#define rubidium_aead_aegis256_NSECBYTES 0U
RUBIDIUM_EXPORT
size_t rubidium_aead_aegis256_nsecbytes(void);

#define rubidium_aead_aegis256_NPUBBYTES 32U
RUBIDIUM_EXPORT
size_t rubidium_aead_aegis256_npubbytes(void);

#define rubidium_aead_aegis256_ABYTES    16U
RUBIDIUM_EXPORT
size_t rubidium_aead_aegis256_abytes(void);

#define rubidium_aead_aegis256_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_aead_aegis256_ABYTES, \
               (1ULL << 61) - 1)
RUBIDIUM_EXPORT
size_t rubidium_aead_aegis256_messagebytes_max(void);

RUBIDIUM_EXPORT
int rubidium_aead_aegis256_encrypt(unsigned char *c,
                                 unsigned long long *clen_p,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *ad,
                                 unsigned long long adlen,
                                 const unsigned char *nsec,
                                 const unsigned char *npub,
                                 const unsigned char *k)
            __attribute__ ((nonnull(1, 8, 9)));

RUBIDIUM_EXPORT
int rubidium_aead_aegis256_decrypt(unsigned char *m,
                                 unsigned long long *mlen_p,
                                 unsigned char *nsec,
                                 const unsigned char *c,
                                 unsigned long long clen,
                                 const unsigned char *ad,
                                 unsigned long long adlen,
                                 const unsigned char *npub,
                                 const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));

RUBIDIUM_EXPORT
int rubidium_aead_aegis256_encrypt_detached(unsigned char *c,
                                          unsigned char *mac,
                                          unsigned long long *maclen_p,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *ad,
                                          unsigned long long adlen,
                                          const unsigned char *nsec,
                                          const unsigned char *npub,
                                          const unsigned char *k)
            __attribute__ ((nonnull(1, 2, 9, 10)));

RUBIDIUM_EXPORT
int rubidium_aead_aegis256_decrypt_detached(unsigned char *m,
                                          unsigned char *nsec,
                                          const unsigned char *c,
                                          unsigned long long clen,
                                          const unsigned char *mac,
                                          const unsigned char *ad,
                                          unsigned long long adlen,
                                          const unsigned char *npub,
                                          const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));

RUBIDIUM_EXPORT
void rubidium_aead_aegis256_keygen(unsigned char k[rubidium_aead_aegis256_KEYBYTES])
            __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
