#ifndef crypto_aead_aegis128l_H
#define crypto_aead_aegis128l_H

#include <stddef.h>
#include "export.h"


namespace lithium {
    LITHIUM_EXPORT
    int crypto_aead_aegis128l_is_available(void);

#define crypto_aead_aegis128l_KEYBYTES  16U

    LITHIUM_EXPORT
    size_t crypto_aead_aegis128l_keybytes(void);

#define crypto_aead_aegis128l_NSECBYTES 0U

    LITHIUM_EXPORT
    size_t crypto_aead_aegis128l_nsecbytes(void);

#define crypto_aead_aegis128l_NPUBBYTES 16U

    LITHIUM_EXPORT
    size_t crypto_aead_aegis128l_npubbytes(void);

#define crypto_aead_aegis128l_ABYTES    16U

    LITHIUM_EXPORT
    size_t crypto_aead_aegis128l_abytes(void);

#define crypto_aead_aegis128l_MESSAGEBYTES_MAX \
    LITHIUM_MIN(LITHIUM_SIZE_MAX - crypto_aead_aegis128l_ABYTES, \
               (1ULL << 61) - 1)

    LITHIUM_EXPORT
    size_t crypto_aead_aegis128l_messagebytes_max(void);

    LITHIUM_EXPORT
    int crypto_aead_aegis128l_encrypt(unsigned char *c,
                                      unsigned long long *clen_p,
                                      const unsigned char *m,
                                      unsigned long long mlen,
                                      const unsigned char *ad,
                                      unsigned long long adlen,
                                      const unsigned char *nsec,
                                      const unsigned char *npub,
                                      const unsigned char *k)
    __attribute__ ((nonnull(1, 8, 9)));

    LITHIUM_EXPORT
    int crypto_aead_aegis128l_decrypt(unsigned char *m,
                                      unsigned long long *mlen_p,
                                      unsigned char *nsec,
                                      const unsigned char *c,
                                      unsigned long long clen,
                                      const unsigned char *ad,
                                      unsigned long long adlen,
                                      const unsigned char *npub,
                                      const unsigned char *k)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));

    LITHIUM_EXPORT
    int crypto_aead_aegis128l_encrypt_detached(unsigned char *c,
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

    LITHIUM_EXPORT
    int crypto_aead_aegis128l_decrypt_detached(unsigned char *m,
                                               unsigned char *nsec,
                                               const unsigned char *c,
                                               unsigned long long clen,
                                               const unsigned char *mac,
                                               const unsigned char *ad,
                                               unsigned long long adlen,
                                               const unsigned char *npub,
                                               const unsigned char *k)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));

    LITHIUM_EXPORT
    void crypto_aead_aegis128l_keygen(unsigned char k[crypto_aead_aegis128l_KEYBYTES])
    __attribute__ ((nonnull));


}
#endif
