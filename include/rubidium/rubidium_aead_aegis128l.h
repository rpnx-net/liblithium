#ifndef rubidium_aead_aegis128l_H
#define rubidium_aead_aegis128l_H

#include <cstddef>
#include "export.h"


namespace rubidium {
    RUBIDIUM_EXPORT
    int rubidium_aead_aegis128l_is_available(void);

#define rubidium_aead_aegis128l_KEYBYTES  16U

    RUBIDIUM_EXPORT
    size_t rubidium_aead_aegis128l_keybytes(void);

#define rubidium_aead_aegis128l_NSECBYTES 0U

    RUBIDIUM_EXPORT
    size_t rubidium_aead_aegis128l_nsecbytes(void);

#define rubidium_aead_aegis128l_NPUBBYTES 16U

    RUBIDIUM_EXPORT
    size_t rubidium_aead_aegis128l_npubbytes(void);

#define rubidium_aead_aegis128l_ABYTES    16U

    RUBIDIUM_EXPORT
    size_t rubidium_aead_aegis128l_abytes(void);

#define rubidium_aead_aegis128l_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_aead_aegis128l_ABYTES, \
               (1ULL << 61) - 1)

    RUBIDIUM_EXPORT
    size_t rubidium_aead_aegis128l_messagebytes_max(void);

    RUBIDIUM_EXPORT
    int rubidium_aead_aegis128l_encrypt(unsigned char *c,
                                      std::size_t *clen_p,
                                      const unsigned char *m,
                                      std::size_t mlen,
                                      const unsigned char *ad,
                                      std::size_t adlen,
                                      const unsigned char *nsec,
                                      const unsigned char *npub,
                                      const unsigned char *k)
    __attribute__ ((nonnull(1, 8, 9)));

    RUBIDIUM_EXPORT
    int rubidium_aead_aegis128l_decrypt(unsigned char *m,
                                      std::size_t *mlen_p,
                                      unsigned char *nsec,
                                      const unsigned char *c,
                                      std::size_t clen,
                                      const unsigned char *ad,
                                      std::size_t adlen,
                                      const unsigned char *npub,
                                      const unsigned char *k)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));

    RUBIDIUM_EXPORT
    int rubidium_aead_aegis128l_encrypt_detached(unsigned char *c,
                                               unsigned char *mac,
                                               std::size_t *maclen_p,
                                               const unsigned char *m,
                                               std::size_t mlen,
                                               const unsigned char *ad,
                                               std::size_t adlen,
                                               const unsigned char *nsec,
                                               const unsigned char *npub,
                                               const unsigned char *k)
    __attribute__ ((nonnull(1, 2, 9, 10)));

    RUBIDIUM_EXPORT
    int rubidium_aead_aegis128l_decrypt_detached(unsigned char *m,
                                               unsigned char *nsec,
                                               const unsigned char *c,
                                               std::size_t clen,
                                               const unsigned char *mac,
                                               const unsigned char *ad,
                                               std::size_t adlen,
                                               const unsigned char *npub,
                                               const unsigned char *k)
    __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));

    RUBIDIUM_EXPORT
    void rubidium_aead_aegis128l_keygen(unsigned char k[rubidium_aead_aegis128l_KEYBYTES])
    __attribute__ ((nonnull));


}
#endif
