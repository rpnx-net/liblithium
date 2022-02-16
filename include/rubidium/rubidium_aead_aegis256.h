#ifndef rubidium_aead_aegis256_H
#define rubidium_aead_aegis256_H

#include <cstddef>
#include "export.h"




int rubidium_aead_aegis256_is_available(void);

#define rubidium_aead_aegis256_KEYBYTES  32U

size_t rubidium_aead_aegis256_keybytes(void);

#define rubidium_aead_aegis256_NSECBYTES 0U

size_t rubidium_aead_aegis256_nsecbytes(void);

#define rubidium_aead_aegis256_NPUBBYTES 32U

size_t rubidium_aead_aegis256_npubbytes(void);

#define rubidium_aead_aegis256_ABYTES    16U

size_t rubidium_aead_aegis256_abytes(void);

#define rubidium_aead_aegis256_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_aead_aegis256_ABYTES, \
               (1ULL << 61) - 1)

size_t rubidium_aead_aegis256_messagebytes_max(void);


int rubidium_aead_aegis256_encrypt(unsigned char *c,
                                 std::size_t *clen_p,
                                 const unsigned char *m,
                                 std::size_t mlen,
                                 const unsigned char *ad,
                                 std::size_t adlen,
                                 const unsigned char *nsec,
                                 const unsigned char *npub,
                                 const unsigned char *k)
            __attribute__ ((nonnull(1, 8, 9)));


int rubidium_aead_aegis256_decrypt(unsigned char *m,
                                 std::size_t *mlen_p,
                                 unsigned char *nsec,
                                 const unsigned char *c,
                                 std::size_t clen,
                                 const unsigned char *ad,
                                 std::size_t adlen,
                                 const unsigned char *npub,
                                 const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));


int rubidium_aead_aegis256_encrypt_detached(unsigned char *c,
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


int rubidium_aead_aegis256_decrypt_detached(unsigned char *m,
                                          unsigned char *nsec,
                                          const unsigned char *c,
                                          std::size_t clen,
                                          const unsigned char *mac,
                                          const unsigned char *ad,
                                          std::size_t adlen,
                                          const unsigned char *npub,
                                          const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));


void rubidium_aead_aegis256_keygen(unsigned char k[rubidium_aead_aegis256_KEYBYTES])
            __attribute__ ((nonnull));


#endif
