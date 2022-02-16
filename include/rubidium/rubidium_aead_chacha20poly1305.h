#ifndef rubidium_aead_chacha20poly1305_H
#define rubidium_aead_chacha20poly1305_H

#include <cstddef>
#include "export.h"



/* -- IETF ChaCha20-Poly1305 construction with a 96-bit nonce and a 32-bit internal counter -- */

#define rubidium_aead_chacha20poly1305_ietf_KEYBYTES 32U

size_t rubidium_aead_chacha20poly1305_ietf_keybytes(void);

#define rubidium_aead_chacha20poly1305_ietf_NSECBYTES 0U

size_t rubidium_aead_chacha20poly1305_ietf_nsecbytes(void);

#define rubidium_aead_chacha20poly1305_ietf_NPUBBYTES 12U


size_t rubidium_aead_chacha20poly1305_ietf_npubbytes(void);

#define rubidium_aead_chacha20poly1305_ietf_ABYTES 16U

size_t rubidium_aead_chacha20poly1305_ietf_abytes(void);

#define rubidium_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_aead_chacha20poly1305_ietf_ABYTES, \
               (64ULL * ((1ULL << 32) - 1ULL)))

size_t rubidium_aead_chacha20poly1305_ietf_messagebytes_max(void);


int rubidium_aead_chacha20poly1305_ietf_encrypt(unsigned char *c,
                                              std::size_t *clen_p,
                                              const unsigned char *m,
                                              std::size_t mlen,
                                              const unsigned char *ad,
                                              std::size_t adlen,
                                              const unsigned char *nsec,
                                              const unsigned char *npub,
                                              const unsigned char *k)
            __attribute__ ((nonnull(1, 8, 9)));


int rubidium_aead_chacha20poly1305_ietf_decrypt(unsigned char *m,
                                              std::size_t *mlen_p,
                                              unsigned char *nsec,
                                              const unsigned char *c,
                                              std::size_t clen,
                                              const unsigned char *ad,
                                              std::size_t adlen,
                                              const unsigned char *npub,
                                              const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));


int rubidium_aead_chacha20poly1305_ietf_encrypt_detached(unsigned char *c,
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


int rubidium_aead_chacha20poly1305_ietf_decrypt_detached(unsigned char *m,
                                                       unsigned char *nsec,
                                                       const unsigned char *c,
                                                       std::size_t clen,
                                                       const unsigned char *mac,
                                                       const unsigned char *ad,
                                                       std::size_t adlen,
                                                       const unsigned char *npub,
                                                       const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));


void rubidium_aead_chacha20poly1305_ietf_keygen(unsigned char k[rubidium_aead_chacha20poly1305_ietf_KEYBYTES])
            __attribute__ ((nonnull));

/* -- Original ChaCha20-Poly1305 construction with a 64-bit nonce and a 64-bit internal counter -- */

#define rubidium_aead_chacha20poly1305_KEYBYTES 32U

size_t rubidium_aead_chacha20poly1305_keybytes(void);

#define rubidium_aead_chacha20poly1305_NSECBYTES 0U

size_t rubidium_aead_chacha20poly1305_nsecbytes(void);

#define rubidium_aead_chacha20poly1305_NPUBBYTES 8U

size_t rubidium_aead_chacha20poly1305_npubbytes(void);

#define rubidium_aead_chacha20poly1305_ABYTES 16U

size_t rubidium_aead_chacha20poly1305_abytes(void);

#define rubidium_aead_chacha20poly1305_MESSAGEBYTES_MAX \
    (RUBIDIUM_SIZE_MAX - rubidium_aead_chacha20poly1305_ABYTES)

size_t rubidium_aead_chacha20poly1305_messagebytes_max(void);


int rubidium_aead_chacha20poly1305_encrypt(unsigned char *c,
                                         std::size_t *clen_p,
                                         const unsigned char *m,
                                         std::size_t mlen,
                                         const unsigned char *ad,
                                         std::size_t adlen,
                                         const unsigned char *nsec,
                                         const unsigned char *npub,
                                         const unsigned char *k)
            __attribute__ ((nonnull(1, 8, 9)));


int rubidium_aead_chacha20poly1305_decrypt(unsigned char *m,
                                         std::size_t *mlen_p,
                                         unsigned char *nsec,
                                         const unsigned char *c,
                                         std::size_t clen,
                                         const unsigned char *ad,
                                         std::size_t adlen,
                                         const unsigned char *npub,
                                         const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));


int rubidium_aead_chacha20poly1305_encrypt_detached(unsigned char *c,
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


int rubidium_aead_chacha20poly1305_decrypt_detached(unsigned char *m,
                                                  unsigned char *nsec,
                                                  const unsigned char *c,
                                                  std::size_t clen,
                                                  const unsigned char *mac,
                                                  const unsigned char *ad,
                                                  std::size_t adlen,
                                                  const unsigned char *npub,
                                                  const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));


void rubidium_aead_chacha20poly1305_keygen(unsigned char k[rubidium_aead_chacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));

/* Aliases */

#define rubidium_aead_chacha20poly1305_IETF_KEYBYTES         rubidium_aead_chacha20poly1305_ietf_KEYBYTES
#define rubidium_aead_chacha20poly1305_IETF_NSECBYTES        rubidium_aead_chacha20poly1305_ietf_NSECBYTES
#define rubidium_aead_chacha20poly1305_IETF_NPUBBYTES        rubidium_aead_chacha20poly1305_ietf_NPUBBYTES
#define rubidium_aead_chacha20poly1305_IETF_ABYTES           rubidium_aead_chacha20poly1305_ietf_ABYTES
#define rubidium_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX rubidium_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX



#endif
