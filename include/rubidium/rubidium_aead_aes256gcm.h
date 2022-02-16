#ifndef rubidium_aead_aes256gcm_H
#define rubidium_aead_aes256gcm_H

/*
 * WARNING: Despite being the most popular AEAD construction due to its
 * use in TLS, safely using AES-GCM in a different context is tricky.
 *
 * No more than ~ 350 GB of input data should be encrypted with a given key.
 * This is for ~ 16 KB messages -- Actual figures vary according to
 * message sizes.
 *
 * In addition, nonces are short and repeated nonces would totally destroy
 * the security of this scheme.
 *
 * Nonces should thus come from atomic counters, which can be difficult to
 * set up in a distributed environment.
 *
 * Unless you absolutely need AES-GCM, use rubidium_aead_xchacha20poly1305_ietf_*()
 * instead. It doesn't have any of these limitations.
 * Or, if you don't need to authenticate additional data, just stick to
 * rubidium_secretbox().
 */

#include <cstddef>
#include "export.h"



int rubidium_aead_aes256gcm_is_available(void);

#define rubidium_aead_aes256gcm_KEYBYTES  32U

size_t rubidium_aead_aes256gcm_keybytes(void);

#define rubidium_aead_aes256gcm_NSECBYTES 0U

size_t rubidium_aead_aes256gcm_nsecbytes(void);

#define rubidium_aead_aes256gcm_NPUBBYTES 12U

size_t rubidium_aead_aes256gcm_npubbytes(void);

#define rubidium_aead_aes256gcm_ABYTES    16U

size_t rubidium_aead_aes256gcm_abytes(void);

#define rubidium_aead_aes256gcm_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_aead_aes256gcm_ABYTES, \
               (16ULL * ((1ULL << 32) - 2ULL)))

size_t rubidium_aead_aes256gcm_messagebytes_max(void);

typedef struct alignas(16) rubidium_aead_aes256gcm_state_ {
    unsigned char opaque[512];
} rubidium_aead_aes256gcm_state;


size_t rubidium_aead_aes256gcm_statebytes(void);


int rubidium_aead_aes256gcm_encrypt(unsigned char *c,
                                  std::size_t *clen_p,
                                  const unsigned char *m,
                                  std::size_t mlen,
                                  const unsigned char *ad,
                                  std::size_t adlen,
                                  const unsigned char *nsec,
                                  const unsigned char *npub,
                                  const unsigned char *k)
            __attribute__ ((nonnull(1, 8, 9)));


int rubidium_aead_aes256gcm_decrypt(unsigned char *m,
                                  std::size_t *mlen_p,
                                  unsigned char *nsec,
                                  const unsigned char *c,
                                  std::size_t clen,
                                  const unsigned char *ad,
                                  std::size_t adlen,
                                  const unsigned char *npub,
                                  const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));


int rubidium_aead_aes256gcm_encrypt_detached(unsigned char *c,
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


int rubidium_aead_aes256gcm_decrypt_detached(unsigned char *m,
                                           unsigned char *nsec,
                                           const unsigned char *c,
                                           std::size_t clen,
                                           const unsigned char *mac,
                                           const unsigned char *ad,
                                           std::size_t adlen,
                                           const unsigned char *npub,
                                           const unsigned char *k)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));

/* -- Precomputation interface -- */


int rubidium_aead_aes256gcm_beforenm(rubidium_aead_aes256gcm_state *ctx_,
                                   const unsigned char *k)
            __attribute__ ((nonnull));


int rubidium_aead_aes256gcm_encrypt_afternm(unsigned char *c,
                                          std::size_t *clen_p,
                                          const unsigned char *m,
                                          std::size_t mlen,
                                          const unsigned char *ad,
                                          std::size_t adlen,
                                          const unsigned char *nsec,
                                          const unsigned char *npub,
                                          const rubidium_aead_aes256gcm_state *ctx_)
            __attribute__ ((nonnull(1, 8, 9)));


int rubidium_aead_aes256gcm_decrypt_afternm(unsigned char *m,
                                          std::size_t *mlen_p,
                                          unsigned char *nsec,
                                          const unsigned char *c,
                                          std::size_t clen,
                                          const unsigned char *ad,
                                          std::size_t adlen,
                                          const unsigned char *npub,
                                          const rubidium_aead_aes256gcm_state *ctx_)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(4, 8, 9)));


int rubidium_aead_aes256gcm_encrypt_detached_afternm(unsigned char *c,
                                                   unsigned char *mac,
                                                   std::size_t *maclen_p,
                                                   const unsigned char *m,
                                                   std::size_t mlen,
                                                   const unsigned char *ad,
                                                   std::size_t adlen,
                                                   const unsigned char *nsec,
                                                   const unsigned char *npub,
                                                   const rubidium_aead_aes256gcm_state *ctx_)
            __attribute__ ((nonnull(1, 2, 9, 10)));


int rubidium_aead_aes256gcm_decrypt_detached_afternm(unsigned char *m,
                                                   unsigned char *nsec,
                                                   const unsigned char *c,
                                                   std::size_t clen,
                                                   const unsigned char *mac,
                                                   const unsigned char *ad,
                                                   std::size_t adlen,
                                                   const unsigned char *npub,
                                                   const rubidium_aead_aes256gcm_state *ctx_)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull(3, 5, 8, 9)));


void rubidium_aead_aes256gcm_keygen(unsigned char k[rubidium_aead_aes256gcm_KEYBYTES])
            __attribute__ ((nonnull));



#endif
