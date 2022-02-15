#ifndef rubidium_kx_H
#define rubidium_kx_H

#include <stddef.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_kx_PUBLICKEYBYTES 32
RUBIDIUM_EXPORT
size_t rubidium_kx_publickeybytes(void);

#define rubidium_kx_SECRETKEYBYTES 32
RUBIDIUM_EXPORT
size_t rubidium_kx_secretkeybytes(void);

#define rubidium_kx_SEEDBYTES 32
RUBIDIUM_EXPORT
size_t rubidium_kx_seedbytes(void);

#define rubidium_kx_SESSIONKEYBYTES 32
RUBIDIUM_EXPORT
size_t rubidium_kx_sessionkeybytes(void);

#define rubidium_kx_PRIMITIVE "x25519blake2b"
RUBIDIUM_EXPORT
const char *rubidium_kx_primitive(void);

RUBIDIUM_EXPORT
int rubidium_kx_seed_keypair(unsigned char pk[rubidium_kx_PUBLICKEYBYTES],
                           unsigned char sk[rubidium_kx_SECRETKEYBYTES],
                           const unsigned char seed[rubidium_kx_SEEDBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_kx_keypair(unsigned char pk[rubidium_kx_PUBLICKEYBYTES],
                      unsigned char sk[rubidium_kx_SECRETKEYBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_kx_client_session_keys(unsigned char rx[rubidium_kx_SESSIONKEYBYTES],
                                  unsigned char tx[rubidium_kx_SESSIONKEYBYTES],
                                  const unsigned char client_pk[rubidium_kx_PUBLICKEYBYTES],
                                  const unsigned char client_sk[rubidium_kx_SECRETKEYBYTES],
                                  const unsigned char server_pk[rubidium_kx_PUBLICKEYBYTES])
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull(3, 4, 5)));

RUBIDIUM_EXPORT
int rubidium_kx_server_session_keys(unsigned char rx[rubidium_kx_SESSIONKEYBYTES],
                                  unsigned char tx[rubidium_kx_SESSIONKEYBYTES],
                                  const unsigned char server_pk[rubidium_kx_PUBLICKEYBYTES],
                                  const unsigned char server_sk[rubidium_kx_SECRETKEYBYTES],
                                  const unsigned char client_pk[rubidium_kx_PUBLICKEYBYTES])
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull(3, 4, 5)));

#ifdef __cplusplus
}
#endif

#endif
