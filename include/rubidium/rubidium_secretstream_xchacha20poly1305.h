#ifndef rubidium_secretstream_xchacha20poly1305_H
#define rubidium_secretstream_xchacha20poly1305_H

#include <stddef.h>

#include "rubidium_aead_xchacha20poly1305.h"
#include "rubidium_stream_chacha20.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define rubidium_secretstream_xchacha20poly1305_ABYTES \
    (1U + rubidium_aead_xchacha20poly1305_ietf_ABYTES)
RUBIDIUM_EXPORT
size_t rubidium_secretstream_xchacha20poly1305_abytes(void);

#define rubidium_secretstream_xchacha20poly1305_HEADERBYTES \
    rubidium_aead_xchacha20poly1305_ietf_NPUBBYTES
RUBIDIUM_EXPORT
size_t rubidium_secretstream_xchacha20poly1305_headerbytes(void);

#define rubidium_secretstream_xchacha20poly1305_KEYBYTES \
    rubidium_aead_xchacha20poly1305_ietf_KEYBYTES
RUBIDIUM_EXPORT
size_t rubidium_secretstream_xchacha20poly1305_keybytes(void);

#define rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_secretstream_xchacha20poly1305_ABYTES, \
              (64ULL * ((1ULL << 32) - 2ULL)))
RUBIDIUM_EXPORT
size_t rubidium_secretstream_xchacha20poly1305_messagebytes_max(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_MESSAGE 0x00
RUBIDIUM_EXPORT
unsigned char rubidium_secretstream_xchacha20poly1305_tag_message(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_PUSH    0x01
RUBIDIUM_EXPORT
unsigned char rubidium_secretstream_xchacha20poly1305_tag_push(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_REKEY   0x02
RUBIDIUM_EXPORT
unsigned char rubidium_secretstream_xchacha20poly1305_tag_rekey(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_FINAL \
    (rubidium_secretstream_xchacha20poly1305_TAG_PUSH | \
     rubidium_secretstream_xchacha20poly1305_TAG_REKEY)
RUBIDIUM_EXPORT
unsigned char rubidium_secretstream_xchacha20poly1305_tag_final(void);

typedef struct rubidium_secretstream_xchacha20poly1305_state {
    unsigned char k[rubidium_stream_chacha20_ietf_KEYBYTES];
    unsigned char nonce[rubidium_stream_chacha20_ietf_NONCEBYTES];
    unsigned char _pad[8];
} rubidium_secretstream_xchacha20poly1305_state;

RUBIDIUM_EXPORT
size_t rubidium_secretstream_xchacha20poly1305_statebytes(void);

RUBIDIUM_EXPORT
void rubidium_secretstream_xchacha20poly1305_keygen
   (unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_secretstream_xchacha20poly1305_init_push
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char header[rubidium_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_secretstream_xchacha20poly1305_push
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char *c, unsigned long long *clen_p,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen, unsigned char tag)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
int rubidium_secretstream_xchacha20poly1305_init_pull
   (rubidium_secretstream_xchacha20poly1305_state *state,
    const unsigned char header[rubidium_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));

RUBIDIUM_EXPORT
int rubidium_secretstream_xchacha20poly1305_pull
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char *m, unsigned long long *mlen_p, unsigned char *tag_p,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen)
            __attribute__ ((nonnull(1)));

RUBIDIUM_EXPORT
void rubidium_secretstream_xchacha20poly1305_rekey
    (rubidium_secretstream_xchacha20poly1305_state *state);

#ifdef __cplusplus
}
#endif

#endif
