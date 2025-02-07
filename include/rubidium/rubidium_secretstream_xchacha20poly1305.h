#ifndef rubidium_secretstream_xchacha20poly1305_H
#define rubidium_secretstream_xchacha20poly1305_H

#include <cstddef>

#include "rubidium_aead_xchacha20poly1305.h"
#include "rubidium_stream_chacha20.h"
#include "export.h"



#define rubidium_secretstream_xchacha20poly1305_ABYTES \
    (1U + rubidium_aead_xchacha20poly1305_ietf_ABYTES)

size_t rubidium_secretstream_xchacha20poly1305_abytes(void);

#define rubidium_secretstream_xchacha20poly1305_HEADERBYTES \
    rubidium_aead_xchacha20poly1305_ietf_NPUBBYTES

size_t rubidium_secretstream_xchacha20poly1305_headerbytes(void);

#define rubidium_secretstream_xchacha20poly1305_KEYBYTES \
    rubidium_aead_xchacha20poly1305_ietf_KEYBYTES

size_t rubidium_secretstream_xchacha20poly1305_keybytes(void);

#define rubidium_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX \
    RUBIDIUM_MIN(RUBIDIUM_SIZE_MAX - rubidium_secretstream_xchacha20poly1305_ABYTES, \
              (64ULL * ((1ULL << 32) - 2ULL)))

size_t rubidium_secretstream_xchacha20poly1305_messagebytes_max(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_MESSAGE 0x00

unsigned char rubidium_secretstream_xchacha20poly1305_tag_message(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_PUSH    0x01

unsigned char rubidium_secretstream_xchacha20poly1305_tag_push(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_REKEY   0x02

unsigned char rubidium_secretstream_xchacha20poly1305_tag_rekey(void);

#define rubidium_secretstream_xchacha20poly1305_TAG_FINAL \
    (rubidium_secretstream_xchacha20poly1305_TAG_PUSH | \
     rubidium_secretstream_xchacha20poly1305_TAG_REKEY)

unsigned char rubidium_secretstream_xchacha20poly1305_tag_final(void);

typedef struct rubidium_secretstream_xchacha20poly1305_state {
    unsigned char k[rubidium_stream_chacha20_ietf_KEYBYTES];
    unsigned char nonce[rubidium_stream_chacha20_ietf_NONCEBYTES];
    unsigned char _pad[8];
} rubidium_secretstream_xchacha20poly1305_state;


size_t rubidium_secretstream_xchacha20poly1305_statebytes(void);


void rubidium_secretstream_xchacha20poly1305_keygen
   (unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));


int rubidium_secretstream_xchacha20poly1305_init_push
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char header[rubidium_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));


int rubidium_secretstream_xchacha20poly1305_push
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char *c, std::size_t *clen_p,
    const unsigned char *m, std::size_t mlen,
    const unsigned char *ad, std::size_t adlen, unsigned char tag)
            __attribute__ ((nonnull(1)));


int rubidium_secretstream_xchacha20poly1305_init_pull
   (rubidium_secretstream_xchacha20poly1305_state *state,
    const unsigned char header[rubidium_secretstream_xchacha20poly1305_HEADERBYTES],
    const unsigned char k[rubidium_secretstream_xchacha20poly1305_KEYBYTES])
            __attribute__ ((nonnull));


int rubidium_secretstream_xchacha20poly1305_pull
   (rubidium_secretstream_xchacha20poly1305_state *state,
    unsigned char *m, std::size_t *mlen_p, unsigned char *tag_p,
    const unsigned char *c, std::size_t clen,
    const unsigned char *ad, std::size_t adlen)
            __attribute__ ((nonnull(1)));


void rubidium_secretstream_xchacha20poly1305_rekey
    (rubidium_secretstream_xchacha20poly1305_state *state);



#endif
