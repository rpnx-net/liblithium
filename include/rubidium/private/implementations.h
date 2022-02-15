#ifndef implementations_H
#define implementations_H

#include "private/quirks.h"

int _rubidium_generichash_blake2b_pick_best_implementation(void);
int _rubidium_onetimeauth_poly1305_pick_best_implementation(void);
int _rubidium_pwhash_argon2_pick_best_implementation(void);
int _rubidium_scalarmult_curve25519_pick_best_implementation(void);
int _rubidium_stream_chacha20_pick_best_implementation(void);
int _rubidium_stream_salsa20_pick_best_implementation(void);

#endif
