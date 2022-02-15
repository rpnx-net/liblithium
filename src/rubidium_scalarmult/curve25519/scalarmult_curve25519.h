
#ifndef scalarmult_poly1305_H
#define scalarmult_poly1305_H

typedef struct rubidium_scalarmult_curve25519_implementation {
    int (*mult)(unsigned char *q, const unsigned char *n,
                const unsigned char *p);
    int (*mult_base)(unsigned char *q, const unsigned char *n);
} rubidium_scalarmult_curve25519_implementation;

#endif
