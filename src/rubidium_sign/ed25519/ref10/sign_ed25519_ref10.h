#ifndef sign_ed25519_ref10_H
#define sign_ed25519_ref10_H



void _rubidium_sign_ed25519_ref10_hinit(rubidium_hash_sha512_state *hs,
                                      int prehashed);

int _rubidium_sign_ed25519_detached(unsigned char *sig,
                                  std::size_t *siglen_p,
                                  const unsigned char *m,
                                  std::size_t mlen,
                                  const unsigned char *sk, int prehashed);

int _rubidium_sign_ed25519_verify_detached(const unsigned char *sig,
                                         const unsigned char *m,
                                         std::size_t   mlen,
                                         const unsigned char *pk,
                                         int prehashed);
#endif
