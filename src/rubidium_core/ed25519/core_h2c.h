#ifndef core_h2c_H
#define core_h2c_H



#define CORE_H2C_SHA256 1
#define CORE_H2C_SHA512 2

int _rubidium_core_h2c_string_to_hash(unsigned char *h, const size_t h_len, const char *ctx,
                            const unsigned char *msg, size_t msg_len,
                            int hash_alg);
#endif
