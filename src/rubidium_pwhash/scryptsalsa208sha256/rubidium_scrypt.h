/*-
 * Copyright 2009 Colin Percival
 * Copyright 2013 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#ifndef rubidium_scrypt_H
#define rubidium_scrypt_H

#include <limits.h>
#include <cstddef>
#include <cstdint>



#if SIZE_MAX > 0xffffffffULL
#define ARCH_BITS 64
#else
#define ARCH_BITS 32
#endif

#define rubidium_pwhash_scryptsalsa208sha256_STRPREFIXBYTES 14
#define rubidium_pwhash_scryptsalsa208sha256_STRSETTINGBYTES 57
#define rubidium_pwhash_scryptsalsa208sha256_STRSALTBYTES 32
#define rubidium_pwhash_scryptsalsa208sha256_STRSALTBYTES_ENCODED 43
#define rubidium_pwhash_scryptsalsa208sha256_STRHASHBYTES 32
#define rubidium_pwhash_scryptsalsa208sha256_STRHASHBYTES_ENCODED 43

#define BYTES2CHARS(bytes) ((((bytes) *8) + 5) / 6)

typedef struct {
    void * base, *aligned;
    size_t size;
} escrypt_region_t;

typedef escrypt_region_t escrypt_local_t;

int _rubidium_escrypt_init_local(escrypt_local_t *__local);

int _rubidium_escrypt_free_local(escrypt_local_t *__local);

void *_rubidium_escrypt_alloc_region(escrypt_region_t *region, size_t size);
int _rubidium_escrypt_free_region(escrypt_region_t *region);

typedef int (*escrypt_kdf_t)(escrypt_local_t *__local, const uint8_t *__passwd,
                             size_t __passwdlen, const uint8_t *__salt,
                             size_t __saltlen, uint64_t __N, uint32_t __r,
                             uint32_t __p, uint8_t *__buf, size_t __buflen);

int _rubidium_escrypt_kdf_nosse(escrypt_local_t *__local, const uint8_t *__passwd,
                      size_t __passwdlen, const uint8_t *__salt,
                      size_t __saltlen, uint64_t __N, uint32_t __r,
                      uint32_t __p, uint8_t *__buf, size_t __buflen);

int _rubidium_escrypt_kdf_sse(escrypt_local_t *__local, const uint8_t *__passwd,
                    size_t __passwdlen, const uint8_t *__salt,
                    size_t __saltlen, uint64_t __N, uint32_t __r,
                    uint32_t __p, uint8_t *__buf, size_t __buflen);

uint8_t *_rubidium_escrypt_r(escrypt_local_t *__local, const uint8_t *__passwd,
                   size_t __passwdlen, const uint8_t *__setting,
                   uint8_t *__buf, size_t __buflen);

uint8_t *_rubidium_escrypt_gensalt_r(uint32_t __N_log2, uint32_t __r, uint32_t __p,
                           const uint8_t *__src, size_t __srclen,
                           uint8_t *__buf, size_t __buflen);

const uint8_t *_rubidium_escrypt_parse_setting(const uint8_t *setting,
                                     uint32_t *N_log2_p, uint32_t *r_p,
                                     uint32_t *p_p);

#endif /* !_RUBIDIUM_SCRYPT_H_ */
