
#ifndef rubidium_runtime_H
#define rubidium_runtime_H

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif


int rubidium_runtime_has_neon(void);


int rubidium_runtime_has_armcrypto(void);


int rubidium_runtime_has_sse2(void);


int rubidium_runtime_has_sse3(void);


int rubidium_runtime_has_ssse3(void);


int rubidium_runtime_has_sse41(void);


int rubidium_runtime_has_avx(void);


int rubidium_runtime_has_avx2(void);


int rubidium_runtime_has_avx512f(void);


int rubidium_runtime_has_pclmul(void);


int rubidium_runtime_has_aesni(void);


int rubidium_runtime_has_rdrand(void);

/* ------------------------------------------------------------------------- */

int _rubidium_runtime_get_cpu_features(void);

#ifdef __cplusplus
}
#endif

#endif
