
#ifndef rubidium_runtime_H
#define rubidium_runtime_H

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_neon(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_armcrypto(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_sse2(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_sse3(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_ssse3(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_sse41(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_avx(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_avx2(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_avx512f(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_pclmul(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_aesni(void);

RUBIDIUM_EXPORT_WEAK
int rubidium_runtime_has_rdrand(void);

/* ------------------------------------------------------------------------- */

int _rubidium_runtime_get_cpu_features(void);

#ifdef __cplusplus
}
#endif

#endif
