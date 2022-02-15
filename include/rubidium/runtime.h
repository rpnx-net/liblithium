
#ifndef lithium_runtime_H
#define lithium_runtime_H

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_neon(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_armcrypto(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_sse2(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_sse3(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_ssse3(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_sse41(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_avx(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_avx2(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_avx512f(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_pclmul(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_aesni(void);

LITHIUM_EXPORT_WEAK
int lithium_runtime_has_rdrand(void);

/* ------------------------------------------------------------------------- */

int _lithium_runtime_get_cpu_features(void);

#ifdef __cplusplus
}
#endif

#endif
