
#ifndef rubidium_core_H
#define rubidium_core_H

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

RUBIDIUM_EXPORT
int rubidium_init(void)
            __attribute__ ((warn_unused_result));

/* ---- */

RUBIDIUM_EXPORT
int rubidium_set_misuse_handler(void (*handler)(void));

RUBIDIUM_EXPORT
void rubidium_misuse(void)
            __attribute__ ((noreturn));

#ifdef __cplusplus
}
#endif

#endif
