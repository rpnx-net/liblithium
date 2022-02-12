
#ifndef lithium_core_H
#define lithium_core_H

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

LITHIUM_EXPORT
int lithium_init(void)
            __attribute__ ((warn_unused_result));

/* ---- */

LITHIUM_EXPORT
int lithium_set_misuse_handler(void (*handler)(void));

LITHIUM_EXPORT
void lithium_misuse(void)
            __attribute__ ((noreturn));

#ifdef __cplusplus
}
#endif

#endif
