#ifndef mutex_H
#define mutex_H 1

#include "private/quirks.h"

extern int lithium_crit_enter(void);
extern int lithium_crit_leave(void);

#endif
