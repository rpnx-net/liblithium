
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
# include <windows.h>
#endif

#include "core.h"
#include "rubidium_generichash_blake2b.h"
#include "rubidium_onetimeauth.h"
#include "rubidium_scalarmult.h"
#include "rubidium_stream_chacha20.h"
#include "rubidium_stream_salsa20.h"
#include "randombytes.h"
#include "runtime.h"
#include "utils.h"
#include "private/implementations.h"
#include "private/mutex.h"
#include <mutex>

static std::atomic<bool> initialized;
static std::recursive_mutex lock;

int
rubidium_init(void)
{
    if (rubidium_crit_enter() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    if (initialized != 0) {
        if (rubidium_crit_leave() != 0) {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 1;
    }
    _rubidium_runtime_get_cpu_features();
    randombytes_stir();
    _rubidium_alloc_init();
    _rubidium_pwhash_argon2_pick_best_implementation();
    _rubidium_generichash_blake2b_pick_best_implementation();
    _rubidium_onetimeauth_poly1305_pick_best_implementation();
    _rubidium_scalarmult_curve25519_pick_best_implementation();
    _rubidium_stream_chacha20_pick_best_implementation();
    _rubidium_stream_salsa20_pick_best_implementation();
    initialized = 1;
    if (rubidium_crit_leave() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}


int
rubidium_crit_enter(void)
{
    lock.lock();
    return 0;
}

int
rubidium_crit_leave(void)
{
    lock.unlock();
    return 0;
}


static void (*_misuse_handler)(void);

void
rubidium_misuse(void)
{
    void (*handler)(void);

    (void) rubidium_crit_leave();
    if (rubidium_crit_enter() == 0) {
        handler = _misuse_handler;
        if (handler != NULL) {
            handler();
        }
    }
    abort();
}
int
rubidium_set_misuse_handler(void (*handler)(void))
{
    if (rubidium_crit_enter() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _misuse_handler = handler;
    if (rubidium_crit_leave() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}

#if defined(_WIN32) && !defined(RUBIDIUM_STATIC)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void) hinstDLL;
    (void) lpReserved;

    if (fdwReason == DLL_PROCESS_DETACH && _rubidium_lock_initialized == 2) {
        DeleteCriticalSection(&_rubidium_lock);
    }
    return TRUE;
}
#endif
