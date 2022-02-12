
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
# include <windows.h>
#elif defined(HAVE_PTHREAD)
# include <pthread.h>
#endif

#include "core.h"
#include "crypto_generichash.h"
#include "crypto_onetimeauth.h"
#include "crypto_scalarmult.h"
#include "crypto_stream_chacha20.h"
#include "crypto_stream_salsa20.h"
#include "randombytes.h"
#include "runtime.h"
#include "utils.h"
#include "private/implementations.h"
#include "private/mutex.h"
#include <mutex>

static std::atomic<bool> initialized;
static std::recursive_mutex lock;

int
sodium_init(void)
{
    if (sodium_crit_enter() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    if (initialized != 0) {
        if (sodium_crit_leave() != 0) {
            return -1; /* LCOV_EXCL_LINE */
        }
        return 1;
    }
    _sodium_runtime_get_cpu_features();
    randombytes_stir();
    _sodium_alloc_init();
    _crypto_pwhash_argon2_pick_best_implementation();
    _crypto_generichash_blake2b_pick_best_implementation();
    _crypto_onetimeauth_poly1305_pick_best_implementation();
    _crypto_scalarmult_curve25519_pick_best_implementation();
    _crypto_stream_chacha20_pick_best_implementation();
    _crypto_stream_salsa20_pick_best_implementation();
    initialized = 1;
    if (sodium_crit_leave() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}


int
sodium_crit_enter(void)
{
    lock.lock();
    return 0;
}

int
sodium_crit_leave(void)
{
    lock.unlock();
    return 0;
}


static void (*_misuse_handler)(void);

void
sodium_misuse(void)
{
    void (*handler)(void);

    (void) sodium_crit_leave();
    if (sodium_crit_enter() == 0) {
        handler = _misuse_handler;
        if (handler != NULL) {
            handler();
        }
    }
/* LCOV_EXCL_START */
    abort();
}
/* LCOV_EXCL_STOP */

int
sodium_set_misuse_handler(void (*handler)(void))
{
    if (sodium_crit_enter() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _misuse_handler = handler;
    if (sodium_crit_leave() != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    return 0;
}

#if defined(_WIN32) && !defined(SODIUM_STATIC)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void) hinstDLL;
    (void) lpReserved;

    if (fdwReason == DLL_PROCESS_DETACH && _sodium_lock_initialized == 2) {
        DeleteCriticalSection(&_sodium_lock);
    }
    return TRUE;
}
#endif
