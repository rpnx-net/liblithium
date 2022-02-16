#ifndef __STDC_WANT_LIB_EXT1__
# define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <cstdint>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <cstddef>
#include <cstdint>
#include <stdlib.h>
#include <string.h>






#include "rubidium_generichash_blake2b.h"
#include "rubidium_stream.h"
#include "randombytes.h"
#include "private/common.h"
#include "utils.h"

#ifndef ENOSYS
# define ENOSYS ENXIO
#endif

#if defined(_WIN32) && \
    (!defined(WINAPI_FAMILY) || WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
# define WINAPI_DESKTOP
#endif

#define CANARY_SIZE 16U
#define GARBAGE_VALUE 0xdb

#ifndef MAP_NOCORE
# ifdef MAP_CONCEAL
#  define MAP_NOCORE MAP_CONCEAL
# else
#  define MAP_NOCORE 0
# endif
#endif
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
# define MAP_ANON MAP_ANONYMOUS
#endif
#if defined(WINAPI_DESKTOP) || (defined(MAP_ANON) && defined(HAVE_MMAP)) || \
    defined(HAVE_POSIX_MEMALIGN)
# define HAVE_ALIGNED_MALLOC
#endif
#if defined(HAVE_MPROTECT) && \
    !(defined(PROT_NONE) && defined(PROT_READ) && defined(PROT_WRITE))
# undef HAVE_MPROTECT
#endif
#if defined(HAVE_ALIGNED_MALLOC) && \
    (defined(WINAPI_DESKTOP) || defined(HAVE_MPROTECT))
# define HAVE_PAGE_PROTECTION
#endif
#if !defined(MADV_DODUMP) && defined(MADV_CORE)
# define MADV_DODUMP   MADV_CORE
# define MADV_DONTDUMP MADV_NOCORE
#endif



static unsigned char canary[CANARY_SIZE];

void
rubidium_memzero(void * const pnt, const std::size_t len)
{
    volatile unsigned char *volatile pnt_ =
        (volatile unsigned char *volatile) pnt;
    std::size_t i = (std::size_t) 0U;

    while (i < len) {
        pnt_[i++] = 0U;
    }
}

int
rubidium_memcmp(const void *const b1_, const void *const b2_, std::size_t len)
{
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
#else
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
#endif
    std::size_t                 i;
    volatile unsigned char d = 0U;

#if HAVE_WEAK_SYMBOLS
    _rubidium_dummy_symbol_to_prevent_memcmp_lto(b1, b2, len);
#endif
    for (i = 0U; i < len; i++) {
        d = d | (b1[i] ^ b2[i]);
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void
_rubidium_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1,
                                            const unsigned char *b2,
                                            const std::size_t         len);
__attribute__((weak)) void
_rubidium_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1,
                                            const unsigned char *b2,
                                            const std::size_t         len)
{
    (void) b1;
    (void) b2;
    (void) len;
}
#endif

int
rubidium_compare(const unsigned char *b1_, const unsigned char *b2_, std::size_t len)
{
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = b1_;
    const unsigned char *b2 = b2_;
#else
    const volatile unsigned char *volatile b1 =
        (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 =
        (const volatile unsigned char *volatile) b2_;
#endif
    std::size_t                 i;
    volatile unsigned char gt = 0U;
    volatile unsigned char eq = 1U;
    uint16_t               x1, x2;

#if HAVE_WEAK_SYMBOLS
    _rubidium_dummy_symbol_to_prevent_compare_lto(b1, b2, len);
#endif
    i = len;
    while (i != 0U) {
        i--;
        x1 = b1[i];
        x2 = b2[i];
        gt |= ((x2 - x1) >> 8) & eq;
        eq &= ((x2 ^ x1) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}

int
rubidium_is_zero(const unsigned char *n, const std::size_t nlen)
{
    std::size_t                 i;
    volatile unsigned char d = 0U;

    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}

void
rubidium_increment(unsigned char *n, const std::size_t nlen)
{
    std::size_t        i = 0U;
    uint_fast16_t c = 1U;

#ifdef HAVE_AMD64_ASM
    uint64_t t64, t64_2;
    uint32_t t32;

    if (nlen == 12U) {
        __asm__ __volatile__(
            "xorq %[t64], %[t64] \n"
            "xorl %[t32], %[t32] \n"
            "stc \n"
            "adcq %[t64], (%[out]) \n"
            "adcl %[t32], 8(%[out]) \n"
            : [t64] "=&r"(t64), [t32] "=&r"(t32)
            : [out] "D"(n)
            : "memory", "flags", "cc");
        return;
    } else if (nlen == 24U) {
        __asm__ __volatile__(
            "movq $1, %[t64] \n"
            "xorq %[t64_2], %[t64_2] \n"
            "addq %[t64], (%[out]) \n"
            "adcq %[t64_2], 8(%[out]) \n"
            "adcq %[t64_2], 16(%[out]) \n"
            : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2)
            : [out] "D"(n)
            : "memory", "flags", "cc");
        return;
    } else if (nlen == 8U) {
        __asm__ __volatile__("incq (%[out]) \n"
                             :
                             : [out] "D"(n)
                             : "memory", "flags", "cc");
        return;
    }
#endif
    for (; i < nlen; i++) {
        c += (uint_fast16_t) n[i];
        n[i] = (unsigned char) c;
        c >>= 8;
    }
}

void
rubidium_add(unsigned char *a, const unsigned char *b, const std::size_t len)
{
    std::size_t        i;
    uint_fast16_t c = 0U;

#ifdef HAVE_AMD64_ASM
    uint64_t t64, t64_2, t64_3;
    uint32_t t32;

    if (len == 12U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "movl 8(%[in]), %[t32] \n"
            "addq %[t64], (%[out]) \n"
            "adcl %[t32], 8(%[out]) \n"
            : [t64] "=&r"(t64), [t32] "=&r"(t32)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    } else if (len == 24U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "movq 8(%[in]), %[t64_2] \n"
            "movq 16(%[in]), %[t64_3] \n"
            "addq %[t64], (%[out]) \n"
            "adcq %[t64_2], 8(%[out]) \n"
            "adcq %[t64_3], 16(%[out]) \n"
            : [t64] "=&r"(t64), [t64_2] "=&r"(t64_2), [t64_3] "=&r"(t64_3)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    } else if (len == 8U) {
        __asm__ __volatile__(
            "movq (%[in]), %[t64] \n"
            "addq %[t64], (%[out]) \n"
            : [t64] "=&r"(t64)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    }
#endif
    for (i = 0U; i < len; i++) {
        c += (uint_fast16_t) a[i] + (uint_fast16_t) b[i];
        a[i] = (unsigned char) c;
        c >>= 8;
    }
}

void
rubidium_sub(unsigned char *a, const unsigned char *b, const std::size_t len)
{
    uint_fast16_t c = 0U;
    std::size_t        i;

#ifdef HAVE_AMD64_ASM
    uint64_t t64_1, t64_2, t64_3, t64_4;
    uint64_t t64_5, t64_6, t64_7, t64_8;
    uint32_t t32;

    if (len == 64U) {
        __asm__ __volatile__(
            "movq   (%[in]), %[t64_1] \n"
            "movq  8(%[in]), %[t64_2] \n"
            "movq 16(%[in]), %[t64_3] \n"
            "movq 24(%[in]), %[t64_4] \n"
            "movq 32(%[in]), %[t64_5] \n"
            "movq 40(%[in]), %[t64_6] \n"
            "movq 48(%[in]), %[t64_7] \n"
            "movq 56(%[in]), %[t64_8] \n"
            "subq %[t64_1],   (%[out]) \n"
            "sbbq %[t64_2],  8(%[out]) \n"
            "sbbq %[t64_3], 16(%[out]) \n"
            "sbbq %[t64_4], 24(%[out]) \n"
            "sbbq %[t64_5], 32(%[out]) \n"
            "sbbq %[t64_6], 40(%[out]) \n"
            "sbbq %[t64_7], 48(%[out]) \n"
            "sbbq %[t64_8], 56(%[out]) \n"
            : [t64_1] "=&r"(t64_1), [t64_2] "=&r"(t64_2), [t64_3] "=&r"(t64_3), [t64_4] "=&r"(t64_4),
              [t64_5] "=&r"(t64_5), [t64_6] "=&r"(t64_6), [t64_7] "=&r"(t64_7), [t64_8] "=&r"(t64_8)
            : [in] "S"(b), [out] "D"(a)
            : "memory", "flags", "cc");
        return;
    }
#endif
    for (i = 0U; i < len; i++) {
        c = (uint_fast16_t) a[i] - (uint_fast16_t) b[i] - c;
        a[i] = (unsigned char) c;
        c = (c >> 8) & 1U;
    }
}

int
_rubidium_alloc_init(void)
{
#ifdef HAVE_ALIGNED_MALLOC
# if defined(_SC_PAGESIZE) && defined(HAVE_SYSCONF)
    long page_size_ = sysconf(_SC_PAGESIZE);
    if (page_size_ > 0L) {
        page_size = (std::size_t) page_size_;
    }
# elif defined(WINAPI_DESKTOP)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    page_size = (std::size_t) si.dwPageSize;
# elif !defined(PAGE_SIZE)
#  warning Unknown page size
# endif
    if (page_size < CANARY_SIZE || page_size < sizeof(std::size_t)) {
        throw std::invalid_argument(""); /* LCOV_EXCL_LINE */
    }
#endif
    randombytes_buf(canary, CANARY_SIZE);

    return 0;
}

int
rubidium_mlock(void *const addr, const std::size_t len)
{
#if defined(MADV_DONTDUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DONTDUMP);
#endif
#ifdef HAVE_MLOCK
    return mlock(addr, len);
#elif defined(WINAPI_DESKTOP)
    return -(VirtualLock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int
rubidium_munlock(void *const addr, const std::size_t len)
{
    rubidium_memzero(addr, len);
#if defined(MADV_DODUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DODUMP);
#endif
#ifdef HAVE_MLOCK
    return munlock(addr, len);
#elif defined(WINAPI_DESKTOP)
    return -(VirtualUnlock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_noaccess(void *ptr, std::size_t size)
{
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_NONE);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_NOACCESS, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_readonly(void *ptr, std::size_t size)
{
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READONLY, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int
_mprotect_readwrite(void *ptr, std::size_t size)
{
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READWRITE, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

#ifdef HAVE_ALIGNED_MALLOC

__attribute__((noreturn)) static void
_out_of_bounds(void)
{
# if defined(HAVE_RAISE) && !defined(__wasm__)
#  ifdef SIGSEGV
    raise(SIGSEGV);
#  elif defined(SIGKILL)
    raise(SIGKILL);
#  endif
# endif
    abort(); /* not something we want any higher-level API to catch */
} /* LCOV_EXCL_LINE */

static inline std::size_t
_page_round(const std::size_t size)
{
    const std::size_t page_mask = page_size - 1U;

    return (size + page_mask) & ~page_mask;
}

static __attribute__((malloc)) unsigned char *
_alloc_aligned(const std::size_t size)
{
    void *ptr;

# if defined(MAP_ANON) && defined(HAVE_MMAP)
    if ((ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) ==
        MAP_FAILED) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    }               /* LCOV_EXCL_LINE */
# elif defined(HAVE_POSIX_MEMALIGN)
    if (posix_memalign(&ptr, page_size, size) != 0) {
        ptr = NULL; /* LCOV_EXCL_LINE */
    }               /* LCOV_EXCL_LINE */
# elif defined(WINAPI_DESKTOP)
    ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
# else
#  error Bug
# endif
    return (unsigned char *) ptr;
}

static void
_free_aligned(unsigned char *const ptr, const std::size_t size)
{
# if defined(MAP_ANON) && defined(HAVE_MMAP)
    (void) munmap(ptr, size);
# elif defined(HAVE_POSIX_MEMALIGN)
    free(ptr);
# elif defined(WINAPI_DESKTOP)
    VirtualFree(ptr, 0U, MEM_RELEASE);
# else
#  error Bug
#endif
}

static unsigned char *
_unprotected_ptr_from_user_ptr(void *const ptr)
{
    uintptr_t      unprotected_ptr_u;
    unsigned char *canary_ptr;
    std::size_t         page_mask;

    canary_ptr = ((unsigned char *) ptr) - sizeof canary;
    page_mask = page_size - 1U;
    unprotected_ptr_u = ((uintptr_t) canary_ptr & (uintptr_t) ~page_mask);
    if (unprotected_ptr_u <= page_size * 2U) {
        throw std::invalid_argument(""); /* LCOV_EXCL_LINE */
    }
    return (unsigned char *) unprotected_ptr_u;
}

#endif /* HAVE_ALIGNED_MALLOC */

#ifndef HAVE_ALIGNED_MALLOC
static __attribute__((malloc)) void *
_rubidium_malloc(const std::size_t size)
{
    return malloc(size > (std::size_t) 0U ? size : (std::size_t) 1U);
}
#else
static __attribute__((malloc)) void *
_rubidium_malloc(const std::size_t size)
{
    void          *user_ptr;
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    std::size_t         size_with_canary;
    std::size_t         total_size;
    std::size_t         unprotected_size;

    if (size >= (std::size_t) SIZE_MAX - page_size * 4U) {
        errno = ENOMEM;
        return NULL;
    }
    if (page_size <= sizeof canary || page_size < sizeof unprotected_size) {
        throw std::invalid_argument(""); /* LCOV_EXCL_LINE */
    }
    size_with_canary = (sizeof canary) + size;
    unprotected_size = _page_round(size_with_canary);
    total_size       = page_size + page_size + unprotected_size + page_size;
    if ((base_ptr = _alloc_aligned(total_size)) == NULL) {
        return NULL; /* LCOV_EXCL_LINE */
    }
    unprotected_ptr = base_ptr + page_size * 2U;
    _mprotect_noaccess(base_ptr + page_size, page_size);
# ifndef HAVE_PAGE_PROTECTION
    memcpy(unprotected_ptr + unprotected_size, canary, sizeof canary);
# endif
    _mprotect_noaccess(unprotected_ptr + unprotected_size, page_size);
    rubidium_mlock(unprotected_ptr, unprotected_size);
    canary_ptr =
        unprotected_ptr + _page_round(size_with_canary) - size_with_canary;
    user_ptr = canary_ptr + sizeof canary;
    memcpy(canary_ptr, canary, sizeof canary);
    memcpy(base_ptr, &unprotected_size, sizeof unprotected_size);
    _mprotect_readonly(base_ptr, page_size);
    assert(_unprotected_ptr_from_user_ptr(user_ptr) == unprotected_ptr);

    return user_ptr;
}
#endif /* !HAVE_ALIGNED_MALLOC */

__attribute__((malloc)) void *
rubidium_malloc(const std::size_t size)
{
    void *ptr;

    if ((ptr = _rubidium_malloc(size)) == NULL) {
        return NULL;
    }
    memset(ptr, (int) GARBAGE_VALUE, size);

    return ptr;
}

__attribute__((malloc)) void *
rubidium_allocarray(std::size_t count, std::size_t size)
{
    if (count > (std::size_t) 0U && size >= (std::size_t) SIZE_MAX / count) {
        errno = ENOMEM;
        return NULL;
    }
    return rubidium_malloc(count * size);
}

#ifndef HAVE_ALIGNED_MALLOC
void
rubidium_free(void *ptr)
{
    free(ptr);
}
#else
void
rubidium_free(void *ptr)
{
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    std::size_t         total_size;
    std::size_t         unprotected_size;

    if (ptr == NULL) {
        return;
    }
    canary_ptr      = ((unsigned char *) ptr) - sizeof canary;
    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);
    total_size = page_size + page_size + unprotected_size + page_size;
    _mprotect_readwrite(base_ptr, total_size);
    if (rubidium_memcmp(canary_ptr, canary, sizeof canary) != 0) {
        _out_of_bounds();
    }
# ifndef HAVE_PAGE_PROTECTION
    if (rubidium_memcmp(unprotected_ptr + unprotected_size, canary,
                      sizeof canary) != 0) {
        _out_of_bounds();
    }
# endif
    rubidium_munlock(unprotected_ptr, unprotected_size);
    _free_aligned(base_ptr, total_size);
}
#endif /* HAVE_ALIGNED_MALLOC */

#ifndef HAVE_PAGE_PROTECTION
static int
_rubidium_mprotect(void *ptr, int (*cb)(void *ptr, std::size_t size))
{
    (void) ptr;
    (void) cb;
    errno = ENOSYS;
    return -1;
}
#else
static int
_rubidium_mprotect(void *ptr, int (*cb)(void *ptr, std::size_t size))
{
    unsigned char *base_ptr;
    unsigned char *unprotected_ptr;
    std::size_t         unprotected_size;

    unprotected_ptr = _unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);

    return cb(unprotected_ptr, unprotected_size);
}
#endif

int
rubidium_mprotect_noaccess(void *ptr)
{
    return _rubidium_mprotect(ptr, _mprotect_noaccess);
}

int
rubidium_mprotect_readonly(void *ptr)
{
    return _rubidium_mprotect(ptr, _mprotect_readonly);
}

int
rubidium_mprotect_readwrite(void *ptr)
{
    return _rubidium_mprotect(ptr, _mprotect_readwrite);
}

int
rubidium_pad(std::size_t *padded_buflen_p, unsigned char *buf,
           std::size_t unpadded_buflen, std::size_t blocksize, std::size_t max_buflen)
{
    unsigned char          *tail;
    std::size_t                  i;
    std::size_t                  xpadlen;
    std::size_t                  xpadded_len;
    volatile unsigned char  mask;
    unsigned char           barrier_mask;

    if (blocksize <= 0U) {
        return -1;
    }
    xpadlen = blocksize - 1U;
    if ((blocksize & (blocksize - 1U)) == 0U) {
        xpadlen -= unpadded_buflen & (blocksize - 1U);
    } else {
        xpadlen -= unpadded_buflen % blocksize;
    }
    if ((std::size_t) SIZE_MAX - unpadded_buflen <= xpadlen) {
        throw std::invalid_argument("");
    }
    xpadded_len = unpadded_buflen + xpadlen;
    if (xpadded_len >= max_buflen) {
        return -1;
    }
    tail = &buf[xpadded_len];
    if (padded_buflen_p != NULL) {
        *padded_buflen_p = xpadded_len + 1U;
    }
    mask = 0U;
    for (i = 0; i < blocksize; i++) {
        barrier_mask = (unsigned char) (((i ^ xpadlen) - 1U)
           >> ((sizeof(std::size_t) - 1) * CHAR_BIT));
        *(tail - i) = ((*(tail - i)) & mask) | (0x80 & barrier_mask);
        mask |= barrier_mask;
    }
    return 0;
}

int
rubidium_unpad(std::size_t *unpadded_buflen_p, const unsigned char *buf,
             std::size_t padded_buflen, std::size_t blocksize)
{
    const unsigned char *tail;
    unsigned char        acc = 0U;
    unsigned char        c;
    unsigned char        valid = 0U;
    volatile std::size_t      pad_len = 0U;
    std::size_t               i;
    std::size_t               is_barrier;

    if (padded_buflen < blocksize || blocksize <= 0U) {
        return -1;
    }
    tail = &buf[padded_buflen - 1U];

    for (i = 0U; i < blocksize; i++) {
        c = *(tail - i);
        is_barrier =
            (( (acc - 1U) & (pad_len - 1U) & ((c ^ 0x80) - 1U) ) >> 8) & 1U;
        acc |= c;
        pad_len = pad_len | ( i & (1U + ~is_barrier));
        valid |= (unsigned char) is_barrier;
    }
    *unpadded_buflen_p = padded_buflen - 1U - pad_len;

    return (int) (valid - 1U);
}
