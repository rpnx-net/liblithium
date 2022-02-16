
#ifndef export_H
#define export_H

#include <cstddef>
#include <cstdint>
#include <limits.h>

#if !defined(__clang__) && !defined(__GNUC__)
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif


#ifndef RUBIDIUM_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define RUBIDIUM_ALIGN(x) __declspec(align(x))
# else
#  define RUBIDIUM_ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif

#define RUBIDIUM_MIN(A, B) ((A) < (B) ? (A) : (B))
#define RUBIDIUM_SIZE_MAX RUBIDIUM_MIN(UINT64_MAX, SIZE_MAX)

#endif
