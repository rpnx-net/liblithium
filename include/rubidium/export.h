
#ifndef lithium_export_H
#define lithium_export_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#if !defined(__clang__) && !defined(__GNUC__)
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

#ifdef LITHIUM_STATIC
# define LITHIUM_EXPORT
# define LITHIUM_EXPORT_WEAK
#else
# if defined(_MSC_VER)
#  ifdef LITHIUM_DLL_EXPORT
#   define LITHIUM_EXPORT __declspec(dllexport)
#  else
#   define LITHIUM_EXPORT __declspec(dllimport)
#  endif
# else
#  if defined(__SUNPRO_C)
#   ifndef __GNU_C__
#    define LITHIUM_EXPORT __attribute__ (visibility(__global))
#   else
#    define LITHIUM_EXPORT __attribute__ __global
#   endif
#  elif defined(_MSG_VER)
#   define LITHIUM_EXPORT extern __declspec(dllexport)
#  else
#   define LITHIUM_EXPORT __attribute__ ((visibility ("default")))
#  endif
# endif
# if defined(__ELF__) && !defined(LITHIUM_DISABLE_WEAK_FUNCTIONS)
#  define LITHIUM_EXPORT_WEAK LITHIUM_EXPORT __attribute__((weak))
# else
#  define LITHIUM_EXPORT_WEAK LITHIUM_EXPORT
# endif
#endif

#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif

#define LITHIUM_MIN(A, B) ((A) < (B) ? (A) : (B))
#define LITHIUM_SIZE_MAX LITHIUM_MIN(UINT64_MAX, SIZE_MAX)

#endif
