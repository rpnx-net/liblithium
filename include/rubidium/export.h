
#ifndef rubidium_export_H
#define rubidium_export_H

#include <cstddef>
#include <cstdint>
#include <limits.h>

#if !defined(__clang__) && !defined(__GNUC__)
# ifdef __attribute__
#  undef __attribute__
# endif
# define __attribute__(a)
#endif

#ifdef RUBIDIUM_STATIC
# define RUBIDIUM_EXPORT
# define RUBIDIUM_EXPORT_WEAK
#else
# if defined(_MSC_VER)
#  ifdef RUBIDIUM_DLL_EXPORT
#   define RUBIDIUM_EXPORT __declspec(dllexport)
#  else
#   define RUBIDIUM_EXPORT __declspec(dllimport)
#  endif
# else
#  if defined(__SUNPRO_C)
#   ifndef __GNU_C__
#    define RUBIDIUM_EXPORT __attribute__ (visibility(__global))
#   else
#    define RUBIDIUM_EXPORT __attribute__ __global
#   endif
#  elif defined(_MSG_VER)
#   define RUBIDIUM_EXPORT extern __declspec(dllexport)
#  else
#   define RUBIDIUM_EXPORT __attribute__ ((visibility ("default")))
#  endif
# endif
# if defined(__ELF__) && !defined(RUBIDIUM_DISABLE_WEAK_FUNCTIONS)
#  define RUBIDIUM_EXPORT_WEAK RUBIDIUM_EXPORT __attribute__((weak))
# else
#  define RUBIDIUM_EXPORT_WEAK RUBIDIUM_EXPORT
# endif
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
