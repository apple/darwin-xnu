// vim:noexpandtab
#ifndef __TYPES_H__
#define __TYPES_H__

#include <stdint.h>
#include <stdbool.h>

typedef signed char     s8;
typedef unsigned char   u8;
typedef uint16_t        u16;
typedef int16_t         s16;
typedef uint32_t        u32;
typedef uint64_t        u64;
typedef int32_t         s32;
typedef int64_t         s64;

#if defined(__arm64__) || defined(__x86_64__)
typedef u64     un;
typedef s64     sn;
#else
typedef u32     un;
typedef s32     sn;
#endif

#ifndef __DRT_H__
typedef u32     uint;
#endif

#define volatile_read(atom)             (*((volatile typeof(*(atom)) *)(atom)))
#define volatile_write(atom, value)     (*((volatile typeof(*(atom)) *)(atom)) = value)

#endif
