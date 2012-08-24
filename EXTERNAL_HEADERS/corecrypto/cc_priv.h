/*
 *  cc_priv.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/1/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CC_PRIV_H_
#define _CORECRYPTO_CC_PRIV_H_

#include <corecrypto/cc.h>
#include <stdint.h>

/* defines the following macros :

 CC_MEMCPY  : optimized memcpy.
 CC_MEMMOVE : optimized memmove.
 CC_MEMSET  : optimized memset.
 CC_BZERO   : optimized bzero.

 CC_STORE32_BE : store 32 bit value in big endian in unaligned buffer.
 CC_STORE32_LE : store 32 bit value in little endian in unaligned buffer.
 CC_STORE64_BE : store 64 bit value in big endian in unaligned buffer.
 CC_STORE64_LE : store 64 bit value in little endian in unaligned buffer.

 CC_LOAD32_BE : load 32 bit value in big endian from unaligned buffer.
 CC_LOAD32_LE : load 32 bit value in little endian from unaligned buffer.
 CC_LOAD64_BE : load 64 bit value in big endian from unaligned buffer.
 CC_LOAD64_LE : load 64 bit value in little endian from unaligned buffer.

 CC_ROR  : Rotate Right 32 bits. Rotate count can be a variable.
 CC_ROL  : Rotate Left 32 bits. Rotate count can be a variable.
 CC_RORc : Rotate Right 32 bits. Rotate count must be a constant.
 CC_ROLc : Rotate Left 32 bits. Rotate count must be a constant.

 CC_ROR64  : Rotate Right 64 bits. Rotate count can be a variable.
 CC_ROL64  : Rotate Left 64 bits. Rotate count can be a variable.
 CC_ROR64c : Rotate Right 64 bits. Rotate count must be a constant.
 CC_ROL64c : Rotate Left 64 bits. Rotate count must be a constant.

 CC_BSWAP  : byte swap a 32 bits variable.

 CC_H2BE32 : convert a 32 bits value between host and big endian order.
 CC_H2LE32 : convert a 32 bits value between host and little endian order.

The following are not defined yet... define them if needed.

 CC_BSWAPc   : byte swap a 32 bits constant

 CC_BSWAP64  : byte swap a 64 bits variable
 CC_BSWAP64c : byte swap a 64 bits constant

 CC_READ_LE32 : read a 32 bits little endian value
 CC_READ_LE64 : read a 64 bits little endian value
 CC_READ_BE32 : read a 32 bits big endian value
 CC_READ_BE64 : read a 64 bits big endian value

 CC_WRITE_LE32 : write a 32 bits little endian value
 CC_WRITE_LE64 : write a 64 bits little endian value
 CC_WRITE_BE32 : write a 32 bits big endian value
 CC_WRITE_BE64 : write a 64 bits big endian value

 CC_H2BE64 : convert a 64 bits value between host and big endian order
 CC_H2LE64 : convert a 64 bits value between host and little endian order
 
*/

/* TODO: optimized versions */
#define CC_MEMCPY(D,S,L) memcpy((D),(S),(L))
#define CC_MEMMOVE(D,S,L) memmove((D),(S),(L))
#define CC_MEMSET(D,V,L) memset((D),(V),(L))
#define CC_BZERO(D,L) memset((D),0,(L))


#pragma mark - Loads and Store

#pragma mark -- 32 bits - little endian

#pragma mark --- Default version

#define	CC_STORE32_LE(x, y) do {                                    \
    ((unsigned char *)(y))[3] = (unsigned char)(((x)>>24)&255);		\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>16)&255);		\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>8)&255);		\
    ((unsigned char *)(y))[0] = (unsigned char)((x)&255);			\
} while(0)

#define	CC_LOAD32_LE(x, y) do {                                     \
x = ((uint32_t)(((unsigned char *)(y))[3] & 255)<<24) |			    \
    ((uint32_t)(((unsigned char *)(y))[2] & 255)<<16) |			    \
    ((uint32_t)(((unsigned char *)(y))[1] & 255)<<8)  |			    \
    ((uint32_t)(((unsigned char *)(y))[0] & 255));				    \
} while(0)

#pragma mark -- 64 bits - little endian

#define	CC_STORE64_LE(x, y) do {                                    \
    ((unsigned char *)(y))[7] = (unsigned char)(((x)>>56)&255);     \
    ((unsigned char *)(y))[6] = (unsigned char)(((x)>>48)&255);		\
    ((unsigned char *)(y))[5] = (unsigned char)(((x)>>40)&255);		\
    ((unsigned char *)(y))[4] = (unsigned char)(((x)>>32)&255);		\
    ((unsigned char *)(y))[3] = (unsigned char)(((x)>>24)&255);		\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>16)&255);		\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>8)&255);		\
    ((unsigned char *)(y))[0] = (unsigned char)((x)&255);			\
} while(0)

#define	CC_LOAD64_LE(x, y) do {                                     \
x = (((uint64_t)(((unsigned char *)(y))[7] & 255))<<56) |           \
    (((uint64_t)(((unsigned char *)(y))[6] & 255))<<48) |           \
    (((uint64_t)(((unsigned char *)(y))[5] & 255))<<40) |           \
    (((uint64_t)(((unsigned char *)(y))[4] & 255))<<32) |           \
    (((uint64_t)(((unsigned char *)(y))[3] & 255))<<24) |           \
    (((uint64_t)(((unsigned char *)(y))[2] & 255))<<16) |           \
    (((uint64_t)(((unsigned char *)(y))[1] & 255))<<8)  |           \
    (((uint64_t)(((unsigned char *)(y))[0] & 255)));                \
} while(0)

#pragma mark -- 32 bits - big endian
#pragma mark --- intel version

#if (defined(__i386__) || defined(__x86_64__))

#define CC_STORE32_BE(x, y)     \
    __asm__ __volatile__ (      \
    "bswapl %0     \n\t"        \
    "movl   %0,(%1)\n\t"        \
    "bswapl %0     \n\t"        \
    ::"r"(x), "r"(y))

#define CC_LOAD32_BE(x, y)      \
    __asm__ __volatile__ (      \
    "movl (%1),%0\n\t"          \
    "bswapl %0\n\t"             \
    :"=r"(x): "r"(y))

#else
#pragma mark --- default version
#define	CC_STORE32_BE(x, y) do {                                \
    ((unsigned char *)(y))[0] = (unsigned char)(((x)>>24)&255);	\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>16)&255);	\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>8)&255);	\
    ((unsigned char *)(y))[3] = (unsigned char)((x)&255);       \
} while(0)

#define	CC_LOAD32_BE(x, y) do {                             \
x = ((uint32_t)(((unsigned char *)(y))[0] & 255)<<24) |	    \
    ((uint32_t)(((unsigned char *)(y))[1] & 255)<<16) |		\
    ((uint32_t)(((unsigned char *)(y))[2] & 255)<<8)  |		\
    ((uint32_t)(((unsigned char *)(y))[3] & 255));          \
} while(0)

#endif

#pragma mark -- 64 bits - big endian

#pragma mark --- intel 64 bits version

#if defined(__x86_64__)

#define	CC_STORE64_BE(x, y)   \
__asm__ __volatile__ (        \
"bswapq %0     \n\t"          \
"movq   %0,(%1)\n\t"          \
"bswapq %0     \n\t"          \
::"r"(x), "r"(y))

#define	CC_LOAD64_BE(x, y)    \
__asm__ __volatile__ (        \
"movq (%1),%0\n\t"            \
"bswapq %0\n\t"               \
:"=r"(x): "r"(y))

#else

#pragma mark --- default version

#define CC_STORE64_BE(x, y) do {                                    \
    ((unsigned char *)(y))[0] = (unsigned char)(((x)>>56)&255);		\
    ((unsigned char *)(y))[1] = (unsigned char)(((x)>>48)&255);		\
    ((unsigned char *)(y))[2] = (unsigned char)(((x)>>40)&255);		\
    ((unsigned char *)(y))[3] = (unsigned char)(((x)>>32)&255);		\
    ((unsigned char *)(y))[4] = (unsigned char)(((x)>>24)&255);		\
    ((unsigned char *)(y))[5] = (unsigned char)(((x)>>16)&255);		\
    ((unsigned char *)(y))[6] = (unsigned char)(((x)>>8)&255);		\
    ((unsigned char *)(y))[7] = (unsigned char)((x)&255);			\
} while(0)

#define	CC_LOAD64_BE(x, y) do {                                     \
x = (((uint64_t)(((unsigned char *)(y))[0] & 255))<<56) |           \
    (((uint64_t)(((unsigned char *)(y))[1] & 255))<<48) |           \
    (((uint64_t)(((unsigned char *)(y))[2] & 255))<<40) |           \
    (((uint64_t)(((unsigned char *)(y))[3] & 255))<<32) |           \
    (((uint64_t)(((unsigned char *)(y))[4] & 255))<<24) |           \
    (((uint64_t)(((unsigned char *)(y))[5] & 255))<<16) |           \
    (((uint64_t)(((unsigned char *)(y))[6] & 255))<<8)  |          	\
    (((uint64_t)(((unsigned char *)(y))[7] & 255)));	            \
} while(0)

#endif

#pragma mark - 32-bit Rotates

#if defined(_MSC_VER)
#pragma mark -- MSVC version

#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define	CC_ROR(x,n) _lrotr(x,n)
#define	CC_ROL(x,n) _lrotl(x,n)
#define	CC_RORc(x,n) _lrotr(x,n)
#define	CC_ROLc(x,n) _lrotl(x,n)

#elif (defined(__i386__) || defined(__x86_64__))
#pragma mark -- intel asm version

static inline uint32_t CC_ROL(uint32_t word, int i)
{
    __asm__ ("roll %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

static inline uint32_t CC_ROR(uint32_t word, int i)
{
    __asm__ ("rorl %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

/* Need to be a macro here, because 'i' is an immediate (constant) */
#define CC_ROLc(word, i)                \
({  uint32_t _word=(word);              \
    __asm__ __volatile__ ("roll %2,%0"  \
        :"=r" (_word)                   \
        :"0" (_word),"I" (i));          \
    _word;                              \
})


#define CC_RORc(word, i)                \
({  uint32_t _word=(word);              \
    __asm__ __volatile__ ("rorl %2,%0"  \
        :"=r" (_word)                   \
        :"0" (_word),"I" (i));          \
    _word;                              \
})

#else

#pragma mark -- default version

static inline uint32_t CC_ROL(uint32_t word, int i)
{
    return ( (word<<(i&31)) | (word>>(32-(i&31))) );
}

static inline uint32_t CC_ROR(uint32_t word, int i)
{
    return ( (word>>(i&31)) | (word<<(32-(i&31))) );
}

#define	CC_ROLc(x, y) CC_ROL(x, y)
#define	CC_RORc(x, y) CC_ROR(x, y)

#endif

#pragma mark - 64 bits rotates

#if defined(__x86_64__)
#pragma mark -- intel 64 asm version

static inline uint64_t CC_ROL64(uint64_t word, int i)
{
    __asm__("rolq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

static inline uint64_t CC_ROR64(uint64_t word, int i)
{
    __asm__("rorq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

/* Need to be a macro here, because 'i' is an immediate (constant) */
#define CC_ROL64c(word, i)      \
({                              \
    uint64_t _word=(word);      \
    __asm__("rolq %2,%0"        \
        :"=r" (_word)           \
        :"0" (_word),"J" (i));  \
    _word;                      \
})

#define CC_ROR64c(word, i)      \
({                              \
    uint64_t _word=(word);      \
    __asm__("rorq %2,%0"        \
        :"=r" (_word)           \
        :"0" (_word),"J" (i));  \
    _word;                      \
})


#else /* Not x86_64  */

#pragma mark -- default C version

static inline uint64_t CC_ROL64(uint64_t word, int i)
{
    return ( (word<<(i&63)) | (word>>(64-(i&63))) );
}

static inline uint64_t CC_ROR64(uint64_t word, int i)
{
    return ( (word>>(i&63)) | (word<<(64-(i&63))) );
}

#define	CC_ROL64c(x, y) CC_ROL64(x, y)
#define	CC_ROR64c(x, y) CC_ROR64(x, y)

#endif


#pragma mark - Byte Swaps

static inline uint32_t CC_BSWAP(uint32_t x)
{
    return (
        ((x>>24)&0x000000FF) |
        ((x<<24)&0xFF000000) |
        ((x>>8) &0x0000FF00) |
        ((x<<8) &0x00FF0000)
    );
}

#ifdef __LITTLE_ENDIAN__
#define CC_H2BE32(x) CC_BSWAP(x)
#define CC_H2LE32(x) (x)
#else
#error not good.
#define CC_H2BE32(x) (x)
#define CC_H2LE32(x) CC_BSWAP(x)
#endif


/* extract a byte portably */
#ifdef _MSC_VER
#define cc_byte(x, n) ((unsigned char)((x) >> (8 * (n))))
#else
#define cc_byte(x, n) (((x) >> (8 * (n))) & 255)
#endif

#endif /* _CORECRYPTO_CC_PRIV_H_ */
