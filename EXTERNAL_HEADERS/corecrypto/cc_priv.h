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


// MARK: - Loads and Store

// MARK: -- 32 bits - little endian

// MARK: --- Default version

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

// MARK: -- 64 bits - little endian

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

// MARK: -- 32 bits - big endian
// MARK: --- intel version

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
// MARK: --- default version
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

// MARK: -- 64 bits - big endian

// MARK: --- intel 64 bits version

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

// MARK: --- default version

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

// MARK: - 32-bit Rotates

#if defined(_MSC_VER)
// MARK: -- MSVC version

#include <stdlib.h>
#pragma intrinsic(_lrotr,_lrotl)
#define	CC_ROR(x,n) _lrotr(x,n)
#define	CC_ROL(x,n) _lrotl(x,n)
#define	CC_RORc(x,n) _lrotr(x,n)
#define	CC_ROLc(x,n) _lrotl(x,n)

#elif (defined(__i386__) || defined(__x86_64__))
// MARK: -- intel asm version

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

// MARK: -- default version

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

// MARK: - 64 bits rotates

#if defined(__x86_64__)
// MARK: -- intel 64 asm version

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

// MARK: -- default C version

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


// MARK: - Byte Swaps

static inline uint32_t CC_BSWAP(uint32_t x)
{
    return (
        ((x>>24)&0x000000FF) |
        ((x<<24)&0xFF000000) |
        ((x>>8) &0x0000FF00) |
        ((x<<8) &0x00FF0000)
    );
}

#define CC_BSWAP64(x) \
((uint64_t)((((uint64_t)(x) & 0xff00000000000000ULL) >> 56) | \
(((uint64_t)(x) & 0x00ff000000000000ULL) >> 40) | \
(((uint64_t)(x) & 0x0000ff0000000000ULL) >> 24) | \
(((uint64_t)(x) & 0x000000ff00000000ULL) >>  8) | \
(((uint64_t)(x) & 0x00000000ff000000ULL) <<  8) | \
(((uint64_t)(x) & 0x0000000000ff0000ULL) << 24) | \
(((uint64_t)(x) & 0x000000000000ff00ULL) << 40) | \
(((uint64_t)(x) & 0x00000000000000ffULL) << 56)))

#ifdef __LITTLE_ENDIAN__
#define CC_H2BE32(x) CC_BSWAP(x)
#define CC_H2LE32(x) (x)
#else
#define CC_H2BE32(x) (x)
#define CC_H2LE32(x) CC_BSWAP(x)
#endif


/* extract a byte portably */
#ifdef _MSC_VER
#define cc_byte(x, n) ((unsigned char)((x) >> (8 * (n))))
#else
#define cc_byte(x, n) (((x) >> (8 * (n))) & 255)
#endif

/* HEAVISIDE_STEP (shifted by one)
   function f(x): x->0, when x=0 
                  x->1, when x>0
   Can also be seen as a bitwise operation: 
      f(x): x -> y
        y[0]=(OR x[i]) for all i (all bits)
        y[i]=0 for all i>0
   Run in constant time (log2(<bitsize of x>))  
   Useful to run constant time checks
*/
#define HEAVISIDE_STEP_UINT64(x) {unsigned long t; \
    t=(((uint64_t)x>>32) | (unsigned long)x); \
    t=((t>>16) | t); \
    t=((t>>8) | t); \
    t=((t>>4) | t); \
    t=((t>>2) | t); \
    t=((t>>1) | t); \
    x=t & 0x1;}

#define HEAVISIDE_STEP_UINT32(x) {uint16_t t; \
    t=(((unsigned long)x>>16) | (uint16_t)x); \
    t=((t>>8) | t); \
    t=((t>>4) | t); \
    t=((t>>2) | t); \
    t=((t>>1) | t); \
    x=t & 0x1;}

#define HEAVISIDE_STEP_UINT16(x) {uint8_t t; \
    t=(((uint16_t)x>>8) | (uint8_t)x); \
    t=((t>>4) | t); \
    t=((t>>2) | t); \
    t=((t>>1) | t); \
    x=t & 0x1;}

#define HEAVISIDE_STEP_UINT8(x) {uint8_t t; \
    t=(((uint8_t)x>>4) | (uint8_t)x); \
    t=((t>>2) | t); \
    t=((t>>1) | t); \
    x=t & 0x1;}

#define CC_HEAVISIDE_STEP(x) { \
    if (sizeof(x) == 1) {HEAVISIDE_STEP_UINT8(x);}  \
    else if (sizeof(x) == 2) {HEAVISIDE_STEP_UINT16(x);} \
    else if (sizeof(x) == 4) {HEAVISIDE_STEP_UINT32(x);} \
    else if (sizeof(x) == 8) {HEAVISIDE_STEP_UINT64(x);} \
    else {x=((x==0)?0:1);} \
    }


/* Set a variable to the biggest power of 2 which can be represented */ 
#define MAX_POWER_OF_2(x)   ((__typeof__(x))1<<(8*sizeof(x)-1))
 

#endif /* _CORECRYPTO_CC_PRIV_H_ */
