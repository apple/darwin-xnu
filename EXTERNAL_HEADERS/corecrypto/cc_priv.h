/*
 *  cc_priv.h
 *  corecrypto
 *
 *  Created on 12/01/2010
 *
 *  Copyright (c) 2010,2011,2012,2014,2015 Apple Inc. All rights reserved.
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

 CC_WRITE_LE32 : write a 32 bits little endian value
 CC_WRITE_LE64 : write a 64 bits little endian value

 CC_H2BE64 : convert a 64 bits value between host and big endian order
 CC_H2LE64 : convert a 64 bits value between host and little endian order

*/

/* TODO: optimized versions */
#define CC_MEMCPY(D,S,L) memcpy((D),(S),(L))
#define CC_MEMMOVE(D,S,L) memmove((D),(S),(L))
#define CC_MEMSET(D,V,L) memset((D),(V),(L))

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
x = ((uint32_t)(((const unsigned char *)(y))[3] & 255)<<24) |			    \
    ((uint32_t)(((const unsigned char *)(y))[2] & 255)<<16) |			    \
    ((uint32_t)(((const unsigned char *)(y))[1] & 255)<<8)  |			    \
    ((uint32_t)(((const unsigned char *)(y))[0] & 255));				    \
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
x = (((uint64_t)(((const unsigned char *)(y))[7] & 255))<<56) |           \
    (((uint64_t)(((const unsigned char *)(y))[6] & 255))<<48) |           \
    (((uint64_t)(((const unsigned char *)(y))[5] & 255))<<40) |           \
    (((uint64_t)(((const unsigned char *)(y))[4] & 255))<<32) |           \
    (((uint64_t)(((const unsigned char *)(y))[3] & 255))<<24) |           \
    (((uint64_t)(((const unsigned char *)(y))[2] & 255))<<16) |           \
    (((uint64_t)(((const unsigned char *)(y))[1] & 255))<<8)  |           \
    (((uint64_t)(((const unsigned char *)(y))[0] & 255)));                \
} while(0)

// MARK: -- 32 bits - big endian
// MARK: --- intel version

#if (defined(__i386__) || defined(__x86_64__)) && !defined(_MSC_VER)

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
x = ((uint32_t)(((const unsigned char *)(y))[0] & 255)<<24) |	    \
    ((uint32_t)(((const unsigned char *)(y))[1] & 255)<<16) |		\
    ((uint32_t)(((const unsigned char *)(y))[2] & 255)<<8)  |		\
    ((uint32_t)(((const unsigned char *)(y))[3] & 255));          \
} while(0)

#endif

// MARK: -- 64 bits - big endian

// MARK: --- intel 64 bits version

#if defined(__x86_64__) && !defined (_MSC_VER)

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
x = (((uint64_t)(((const unsigned char *)(y))[0] & 255))<<56) |           \
    (((uint64_t)(((const unsigned char *)(y))[1] & 255))<<48) |           \
    (((uint64_t)(((const unsigned char *)(y))[2] & 255))<<40) |           \
    (((uint64_t)(((const unsigned char *)(y))[3] & 255))<<32) |           \
    (((uint64_t)(((const unsigned char *)(y))[4] & 255))<<24) |           \
    (((uint64_t)(((const unsigned char *)(y))[5] & 255))<<16) |           \
    (((uint64_t)(((const unsigned char *)(y))[6] & 255))<<8)  |          	\
    (((uint64_t)(((const unsigned char *)(y))[7] & 255)));	            \
} while(0)

#endif

// MARK: - 32-bit Rotates

#if defined(_MSC_VER)
// MARK: -- MSVC version

#include <stdlib.h>
#if !defined(__clang__)
 #pragma intrinsic(_lrotr,_lrotl)
#endif
#define	CC_ROR(x,n) _lrotr(x,n)
#define	CC_ROL(x,n) _lrotl(x,n)
#define	CC_RORc(x,n) _lrotr(x,n)
#define	CC_ROLc(x,n) _lrotl(x,n)

#elif (defined(__i386__) || defined(__x86_64__))
// MARK: -- intel asm version

CC_INLINE uint32_t CC_ROL(uint32_t word, int i)
{
    __asm__ ("roll %%cl,%0"
         :"=r" (word)
         :"0" (word),"c" (i));
    return word;
}

CC_INLINE uint32_t CC_ROR(uint32_t word, int i)
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

CC_INLINE uint32_t CC_ROL(uint32_t word, int i)
{
    return ( (word<<(i&31)) | (word>>(32-(i&31))) );
}

CC_INLINE uint32_t CC_ROR(uint32_t word, int i)
{
    return ( (word>>(i&31)) | (word<<(32-(i&31))) );
}

#define	CC_ROLc(x, y) CC_ROL(x, y)
#define	CC_RORc(x, y) CC_ROR(x, y)

#endif

// MARK: - 64 bits rotates

#if defined(__x86_64__) && !defined(_MSC_VER) //clang _MSVC doesn't support GNU-style inline assembly
// MARK: -- intel 64 asm version

CC_INLINE uint64_t CC_ROL64(uint64_t word, int i)
{
    __asm__("rolq %%cl,%0"
        :"=r" (word)
        :"0" (word),"c" (i));
    return word;
}

CC_INLINE uint64_t CC_ROR64(uint64_t word, int i)
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

CC_INLINE uint64_t CC_ROL64(uint64_t word, int i)
{
    return ( (word<<(i&63)) | (word>>(64-(i&63))) );
}

CC_INLINE uint64_t CC_ROR64(uint64_t word, int i)
{
    return ( (word>>(i&63)) | (word<<(64-(i&63))) );
}

#define	CC_ROL64c(x, y) CC_ROL64(x, y)
#define	CC_ROR64c(x, y) CC_ROR64(x, y)

#endif


// MARK: - Byte Swaps

CC_INLINE uint32_t CC_BSWAP(uint32_t x)
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

#define	CC_READ_LE32(ptr) \
( (uint32_t)( \
((uint32_t)((const uint8_t *)(ptr))[0]) | \
(((uint32_t)((const uint8_t *)(ptr))[1]) <<  8) | \
(((uint32_t)((const uint8_t *)(ptr))[2]) << 16) | \
(((uint32_t)((const uint8_t *)(ptr))[3]) << 24)))

#define	CC_WRITE_LE32(ptr, x) \
do { \
((uint8_t *)(ptr))[0] = (uint8_t)( (x)        & 0xFF); \
((uint8_t *)(ptr))[1] = (uint8_t)(((x) >>  8) & 0xFF); \
((uint8_t *)(ptr))[2] = (uint8_t)(((x) >> 16) & 0xFF); \
((uint8_t *)(ptr))[3] = (uint8_t)(((x) >> 24) & 0xFF); \
} while(0)

#define	CC_WRITE_LE64(ptr, x) \
do { \
((uint8_t *)(ptr))[0] = (uint8_t)( (x)        & 0xFF); \
((uint8_t *)(ptr))[1] = (uint8_t)(((x) >>  8) & 0xFF); \
((uint8_t *)(ptr))[2] = (uint8_t)(((x) >> 16) & 0xFF); \
((uint8_t *)(ptr))[3] = (uint8_t)(((x) >> 24) & 0xFF); \
((uint8_t *)(ptr))[4] = (uint8_t)(((x) >> 32) & 0xFF); \
((uint8_t *)(ptr))[5] = (uint8_t)(((x) >> 40) & 0xFF); \
((uint8_t *)(ptr))[6] = (uint8_t)(((x) >> 48) & 0xFF); \
((uint8_t *)(ptr))[7] = (uint8_t)(((x) >> 56) & 0xFF); \
} while(0)

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
#define HEAVISIDE_STEP_UINT64(r,s) {uint64_t _t=s; \
    _t=(((_t)>>32) | (_t)); \
    _t=(0xFFFFFFFF + (_t & 0xFFFFFFFF)); \
    r=_t >> 32;}

#define HEAVISIDE_STEP_UINT32(r,s) {uint32_t _t=s; \
    _t=(((_t)>>16) | (_t)); \
    _t=(0xFFFF + (_t & 0xFFFF)); \
    r=_t >> 16;}

#define HEAVISIDE_STEP_UINT16(r,s) {uint32_t _t=s; \
    _t=(0xFFFF + ((_t) & 0xFFFF)); \
    r=_t >> 16;}

#define HEAVISIDE_STEP_UINT8(r,s) {uint16_t _t=s; \
    _t=(0xFF + ((_t) & 0xFF)); \
    r=_t >> 8;}

#define CC_HEAVISIDE_STEP(r,s) { \
    if (sizeof(s) == 1)      {HEAVISIDE_STEP_UINT8(r,s);}  \
    else if (sizeof(s) == 2) {HEAVISIDE_STEP_UINT16(r,s);} \
    else if (sizeof(s) == 4) {HEAVISIDE_STEP_UINT32(r,s);} \
    else if (sizeof(s) == 8) {HEAVISIDE_STEP_UINT64(r,s);} \
    else {r=(((s)==0)?0:1);} \
    }

/* Return 1 if x mod 4 =1,2,3, 0 otherwise */
#define CC_CARRY_2BITS(x) (((x>>1) | x) & 0x1)
#define CC_CARRY_3BITS(x) (((x>>2) | (x>>1) | x) & 0x1)

/* Set a variable to the biggest power of 2 which can be represented */ 
#define MAX_POWER_OF_2(x)   ((__typeof__(x))1<<(8*sizeof(x)-1))
#define cc_ceiling(a,b)  (((a)+((b)-1))/(b))
#define CC_BITLEN_TO_BYTELEN(x) cc_ceiling((x), 8)

//cc_try_abort() is implemented to comply with FIPS 140-2. See radar 19129408
void cc_try_abort(const char * msg , ...);

/*!
 @brief     cc_muxp(s, a, b) is equivalent to z = s ? a : b, but it executes in constant time
 @param a	input pointer
 @param b	input pointer
 @param s	The selection parameter s must be 0 or 1. if s is integer 1 a is returned. If s is integer 0, b is returned. Otherwise, the output is undefined.
 @return    Returns a, if s is 1 and b if s is 0
 */
void *cc_muxp(int s, const void *a, const void *b);

/*!
 @brief     cc_mux2p
 @param a	input pointer
 @param b	input pointer
 @param r_true	output pointer: if s is integer 1 r_true=a  is returned, otherwise r_true=b
 @param r_false	output pointer: if s is integer 1 r_false=b is returned, otherwise r_false=a
 @param s	The selection parameter s must be 0 or 1.
 @discussion Executes in constant time
 */
void cc_mux2p(int s, void **r_true, void **r_false, const void *a, const void *b);

/*!
 @brief     CC_MUXU(s, a, b) is equivalent to z = s ? a : b, but it executes in constant time
 @param a	input unsigned type
 @param b	input unsigned type
 @param s	The selection parameter s must be 0 or 1. if s is integer 1 a is returned. If s is integer 0, b is returned. Otherwise, the output is undefined.
 @param r	output
 @return    r = a, if s is 1 and b if s is 0
 */
#define CC_MUXU(r, s, a, b)   \
{                       \
    __typeof__(r) _cond = ((__typeof__(r))(s)-(__typeof__(r))1); \
    r = (~_cond&(a))|(_cond&(b)); \
}

int cc_is_compiled_with_tu(void);

#endif /* _CORECRYPTO_CC_PRIV_H_ */
