/*
 * Copyright (c) 2011-2012 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * http://code.google.com/p/smhasher/
 *
 * Copyright (c) 2009-2011 Austin Appleby.
 *
 * MurmurHash3 was written by Austin Appleby, and is placed in the public
 * domain. The author hereby disclaims copyright to this source code.
 */

/*
 * http://burtleburtle.net/bob/hash/
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * You can use this free for any purpose.  It's in the public domain.
 * It has no warranty.
 */

#include <stdbool.h>
#include <sys/types.h>
#include <machine/endian.h>
#include <net/flowhash.h>

static inline u_int32_t getblock32(const u_int32_t *, int);
static inline u_int64_t getblock64(const u_int64_t *, int);
static inline u_int32_t mh3_fmix32(u_int32_t);
static inline u_int64_t mh3_fmix64(u_int64_t);

#define	ALIGNED16(v)	((((uintptr_t)(v)) & 1) == 0)
#define	ALIGNED32(v)	((((uintptr_t)(v)) & 3) == 0)
#define	ALIGNED64(v)	((((uintptr_t)(v)) & 7) == 0)

#define	ROTL32(x, r)	(((x) << (r)) | ((x) >> (32 - (r))))
#define	ROTL64(x, r)	(((x) << (r)) | ((x) >> (64 - (r))))

/*
 * The following hash algorithms are selected based on performance:
 *
 * 64-bit:	MurmurHash3_x64_128
 * 32-bit:	JHash
 */
#if   defined(__LP64__)
net_flowhash_fn_t *net_flowhash = net_flowhash_mh3_x64_128;
#else /* !__LP64__ */
net_flowhash_fn_t *net_flowhash = net_flowhash_jhash;
#endif /* !__LP64__ */

#if defined(__i386__) || defined(__x86_64__) || defined(__arm64__)
static inline u_int32_t
getblock32(const u_int32_t *p, int i)
{
	return (p[i]);
}

static inline u_int64_t
getblock64(const u_int64_t *p, int i)
{
	return (p[i]);
}
#else /* !__i386__ && !__x86_64__ && !__arm64__*/
static inline u_int32_t
getblock32(const u_int32_t *p, int i)
{
	const u_int8_t *bytes = (u_int8_t *)(void *)(uintptr_t)(p + i);
	u_int32_t value;

	if (ALIGNED32(p)) {
		value = p[i];
	} else {
#if BYTE_ORDER == BIG_ENDIAN
		value =
		    (((u_int32_t)bytes[0]) << 24) |
		    (((u_int32_t)bytes[1]) << 16) |
		    (((u_int32_t)bytes[2]) << 8) |
		    ((u_int32_t)bytes[3]);
#else /* LITTLE_ENDIAN */
		value =
		    (((u_int32_t)bytes[3]) << 24) |
		    (((u_int32_t)bytes[2]) << 16) |
		    (((u_int32_t)bytes[1]) << 8) |
		    ((u_int32_t)bytes[0]);
#endif /* LITTLE_ENDIAN */
	}
	return (value);
}

static inline u_int64_t
getblock64(const u_int64_t *p, int i)
{
	const u_int8_t *bytes = (const u_int8_t *)(void *)(uintptr_t)(p + i);
	u_int64_t value;

	if (ALIGNED64(p)) {
		value = p[i];
	} else {
#if BYTE_ORDER == BIG_ENDIAN
		value =
		    (((u_int64_t)bytes[0]) << 56) |
		    (((u_int64_t)bytes[1]) << 48) |
		    (((u_int64_t)bytes[2]) << 40) |
		    (((u_int64_t)bytes[3]) << 32) |
		    (((u_int64_t)bytes[4]) << 24) |
		    (((u_int64_t)bytes[5]) << 16) |
		    (((u_int64_t)bytes[6]) << 8) |
		    ((u_int64_t)bytes[7]);
#else /* LITTLE_ENDIAN */
		value =
		    (((u_int64_t)bytes[7]) << 56) |
		    (((u_int64_t)bytes[6]) << 48) |
		    (((u_int64_t)bytes[5]) << 40) |
		    (((u_int64_t)bytes[4]) << 32) |
		    (((u_int64_t)bytes[3]) << 24) |
		    (((u_int64_t)bytes[2]) << 16) |
		    (((u_int64_t)bytes[1]) << 8) |
		    ((u_int64_t)bytes[0]);
#endif /* LITTLE_ENDIAN */
	}
	return (value);
}
#endif /* !__i386__ && !__x86_64 && !__arm64__ */

static inline u_int32_t
mh3_fmix32(u_int32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return (h);
}

static inline u_int64_t
mh3_fmix64(u_int64_t k)
{
	k ^= k >> 33;
	k *= 0xff51afd7ed558ccdLLU;
	k ^= k >> 33;
	k *= 0xc4ceb9fe1a85ec53LLU;
	k ^= k >> 33;

	return (k);
}

/*
 * MurmurHash3_x86_32
 */
#define	MH3_X86_32_C1	0xcc9e2d51
#define	MH3_X86_32_C2	0x1b873593

u_int32_t
net_flowhash_mh3_x86_32(const void *key, u_int32_t len, const u_int32_t seed)
{
	const u_int8_t *data = (const u_int8_t *)key;
	const u_int32_t nblocks = len / 4;
	const u_int32_t *blocks;
	const u_int8_t *tail;
	u_int32_t h1 = seed, k1;
	int i;

	/* body */
	blocks = (const u_int32_t *)(const void *)(data + nblocks * 4);

	for (i = -nblocks; i; i++) {
		k1 = getblock32(blocks, i);

		k1 *= MH3_X86_32_C1;
		k1 = ROTL32(k1, 15);
		k1 *= MH3_X86_32_C2;

		h1 ^= k1;
		h1 = ROTL32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	/* tail */
	tail = (const u_int8_t *)(const void *)(data + nblocks * 4);
	k1 = 0;

	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
		/* FALLTHRU */
	case 2:
		k1 ^= tail[1] << 8;
		/* FALLTHRU */
	case 1:
		k1 ^= tail[0];
		k1 *= MH3_X86_32_C1;
		k1 = ROTL32(k1, 15);
		k1 *= MH3_X86_32_C2;
		h1 ^= k1;
	};

	/* finalization */
	h1 ^= len;

	h1 = mh3_fmix32(h1);

	return (h1);
}

/*
 * MurmurHash3_x64_128
 */
#define	MH3_X64_128_C1	0x87c37b91114253d5LLU
#define	MH3_X64_128_C2	0x4cf5ad432745937fLLU

u_int32_t
net_flowhash_mh3_x64_128(const void *key, u_int32_t len, const u_int32_t seed)
{
	const u_int8_t *data = (const u_int8_t *)key;
	const u_int32_t nblocks = len / 16;
	const u_int64_t *blocks;
	const u_int8_t *tail;
	u_int64_t h1 = seed, k1;
	u_int64_t h2 = seed, k2;
	u_int32_t i;

	/* body */
	blocks = (const u_int64_t *)(const void *)data;

	for (i = 0; i < nblocks; i++) {
		k1 = getblock64(blocks, i * 2 + 0);
		k2 = getblock64(blocks, i * 2 + 1);

		k1 *= MH3_X64_128_C1;
#if defined(__x86_64__)
        __asm__ ( "rol   $31, %[k1]\n\t" :[k1] "+r" (k1) : :);
#elif defined(__arm64__)
        __asm__ ( "ror   %[k1], %[k1], #(64-31)\n\t" :[k1] "+r" (k1) : :);
#else /* !__x86_64__ && !__arm64__ */
		k1 = ROTL64(k1, 31);
#endif /* !__x86_64__ && !__arm64__ */
		k1 *= MH3_X64_128_C2;
		h1 ^= k1;

#if defined(__x86_64__)
        __asm__ ( "rol   $27, %[h1]\n\t" :[h1] "+r" (h1) : :);
#elif defined(__arm64__)
        __asm__ ( "ror   %[h1], %[h1], #(64-27)\n\t" :[h1] "+r" (h1) : :);
#else /* !__x86_64__ && !__arm64__ */
        h1 = ROTL64(h1, 27);
#endif /* !__x86_64__ && !__arm64__ */
		h1 += h2;
		h1 = h1 * 5 + 0x52dce729;

		k2 *= MH3_X64_128_C2;
#if defined(__x86_64__)
        __asm__ ( "rol   $33, %[k2]\n\t" :[k2] "+r" (k2) : :);
#elif defined(__arm64__)
        __asm__ ( "ror   %[k2], %[k2], #(64-33)\n\t" :[k2] "+r" (k2) : :);
#else /* !__x86_64__ && !__arm64__ */
        k2 = ROTL64(k2, 33);
#endif /* !__x86_64__ && !__arm64__ */
		k2 *= MH3_X64_128_C1;
		h2 ^= k2;

#if defined(__x86_64__)
        __asm__ ( "rol   $31, %[h2]\n\t" :[h2] "+r" (h2) : :);
#elif defined(__arm64__)
        __asm__ ( "ror   %[h2], %[h2], #(64-31)\n\t" :[h2] "+r" (h2) : :);
#else /* !__x86_64__ && !__arm64__ */
        h2 = ROTL64(h2, 31);
#endif /* !__x86_64__ && !__arm64__ */
		h2 += h1;
		h2 = h2 * 5+ 0x38495ab5;
	}

	/* tail */
	tail = (const u_int8_t *)(const void *)(data + nblocks * 16);
	k1 = 0;
	k2 = 0;

	switch (len & 15) {
	case 15:
		k2 ^= ((u_int64_t)tail[14]) << 48;
		/* FALLTHRU */
	case 14:
		k2 ^= ((u_int64_t)tail[13]) << 40;
		/* FALLTHRU */
	case 13:
		k2 ^= ((u_int64_t)tail[12]) << 32;
		/* FALLTHRU */
	case 12:
		k2 ^= ((u_int64_t)tail[11]) << 24;
		/* FALLTHRU */
	case 11:
		k2 ^= ((u_int64_t)tail[10]) << 16;
		/* FALLTHRU */
	case 10:
		k2 ^= ((u_int64_t)tail[9]) << 8;
		/* FALLTHRU */
	case 9:
		k2 ^= ((u_int64_t)tail[8]) << 0;
		k2 *= MH3_X64_128_C2;
#if defined(__x86_64__)
        __asm__ ( "rol   $33, %[k2]\n\t" :[k2] "+r" (k2) : :);
#elif defined(__arm64__)
        __asm__ ( "ror   %[k2], %[k2], #(64-33)\n\t" :[k2] "+r" (k2) : :);
#else /* !__x86_64__ && !__arm64__ */
        k2 = ROTL64(k2, 33);
#endif /* !__x86_64__ && !__arm64__ */
		k2 *= MH3_X64_128_C1;
		h2 ^= k2;
		/* FALLTHRU */
	case 8:
		k1 ^= ((u_int64_t)tail[7]) << 56;
		/* FALLTHRU */
	case 7:
		k1 ^= ((u_int64_t)tail[6]) << 48;
		/* FALLTHRU */
	case 6:
		k1 ^= ((u_int64_t)tail[5]) << 40;
		/* FALLTHRU */
	case 5:
		k1 ^= ((u_int64_t)tail[4]) << 32;
		/* FALLTHRU */
	case 4:
		k1 ^= ((u_int64_t)tail[3]) << 24;
		/* FALLTHRU */
	case 3:
		k1 ^= ((u_int64_t)tail[2]) << 16;
		/* FALLTHRU */
	case 2:
		k1 ^= ((u_int64_t)tail[1]) << 8;
		/* FALLTHRU */
	case 1:
		k1 ^= ((u_int64_t)tail[0]) << 0;
		k1 *= MH3_X64_128_C1;
#if defined(__x86_64__)
        __asm__ ( "rol   $31, %[k1]\n\t" :[k1] "+r" (k1) : :);
#elif defined(__arm64__)
        __asm__ ( "ror   %[k1], %[k1], #(64-31)\n\t" :[k1] "+r" (k1) : :);
#else /* !__x86_64__ && !__arm64__ */
        k1 = ROTL64(k1, 31);
#endif /* !__x86_64__ && !__arm64__ */
		k1 *= MH3_X64_128_C2;
		h1 ^= k1;
	};

	/* finalization */
	h1 ^= len;
	h2 ^= len;

	h1 += h2;
	h2 += h1;

	h1 = mh3_fmix64(h1);
	h2 = mh3_fmix64(h2);

	h1 += h2;
	h2 += h1;

	/* throw all but lowest 32-bit */
	return (h1 & 0xffffffff);
}

#define	JHASH_INIT	0xdeadbeef

#define	JHASH_MIX(a, b, c) {			\
	a -= c;  a ^= ROTL32(c, 4);   c += b;	\
	b -= a;  b ^= ROTL32(a, 6);   a += c;	\
	c -= b;  c ^= ROTL32(b, 8);   b += a;	\
	a -= c;  a ^= ROTL32(c, 16);  c += b;	\
	b -= a;  b ^= ROTL32(a, 19);  a += c;	\
	c -= b;  c ^= ROTL32(b, 4);   b += a;	\
}

#define	JHASH_FINAL(a, b, c) {			\
	c ^= b;  c -= ROTL32(b, 14);		\
	a ^= c;  a -= ROTL32(c, 11);		\
	b ^= a;  b -= ROTL32(a, 25);		\
	c ^= b;  c -= ROTL32(b, 16);		\
	a ^= c;  a -= ROTL32(c, 4);		\
	b ^= a;  b -= ROTL32(a, 14);		\
	c ^= b;  c -= ROTL32(b, 24);		\
}

#if BYTE_ORDER == BIG_ENDIAN
/*
 * hashbig()
 */
u_int32_t
net_flowhash_jhash(const void *key, u_int32_t len, const u_int32_t seed)
{
	u_int32_t a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INIT + len + seed;

	if (ALIGNED32(key)) {
		/* read 32-bit chunks */
		const u_int32_t *k = (const u_int32_t *)key;

		/*
		 * all but last block:
		 * aligned reads and affect 32 bits of (a,b,c)
		 */
		while (len > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			JHASH_MIX(a, b, c);
			len -= 12;
			k += 3;
		}

		/*
		 * handle the last (probably partial) block
		 *
		 * "k[2] << 8" actually reads beyond the end of the string,
		 * but then shifts out the part it's not allowed to read.
		 * Because the string is aligned, the illegal read is in
		 * the same word as the rest of the string.  The masking
		 * trick does make the hash noticably faster for short
		 * strings (like English words).
		 */
		switch (len) {
		case 12:
			c += k[2];
			b += k[1];
			a += k[0];
			break;

		case 11:
			c += k[2] & 0xffffff00;
			b += k[1];
			a += k[0];
			break;

		case 10:
			c += k[2] & 0xffff0000;
			b += k[1];
			a += k[0];
			break;

		case 9:
			c += k[2] & 0xff000000;
			b += k[1];
			a += k[0];
			break;

		case 8:
			b += k[1];
			a += k[0];
			break;

		case 7:
			b += k[1] & 0xffffff00;
			a += k[0];
			break;

		case 6:
			b += k[1] & 0xffff0000;
			a += k[0];
			break;

		case 5:
			b += k[1] & 0xff000000;
			a += k[0];
			break;

		case 4:
			a += k[0];
			break;

		case 3:
			a += k[0] & 0xffffff00;
			break;

		case 2:
			a += k[0] & 0xffff0000;
			break;

		case 1:
			a += k[0] & 0xff000000;
			break;

		case 0:
			/* zero length requires no mixing */
			return (c);
		}

		JHASH_FINAL(a, b, c);

		return (c);
	}

	/* need to read the key one byte at a time */
	const u_int8_t *k = (const u_int8_t *)key;

	/* all but the last block: affect some 32 bits of (a,b,c) */
	while (len > 12) {
		a += ((u_int32_t)k[0]) << 24;
		a += ((u_int32_t)k[1]) << 16;
		a += ((u_int32_t)k[2]) << 8;
		a += ((u_int32_t)k[3]);
		b += ((u_int32_t)k[4]) << 24;
		b += ((u_int32_t)k[5]) << 16;
		b += ((u_int32_t)k[6]) << 8;
		b += ((u_int32_t)k[7]);
		c += ((u_int32_t)k[8]) << 24;
		c += ((u_int32_t)k[9]) << 16;
		c += ((u_int32_t)k[10]) << 8;
		c += ((u_int32_t)k[11]);
		JHASH_MIX(a, b, c);
		len -= 12;
		k += 12;
	}

	/* last block: affect all 32 bits of (c) */
	switch (len) {
	case 12:
		c += k[11];
		/* FALLTHRU */
	case 11:
		c += ((u_int32_t)k[10]) << 8;
		/* FALLTHRU */
	case 10:
		c += ((u_int32_t)k[9]) << 16;
		/* FALLTHRU */
	case 9:
		c += ((u_int32_t)k[8]) << 24;
		/* FALLTHRU */
	case 8:
		b += k[7];
		/* FALLTHRU */
	case 7:
		b += ((u_int32_t)k[6]) << 8;
		/* FALLTHRU */
	case 6:
		b += ((u_int32_t)k[5]) << 16;
		/* FALLTHRU */
	case 5:
		b += ((u_int32_t)k[4]) << 24;
		/* FALLTHRU */
	case 4:
		a += k[3];
		/* FALLTHRU */
	case 3:
		a += ((u_int32_t)k[2]) << 8;
		/* FALLTHRU */
	case 2:
		a += ((u_int32_t)k[1]) << 16;
		/* FALLTHRU */
	case 1:
		a += ((u_int32_t)k[0]) << 24;
		break;

	case 0:
		/* zero length requires no mixing */
		return (c);
	}

	JHASH_FINAL(a, b, c);

	return (c);
}
#else /* LITTLE_ENDIAN */
/*
 * hashlittle()
 */
u_int32_t
net_flowhash_jhash(const void *key, u_int32_t len, const u_int32_t seed)
{
	u_int32_t a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INIT + len + seed;

#if defined(__i386__) || defined(__x86_64__)
	/*
	 * On i386/x86_64, it is faster to read 32-bit chunks if the key
	 * is aligned 32-bit OR not 16-bit, and perform 16-bit reads if it
	 * is aligned 16-bit.
	 */
	if (ALIGNED32(key) || !ALIGNED16(key)) {
#else /* !defined(__i386__) && !defined(__x86_64__) */
	if (ALIGNED32(key)) {
#endif /* !defined(__i386__) && !defined(__x86_64__) */
		/* read 32-bit chunks */
		const u_int32_t *k = (const u_int32_t *)key;

		/*
		 * all but last block:
		 * aligned reads and affect 32 bits of (a,b,c)
		 */
		while (len > 12) {
			a += k[0];
			b += k[1];
			c += k[2];
			JHASH_MIX(a, b, c);
			len -= 12;
			k += 3;
		}

		/*
		 * handle the last (probably partial) block
		 *
		 * "k[2] & 0xffffff" actually reads beyond the end of the
		 * string, but then masks off the part it's not allowed
		 * to read.  Because the string is aligned, the masked-off
		 * tail is in the same word as the rest of the string.
		 * The masking trick does make the hash noticably faster
		 * for short strings (like English words).
		 */
		switch (len) {
		case 12:
			c += k[2];
			b += k[1];
			a += k[0];
			break;

		case 11:
			c += k[2] & 0xffffff;
			b += k[1];
			a += k[0];
			break;

		case 10:
			c += k[2] & 0xffff;
			b += k[1];
			a += k[0];
			break;

		case 9:
			c += k[2] & 0xff;
			b += k[1];
			a += k[0];
			break;

		case 8:
			b += k[1];
			a += k[0];
			break;

		case 7:
			b += k[1] & 0xffffff;
			a += k[0];
			break;

		case 6:
			b += k[1] & 0xffff;
			a += k[0];
			break;

		case 5:
			b += k[1] & 0xff;
			a += k[0];
			break;

		case 4:
			a += k[0];
			break;

		case 3:
			a += k[0] & 0xffffff;
			break;

		case 2:
			a += k[0] & 0xffff;
			break;

		case 1:
			a += k[0] & 0xff;
			break;

		case 0:
			/* zero length requires no mixing */
			return (c);
		}

		JHASH_FINAL(a, b, c);

		return (c);
	}
#if !defined(__i386__) && !defined(__x86_64__)
	else if (ALIGNED16(key)) {
#endif /* !defined(__i386__) && !defined(__x86_64__) */
		/* read 16-bit chunks */
		const u_int16_t *k = (const u_int16_t *)key;
		const u_int8_t *k8;

		/* all but last block: aligned reads and different mixing */
		while (len > 12) {
			a += k[0] + (((u_int32_t)k[1]) << 16);
			b += k[2] + (((u_int32_t)k[3]) << 16);
			c += k[4] + (((u_int32_t)k[5]) << 16);
			JHASH_MIX(a, b, c);
			len -= 12;
			k += 6;
		}

		/* handle the last (probably partial) block */
		k8 = (const u_int8_t *)k;
		switch (len) {
		case 12:
			c += k[4] + (((u_int32_t)k[5]) << 16);
			b += k[2] + (((u_int32_t)k[3]) << 16);
			a += k[0] + (((u_int32_t)k[1]) << 16);
			break;

		case 11:
			c += ((u_int32_t)k8[10]) << 16;
			/* FALLTHRU */
		case 10:
			c += k[4];
			b += k[2] + (((u_int32_t)k[3]) << 16);
			a += k[0] + (((u_int32_t)k[1]) << 16);
			break;

		case 9:
			c += k8[8];
			/* FALLTHRU */
		case 8:
			b += k[2] + (((u_int32_t)k[3]) << 16);
			a += k[0] + (((u_int32_t)k[1]) << 16);
			break;

		case 7:
			b += ((u_int32_t)k8[6]) << 16;
			/* FALLTHRU */
		case 6:
			b += k[2];
			a += k[0] + (((u_int32_t)k[1]) << 16);
			break;

		case 5:
			b += k8[4];
			/* FALLTHRU */
		case 4:
			a += k[0] + (((u_int32_t)k[1]) << 16);
			break;

		case 3:
			a += ((u_int32_t)k8[2]) << 16;
			/* FALLTHRU */
		case 2:
			a += k[0];
			break;

		case 1:
			a += k8[0];
			break;

		case 0:
			/* zero length requires no mixing */
			return (c);
		}

		JHASH_FINAL(a, b, c);

		return (c);
#if !defined(__i386__) && !defined(__x86_64__)
	}

	/* need to read the key one byte at a time */
	const u_int8_t *k = (const u_int8_t *)key;

	/* all but the last block: affect some 32 bits of (a,b,c) */
	while (len > 12) {
		a += k[0];
		a += ((u_int32_t)k[1]) << 8;
		a += ((u_int32_t)k[2]) << 16;
		a += ((u_int32_t)k[3]) << 24;
		b += k[4];
		b += ((u_int32_t)k[5]) << 8;
		b += ((u_int32_t)k[6]) << 16;
		b += ((u_int32_t)k[7]) << 24;
		c += k[8];
		c += ((u_int32_t)k[9]) << 8;
		c += ((u_int32_t)k[10]) << 16;
		c += ((u_int32_t)k[11]) << 24;
		JHASH_MIX(a, b, c);
		len -= 12;
		k += 12;
	}

	/* last block: affect all 32 bits of (c) */
	switch (len) {
	case 12:
		c += ((u_int32_t)k[11]) << 24;
		/* FALLTHRU */
	case 11:
		c += ((u_int32_t)k[10]) << 16;
		/* FALLTHRU */
	case 10:
		c += ((u_int32_t)k[9]) << 8;
		/* FALLTHRU */
	case 9:
		c += k[8];
		/* FALLTHRU */
	case 8:
		b += ((u_int32_t)k[7]) << 24;
		/* FALLTHRU */
	case 7:
		b += ((u_int32_t)k[6]) << 16;
		/* FALLTHRU */
	case 6:
		b += ((u_int32_t)k[5]) << 8;
		/* FALLTHRU */
	case 5:
		b += k[4];
		/* FALLTHRU */
	case 4:
		a += ((u_int32_t)k[3]) << 24;
		/* FALLTHRU */
	case 3:
		a += ((u_int32_t)k[2]) << 16;
		/* FALLTHRU */
	case 2:
		a += ((u_int32_t)k[1]) << 8;
		/* FALLTHRU */
	case 1:
		a += k[0];
		break;

	case 0:
		/* zero length requires no mixing */
		return (c);
	}

	JHASH_FINAL(a, b, c);

	return (c);
#endif /* !defined(__i386__) && !defined(__x86_64__) */
}
#endif /* LITTLE_ENDIAN */
