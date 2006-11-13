/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:49  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:08  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.5.2  1996/07/31  09:57:36  paire
 * 	Added some more constraints to __asm__ functions for compilation
 * 	under gcc2.7.1 for PROF_CNT_[L]{ADD|SUB} macros
 * 	[96/06/14            paire]
 *
 * Revision 1.1.5.1  1995/01/06  19:53:52  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:25:27  dwm]
 * 
 * Revision 1.1.2.2  1994/05/16  19:19:26  meissner
 * 	Add {,L}PROF_CNT_{SUB,LSUB,OVERFLOW} macros for gprof command.
 * 	[1994/05/10  10:36:06  meissner]
 * 
 * 	Correct 64-bit integer asms to specify result values as inputs, and use =g instead of =m.
 * 	Cast the integer argument to PROF_CNT_ADD to unsigned long, so a short register is widened.
 * 	Add more support for writing the gprof command.
 * 	PROF_CNT_{EQ,NE} should not use ^=, it just uses ^.
 * 	Round PROF_CNT_DIGITS up to 24 bytes so it is word aligned.
 * 	_profile_cnt_to_decimal now takes the low/high values as separate arguments.
 * 	Delete _profile_cnt_to_hex.
 * 	[1994/04/28  21:45:07  meissner]
 * 
 * 	Add more 64 bit arithmetic macros to support writing gprof.
 * 	[1994/04/20  15:47:05  meissner]
 * 
 * Revision 1.1.2.1  1994/04/08  17:51:56  meissner
 * 	Correct spelling on LPROF_CNT_TO_LDOUBLE macro.
 * 	[1994/04/08  16:18:06  meissner]
 * 
 * 	Make LHISTCOUNTER be 64 bits.
 * 	Define LPROF_CNT_INC to increment LHISTCOUNTER.
 * 	[1994/04/08  12:40:32  meissner]
 * 
 * 	Make most stats 64 bits, except for things like memory allocation.
 * 	[1994/04/02  14:58:34  meissner]
 * 
 * 	Add overflow support for {gprof,prof,old,dummy}_mcount counters.
 * 	[1994/03/17  20:13:37  meissner]
 * 
 * 	Add gprof/prof overflow support
 * 	[1994/03/17  14:56:56  meissner]
 * 
 * 	Define LHISTCOUNTER.
 * 	[1994/02/28  12:05:16  meissner]
 * 
 * 	Set HISTFRACTION to 4, so new lprofil call takes the same space.
 * 	[1994/02/24  16:15:34  meissner]
 * 
 * 	Add too_low/too_high to profile_stats.
 * 	[1994/02/16  22:38:23  meissner]
 * 
 * 	Make prof_cnt_t unsigned long.
 * 	[1994/02/11  16:52:09  meissner]
 * 
 * 	Remember function unique ptr in gfuncs structure to reset profiling.
 * 	Add support for range checking gprof arc {from,self}pc addresses.
 * 	Add counter for # times acontext was locked.
 * 	Expand copyright.
 * 	[1994/02/07  12:41:08  meissner]
 * 
 * 	Keep track of the number of times the kernel overflows the HISTCOUNTER counter.
 * 	[1994/02/03  20:13:31  meissner]
 * 
 * 	Add stats for {user,kernel,idle} mode in the kernel.
 * 	[1994/02/03  15:17:36  meissner]
 * 
 * 	No change.
 * 	[1994/02/03  00:58:59  meissner]
 * 
 * 	Combine _profile_{vars,stats,md}; Allow more than one _profile_vars.
 * 	[1994/02/01  12:04:04  meissner]
 * 
 * 	Split # records to # gprof and # prof records.
 * 	Add my_cpu/max_cpu fields.
 * 	[1994/01/28  23:33:30  meissner]
 * 
 * 	Eliminate hash_{size,mask} from gfuncs structure.
 * 	[1994/01/26  20:23:41  meissner]
 * 
 * 	Add structure size fields to _profile_{vars,stats,md}.
 * 	Add major/minor version number to _profile_md.
 * 	Move allocation context block pointer to main structure.
 * 	Delete shift count for allocation contexts.
 * 	[1994/01/25  01:46:08  meissner]
 * 
 * 	Add HASHFRACTION
 * 	[1994/01/22  01:14:02  meissner]
 * 
 * 	Split profile-md.h into profile-internal.h and profile-md.
 * 	[1994/01/20  20:57:18  meissner]
 * 
 * 	Fixup copyright.
 * 	[1994/01/18  23:08:14  meissner]
 * 
 * 	Make flags byte-sized.
 * 	Add have_bb flag.
 * 	Add init_format flag.
 * 	[1994/01/18  21:57:18  meissner]
 * 
 * 	CR 10198 - Initial version.
 * 	[1994/01/18  19:44:59  meissner]
 * 
 * $EndLog$
 */

#ifndef _PROFILE_MD_H
#define _PROFILE_MD_H

#include <types.h>

/*
 * Define the interfaces between the assembly language profiling support
 * that is common between the kernel, mach servers, and user space library.
 */

/*
 * Integer types used.
 */

typedef	long		prof_ptrint_t;	/* hold either pointer or signed int */
typedef	unsigned long	prof_uptrint_t;	/* hold either pointer or unsigned int */
typedef	long		prof_lock_t;	/* lock word type */
typedef unsigned char	prof_flag_t;	/* type for boolean flags */

/*
 * Double precision counter.
 */

typedef struct prof_cnt_t {
	prof_uptrint_t	low;		/* low 32 bits of counter */
	prof_uptrint_t	high;		/* high 32 bits of counter */
} prof_cnt_t;

#if defined(__GNUC__) && !defined(lint)
#define PROF_CNT_INC(cnt)					\
	__asm__("addl $1,%0; adcl $0,%1"			\
		: "=g" ((cnt).low), "=g" ((cnt).high)		\
		: "0" ((cnt).low), "1" ((cnt).high))

#define PROF_CNT_ADD(cnt,val)					\
	__asm__("addl %2,%0; adcl $0,%1"			\
		: "=g,r" ((cnt).low), "=g,r" ((cnt).high)	\
		: "r,g" ((unsigned long)(val)),			\
		"0,0" ((cnt).low), "1,1" ((cnt).high))

#define PROF_CNT_LADD(cnt,val)					\
	__asm__("addl %2,%0; adcl %3,%1"			\
		: "=g,r" ((cnt).low), "=g,r" ((cnt).high)	\
		: "r,g" ((val).low), "r,g" ((val).high),	\
		"0,0" ((cnt).low), "1,1" ((cnt).high))

#define PROF_CNT_SUB(cnt,val)					\
	__asm__("subl %2,%0; sbbl $0,%1"			\
		: "=g,r" ((cnt).low), "=g,r" ((cnt).high)	\
		: "r,g" ((unsigned long)(val)),			\
		"0,0" ((cnt).low), "1,1" ((cnt).high))

#define PROF_CNT_LSUB(cnt,val)					\
	__asm__("subl %2,%0; sbbl %3,%1"			\
		: "=g,r" ((cnt).low), "=g,r" ((cnt).high)	\
		: "r,g" ((val).low), "r,g" ((val).high),	\
		"0,0" ((cnt).low), "1,1" ((cnt).high))

#else
#define PROF_CNT_INC(cnt)	((++((cnt).low) == 0) ? ++((cnt).high) : 0)
#define PROF_CNT_ADD(cnt,val)	(((((cnt).low + (val)) < (val)) ? ((cnt).high++) : 0), ((cnt).low += (val)))
#define PROF_CNT_LADD(cnt,val)	(PROF_CNT_ADD(cnt,(val).low), (cnt).high += (val).high)
#define PROF_CNT_SUB(cnt,val)	(((((cnt).low - (val)) > (cnt).low) ? ((cnt).high--) : 0), ((cnt).low -= (val)))
#define PROF_CNT_LSUB(cnt,val)	(PROF_CNT_SUB(cnt,(val).low), (cnt).high -= (val).high)
#endif

#define PROF_ULONG_TO_CNT(cnt,val)	(((cnt).high = 0), ((cnt).low = val))
#define	PROF_CNT_OVERFLOW(cnt,high,low)	(((high) = (cnt).high), ((low) = (cnt).low))
#define PROF_CNT_TO_ULONG(cnt)		(((cnt).high == 0) ? (cnt).low : 0xffffffffu)
#define PROF_CNT_TO_LDOUBLE(cnt)	((((long double)(cnt).high) * 4294967296.0L) + (long double)(cnt).low)
#define PROF_CNT_TO_DECIMAL(buf,cnt)	_profile_cnt_to_decimal(buf, (cnt).low, (cnt).high)
#define PROF_CNT_EQ_0(cnt)		(((cnt).high | (cnt).low) == 0)
#define PROF_CNT_NE_0(cnt)		(((cnt).high | (cnt).low) != 0)
#define PROF_CNT_EQ(cnt1,cnt2)		((((cnt1).high ^ (cnt2).high) | ((cnt1).low ^ (cnt2).low)) == 0)
#define PROF_CNT_NE(cnt1,cnt2)		((((cnt1).high ^ (cnt2).high) | ((cnt1).low ^ (cnt2).low)) != 0)
#define PROF_CNT_GT(cnt1,cnt2)		(((cnt1).high > (cnt2).high) || ((cnt1).low > (cnt2).low))
#define PROF_CNT_LT(cnt1,cnt2)		(((cnt1).high < (cnt2).high) || ((cnt1).low < (cnt2).low))

/* max # digits + null to hold prof_cnt_t values (round up to multiple of 4) */
#define PROF_CNT_DIGITS			24

/*
 * Types of the profil counter.
 */

typedef unsigned short	HISTCOUNTER;		/* profil */
typedef prof_cnt_t	LHISTCOUNTER;		/* lprofil */

#define LPROF_ULONG_TO_CNT(cnt,val)	PROF_ULONG_TO_CNT(cnt,val)
#define LPROF_CNT_INC(lp)		PROF_CNT_INC(lp)
#define LPROF_CNT_ADD(lp,val)		PROF_CNT_ADD(lp,val)
#define LPROF_CNT_LADD(lp,val)		PROF_CNT_LADD(lp,val)
#define LPROF_CNT_SUB(lp,val)		PROF_CNT_SUB(lp,val)
#define LPROF_CNT_LSUB(lp,val)		PROF_CNT_LSUB(lp,val)
#define	LPROF_CNT_OVERFLOW(lp,high,low)	PROF_CNT_OVERFLOW(lp,high,low)
#define LPROF_CNT_TO_ULONG(lp)		PROF_CNT_TO_ULONG(lp)
#define LPROF_CNT_TO_LDOUBLE(lp)	PROF_CNT_TO_LDOUBLE(lp)
#define LPROF_CNT_TO_DECIMAL(buf,cnt)	PROF_CNT_TO_DECIMAL(buf,cnt)
#define LPROF_CNT_EQ_0(cnt)		PROF_CNT_EQ_0(cnt)
#define LPROF_CNT_NE_0(cnt)		PROF_CNT_NE_0(cnt)
#define LPROF_CNT_EQ(cnt1,cnt2)		PROF_CNT_EQ(cnt1,cnt2)
#define LPROF_CNT_NE(cnt1,cnt2)		PROF_CNT_NE(cnt1,cnt2)
#define LPROF_CNT_GT(cnt1,cnt2)		PROF_CNT_GT(cnt1,cnt2)
#define LPROF_CNT_LT(cnt1,cnt2)		PROF_CNT_LT(cnt1,cnt2)
#define LPROF_CNT_DIGITS		PROF_CNT_DIGITS

/*
 *  fraction of text space to allocate for histogram counters
 */

#define HISTFRACTION    4

/*
 * Fraction of text space to allocate for from hash buckets.
 */

#define HASHFRACTION	HISTFRACTION

/*
 * Prof call count, external format.
 */

struct prof_ext {
	prof_uptrint_t	cvalue;		/* caller address */
	prof_uptrint_t	cncall;		/* # of calls */
};

/*
 * Prof call count, internal format.
 */

struct prof_int {
	struct prof_ext	prof;		/* external prof struct */
	prof_uptrint_t	overflow;	/* # times prof counter overflowed */
};

/*
 * Gprof arc, external format.
 */

struct gprof_arc {
	prof_uptrint_t	 frompc;	/* caller's caller */
	prof_uptrint_t	 selfpc;	/* caller's address */
	prof_uptrint_t	 count;		/* # times arc traversed */
};

/*
 * Gprof arc, internal format.
 */

struct hasharc {
	struct hasharc	*next;		/* next gprof record */
	struct gprof_arc arc;		/* gprof record */
	prof_uptrint_t	 overflow;	/* # times counter overflowed */
};

/*
 * Linked list of all function profile blocks.
 */

#define MAX_CACHE	3		/* # cache table entries */

struct gfuncs {
	struct hasharc **hash_ptr;		/* gprof hash table */
	struct hasharc **unique_ptr; 		/* function unique pointer */
	struct prof_int prof;			/* -p stats for elf */
	struct hasharc *cache_ptr[MAX_CACHE];	/* cache element pointers */
};

/*
 * Profile information which might be written out in ELF {,g}mon.out files.
 */

#define MAX_BUCKETS 9			/* max bucket chain to print out */

struct profile_stats {			/* Debugging counters */
	prof_uptrint_t major_version;	/* major version number */
	prof_uptrint_t minor_version;	/* minor version number */
	prof_uptrint_t stats_size;	/* size of profile_vars structure */
	prof_uptrint_t profil_buckets; 	/* # profil buckets */
	prof_uptrint_t my_cpu;		/* identify current cpu/thread */
	prof_uptrint_t max_cpu;		/* identify max cpu/thread */
	prof_uptrint_t prof_records;	/* # of functions profiled */
	prof_uptrint_t gprof_records;	/* # of gprof arcs */
	prof_uptrint_t hash_buckets;	/* # gprof hash buckets */
	prof_uptrint_t bogus_count;	/* # of bogus functions found in gprof */

	prof_cnt_t cnt;			/* # of calls to _{,g}prof_mcount */
	prof_cnt_t dummy;		/* # of calls to _dummy_mcount */
	prof_cnt_t old_mcount;		/* # of calls to old mcount */
	prof_cnt_t hash_search;		/* # hash buckets searched */
	prof_cnt_t hash_num;		/* # times hash table searched */
	prof_cnt_t user_ticks;		/* # ticks in user space */
	prof_cnt_t kernel_ticks;	/* # ticks in kernel space */
	prof_cnt_t idle_ticks;		/* # ticks in idle mode */
	prof_cnt_t overflow_ticks;	/* # ticks where HISTCOUNTER overflowed */
	prof_cnt_t acontext_locked;	/* # times an acontext was locked */
	prof_cnt_t too_low;		/* # times a histogram tick was too low */
	prof_cnt_t too_high;		/* # times a histogram tick was too high */
	prof_cnt_t prof_overflow;	/* # times a prof count field overflowed */
	prof_cnt_t gprof_overflow;	/* # times a gprof count field overflowed */

					/* allocation statistics */
	prof_uptrint_t num_alloc  [(int)ACONTEXT_MAX];	/* # allocations */
	prof_uptrint_t bytes_alloc[(int)ACONTEXT_MAX];	/* bytes allocated */
	prof_uptrint_t num_context[(int)ACONTEXT_MAX];	/* # contexts */
	prof_uptrint_t wasted     [(int)ACONTEXT_MAX];	/* wasted bytes */
	prof_uptrint_t overhead   [(int)ACONTEXT_MAX];	/* overhead bytes */

	prof_uptrint_t buckets[MAX_BUCKETS+1]; /* # hash indexes that have n buckets */
	prof_cnt_t     cache_hits[MAX_CACHE];  /* # times nth cache entry matched */

	prof_cnt_t stats_unused[64];	/* reserved for future use */
};

#define PROFILE_MAJOR_VERSION 1
#define PROFILE_MINOR_VERSION 1

/*
 * Machine dependent fields.
 */

struct profile_md {
	int major_version;		/* major version number */
	int minor_version;		/* minor version number */
	size_t md_size;			/* size of profile_md structure */
	struct hasharc **hash_ptr;	/* gprof hash table */
	size_t hash_size;		/* size of hash table */
	prof_uptrint_t num_cache;	/* # of cache entries */
	void (*save_mcount_ptr)(void);	/* save for _mcount_ptr */
	void (**mcount_ptr_ptr)(void);	/* pointer to _mcount_ptr */
	struct hasharc *dummy_ptr;	/* pointer to dummy gprof record */
	void *(*alloc_pages)(size_t);	/* pointer to _profile_alloc_pages */
	char num_buffer[PROF_CNT_DIGITS]; /* convert 64 bit ints to string */
	long md_unused[58];		/* add unused fields */
};

/*
 * Record information about each function call.  Specify
 * caller, caller's caller, and a unique label for use by
 * the profiling routines.
 */
extern void _prof_mcount(void);
extern void _gprof_mcount(void);
extern void _dummy_mcount(void);
extern void (*_mcount_ptr)(void);

/*
 * Function in profile-md.c to convert prof_cnt_t to string format (decimal & hex).
 */
extern char *_profile_cnt_to_decimal(char *, prof_uptrint_t, prof_uptrint_t);

#endif /* _PROFILE_MD_H */
