/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Revision 1.1.7.1  1997/09/22  17:41:24  barbou
 * 	MP+RT: protect cpu_number() usage against preemption.
 * 	[97/09/16            barbou]
 *
 * Revision 1.1.5.1  1995/01/06  19:53:37  devrcs
 * 	mk6 CR668 - 1.3b26 merge
 * 	new file for mk6
 * 	[1994/10/12  22:25:20  dwm]
 * 
 * Revision 1.1.2.2  1994/05/16  19:19:17  meissner
 * 	Add support for converting 64-bit integers to a decimal string.
 * 	Use the correct address (selfpc) when creating the prof header for gprof.
 * 	[1994/04/28  21:44:59  meissner]
 * 
 * Revision 1.1.2.1  1994/04/08  17:51:42  meissner
 * 	Make most stats 64 bits, except for things like memory allocation.
 * 	[1994/04/02  14:58:21  meissner]
 * 
 * 	Do not provide old mcount support under MK or server.
 * 	Fixup stats size so it is the same as in profile-md.h.
 * 	[1994/03/29  21:00:03  meissner]
 * 
 * 	Use faster sequence for overflow addition.
 * 	Keep {dummy,prof,gprof,old}_mcount counts in double precision.
 * 	Add kernel NCPUS > 1 support.
 * 	[1994/03/17  20:13:23  meissner]
 * 
 * 	Add gprof/prof overflow support
 * 	[1994/03/17  14:56:44  meissner]
 * 
 * 	Add size of histogram counters & unused fields to profile_profil struct
 * 	[1994/02/17  21:41:44  meissner]
 * 
 * 	Add too_low/too_high to profile_stats.
 * 	[1994/02/16  22:38:11  meissner]
 * 
 * 	Bump # allocation contexts to 32 from 16.
 * 	Store unique ptr address in gprof function header structure for _profile_reset.
 * 	Add new fields from profile-{internal,md}.h.
 * 	Align loop looking for an unlocked acontext.
 * 	Count # times a locked context block was found.
 * 	Expand copyright.
 * 	[1994/02/07  12:40:56  meissner]
 * 
 * 	Keep track of the number of times the kernel overflows the HISTCOUNTER counter.
 * 	[1994/02/03  20:13:23  meissner]
 * 
 * 	Add stats for {user,kernel,idle} mode in the kernel.
 * 	[1994/02/03  15:17:22  meissner]
 * 
 * 	No change.
 * 	[1994/02/03  00:58:49  meissner]
 * 
 * 	Combine _profile_{vars,stats,md}; Allow more than one _profile_vars.
 * 	[1994/02/01  12:03:56  meissner]
 * 
 * 	Move _mcount_ptr to be closer to other data declarations.
 * 	Add text_len to profile_profil structure for mk.
 * 	Split records_cnt into prof_cnt/gprof_cnt.
 * 	Always update prof_cnt/gprof_cnt even if not DO_STATS.
 * 	Add current/max cpu indicator to stats for kernel.
 * 	[1994/01/28  23:33:20  meissner]
 * 
 * 	Don't do 4+Lgotoff(lab), use separate labels.
 * 	Change GPROF_HASH_SHIFT to 9 (from 8).
 * 	[1994/01/26  22:00:59  meissner]
 * 
 * 	Fixup NO_RECURSIVE_ALLOC to do byte loads, not word loads.
 * 	[1994/01/26  20:30:57  meissner]
 * 
 * 	Move callback pointers into separate allocation context.
 * 	Add size fields for other structures to profile-vars.
 * 	Allocate string table as one large allocation.
 * 	Rewrite old mcount code once again.
 * 	Use multiply to make hash value, not divide.
 * 	Hash table is now a power of two.
 * 	[1994/01/26  20:23:32  meissner]
 * 
 * 	Cut hash table size back to 16189.
 * 	Add size fields to all structures.
 * 	Add major/minor version number to _profile_md.
 * 	Move allocation context block pointers to _profile_vars.
 * 	Move _gprof_dummy after _profile_md.
 * 	New function header code now falls into hash an element
 * 	to avoid having the hash code duplicated or use a macro.
 * 	Fix bug in _gprof_mcount with ELF shared libraries.
 * 	[1994/01/25  01:45:59  meissner]
 * 
 * 	Move init functions to C code; rearrange profil varaibles.
 * 	[1994/01/22  01:11:14  meissner]
 * 
 * 	No change.
 * 	[1994/01/20  20:56:43  meissner]
 * 
 * 	Fixup copyright.
 * 	[1994/01/18  23:07:39  meissner]
 * 
 * 	Make flags byte-sized.
 * 	Add have_bb flag.
 * 	Add init_format flag.
 * 	Always put word size multipler first in .space.
 * 	[1994/01/18  21:57:14  meissner]
 * 
 * 	Fix elfpic problems in last change.
 * 	[1994/01/16  14:04:26  meissner]
 * 
 * 	Rewrite gprof caching to be faster & not need a lock.
 * 	Record prof information for gprof too.
 * 	Bump reserved stats to 64.
 * 	Bump up hash table size 30799.
 * 	Conditionally use lock prefix.
 * 	Change most #ifdef's to #if.
 * 	DEBUG_PROFILE turns on stack frames now.
 * 	Conditionally add externs to gprof to determine where time is spent.
 * 	Prof_mcount uses xchgl to update function pointer.
 * 	[1994/01/15  18:40:33  meissner]
 * 
 * 	Fix a comment.
 * 	Separate statistics from debugging (though debugging turns it on).
 * 	Remove debug code that traces each gprof request.
 * 	[1994/01/15  00:59:02  meissner]
 * 
 * 	Move max hash bucket calculation into _gprof_write & put info in stats structure.
 * 	[1994/01/04  16:15:14  meissner]
 * 
 * 	Use _profile_printf to write diagnostics; add diag_stream to hold stream to write to.
 * 	[1994/01/04  15:37:44  meissner]
 * 
 * 	Add more allocation memory pools (gprof function hdrs in particular).
 * 	For prof, gprof arc, and gprof function hdrs, allocate 16 pages at a time.
 * 	Add major/minor version numbers to _profile_{vars,stats}.
 * 	Add # profil buckets field to _profil_stats.
 * 	[19
 * 
 * $EndLog$
 */

/*
 * Common 386 profiling module that is shared between the kernel, mach
 * servers, and the user space library.  Each environment includes
 * this file.
 */

	.file	"profile-asm.s"

#include <machine/asm.h>

/*
 * By default, debugging turns on statistics and stack frames.
 */

#if DEBUG_PROFILE
#ifndef DO_STATS
#define DO_STATS 1
#endif

#ifndef STACK_FRAMES
#define STACK_FRAMES 1
#endif
#endif

#ifndef OLD_MCOUNT
#define OLD_MCOUNT 0			/* do not compile old code for mcount */
#endif

#ifndef DO_STATS
#define DO_STATS 1			/* compile in statistics code */
#endif

#ifndef DO_LOCK
#define	DO_LOCK 0			/* use lock; in front of increments */
#endif

#ifndef LOCK_STATS
#define LOCK_STATS DO_LOCK		/* update stats with lock set */
#endif

#ifndef STACK_FRAMES
#define STACK_FRAMES 0			/* create stack frames for debugger */
#endif

#ifndef NO_RECURSIVE_ALLOC
#define NO_RECURSIVE_ALLOC 0		/* check for recursive allocs */
					/* (not thread safe!) */
#endif

#ifndef MARK_GPROF
#define MARK_GPROF 0			/* add externs for gprof profiling */
#endif

#ifndef OVERFLOW
#define	OVERFLOW 1			/* add overflow checking support */
#endif

/*
 * Turn on the use of the lock prefix if desired.
 */

#ifndef LOCK
#if DO_LOCK
#define LOCK lock;
#else
#define LOCK
#endif
#endif

#ifndef SLOCK
#if LOCK_STATS
#define SLOCK LOCK
#else
#define SLOCK
#endif
#endif

/*
 * Double or single precision incrementing
 */

#if OVERFLOW
#define DINC(mem)		LOCK addl $1,mem; LOCK adcl $0,4+mem
#define DINC2(mem,mem2)		LOCK addl $1,mem; LOCK adcl $0,mem2
#define SDINC(mem)		SLOCK addl $1,mem; SLOCK adcl $0,4+mem
#define SDADD(val,mem)		SLOCK addl val,mem; SLOCK adcl $0,4+mem
#define SDADDNEG(val,mem)	SLOCK subl val,mem; SLOCK adcl $0,4+mem
#define SDSUB(val,mem)		SLOCK subl val,mem; SLOCK sbbl $0,4+mem

#else
#define DINC(mem)		LOCK incl mem
#define DINC2(mem,mem2)		LOCK incl mem
#define SDINC(mem)		SLOCK incl mem
#define	SDADD(val,mem)		SLOCK addl val,mem
#define	SDADDNEG(val,mem)	SLOCK subl val,mem
#define	SDSUB(val,mem)		SLOCK subl val,mem
#endif

/*
 * Stack frame support so that debugger traceback works.
 */

#if STACK_FRAMES
#define	ENTER	pushl %ebp; movl %esp,%ebp
#define	LEAVE0	popl %ebp
#define	Estack	4
#else
#define	ENTER
#define	LEAVE0
#define	Estack	0
#endif

/*
 * Gprof profiling.
 */

#if MARK_GPROF
#define MARK(name) .globl EXT(name); ELF_FUNC(EXT(name)); ELF_SIZE(EXT(name),0); LEXT(name)
#else
#define MARK(name)
#endif

/*
 * Profiling allocation context block.  Each time memory is needed, the
 * allocator loops until it finds an unlocked context block, and allocates
 * from that block.  If no context blocks are available, a new memory
 * pool is allocated, and added to the end of the chain.
 */

LCL(A_next)		= 0			/* next context block link (must be 0) */
LCL(A_plist)		= LCL(A_next)+4		/* head of page list for context block */
LCL(A_lock)		= LCL(A_plist)+4	/* lock word */
LCL(A_size)		= LCL(A_lock)+4		/* size of context block */

#define	A_next		LCL(A_next)
#define	A_plist		LCL(A_plist)
#define	A_lock		LCL(A_lock)
#define	A_size		LCL(A_size)

/*
 * Allocation contexts used.
 */

LCL(C_prof)		= 0			/* prof records */
LCL(C_gprof)		= 1			/* gprof arc records */
LCL(C_gfunc)		= 2			/* gprof function headers */
LCL(C_misc)		= 3			/* misc. allocations */
LCL(C_profil)		= 4			/* memory for profil */
LCL(C_dci)		= 5			/* memory for dci */
LCL(C_bb)		= 6			/* memory for basic blocks */
LCL(C_callback)		= 7			/* memory for callbacks */
LCL(C_max)		= 32			/* # allocation contexts */

#define	C_prof		LCL(C_prof)
#define	C_gprof		LCL(C_gprof)
#define	C_gfunc		LCL(C_gfunc)
#define	C_max		LCL(C_max)

/*
 * Linked list of memory allocations.
 */

LCL(M_first)		= 0			/* pointer to first byte available */
LCL(M_ptr)		= LCL(M_first)+4	/* pointer to next available byte */
LCL(M_next)		= LCL(M_ptr)+4		/* next page allocated */
LCL(M_nfree)		= LCL(M_next)+4		/* # bytes available */
LCL(M_nalloc)		= LCL(M_nfree)+4	/* # bytes allocated */
LCL(M_num)		= LCL(M_nalloc)+4	/* # allocations done on this page */
LCL(M_size)		= LCL(M_num)+4		/* size of page header */

#define	M_first		LCL(M_first)
#define	M_ptr		LCL(M_ptr)
#define	M_next		LCL(M_next)
#define	M_nfree		LCL(M_nfree)
#define	M_nalloc	LCL(M_nalloc)
#define	M_num		LCL(M_num)
#define	M_size		LCL(M_size)

/*
 * Prof data type.
 */

LCL(P_addr)		= 0			/* function address */
LCL(P_count)		= LCL(P_addr)+4		/* # times function called */
LCL(P_overflow)		= LCL(P_count)+4	/* # times count overflowed */
LCL(P_size)		= LCL(P_overflow)+4	/* size of prof data type */

#define	P_addr		LCL(P_addr)
#define	P_count		LCL(P_count)
#define	P_overflow	LCL(P_overflow)
#define	P_size		LCL(P_size)

/*
 * Gprof data type.
 */

LCL(G_next)		= 0			/* next hash link (must be 0) */
LCL(G_frompc)		= LCL(G_next)+4		/* caller's caller */
LCL(G_selfpc)		= LCL(G_frompc)+4	/* caller's address */
LCL(G_count)		= LCL(G_selfpc)+4	/* # times arc traversed */
LCL(G_overflow)		= LCL(G_count)+4	/* # times count overflowed */
LCL(G_size)		= LCL(G_overflow)+4	/* size of gprof data type */

#define	G_next		LCL(G_next)
#define	G_frompc	LCL(G_frompc)
#define	G_selfpc	LCL(G_selfpc)
#define	G_count		LCL(G_count)
#define	G_overflow	LCL(G_overflow)
#define	G_size		LCL(G_size)

/*
 * Gprof header.
 *
 * At least one header is allocated for each unique function that is profiled.
 * In order to save time calculating the hash value, the last H_maxcache
 * distinct arcs are cached within this structure.  Also, to avoid loading
 * the GOT when searching the hash table, we copy the hash pointer to this
 * structure, so that we only load the GOT when we need to allocate an arc.
 */

LCL(H_maxcache)		= 3			/* # of cache table entries */
LCL(H_csize)		= 4*LCL(H_maxcache)	/* size of each cache array */

LCL(H_hash_ptr)		= 0			/* hash table to use */
LCL(H_unique_ptr)	= LCL(H_hash_ptr)+4	/* function unique pointer */
LCL(H_prof)		= LCL(H_unique_ptr)+4	/* prof statistics */
LCL(H_cache_ptr)	= LCL(H_prof)+P_size	/* cache table of element pointers */
LCL(H_size)		= LCL(H_cache_ptr)+LCL(H_csize)	/* size of gprof header type */

#define	H_maxcache	LCL(H_maxcache)
#define	H_csize		LCL(H_csize)
#define	H_hash_ptr	LCL(H_hash_ptr)
#define	H_unique_ptr	LCL(H_unique_ptr)
#define	H_prof		LCL(H_prof)
#define	H_cache_ptr	LCL(H_cache_ptr)
#define	H_size		LCL(H_size)

/*
 * Number of digits needed to write a 64 bit number including trailing null.
 * (rounded up to be divisable by 4).
 */

#define N_digit		24


	.data

/*
 * Default gprof hash table size, which must be a power of two.
 * The shift specifies how many low order bits to eliminate when
 * calculating the hash value.
 */

#ifndef GPROF_HASH_SIZE
#define GPROF_HASH_SIZE 16384
#endif

#ifndef GPROF_HASH_SHIFT
#define	GPROF_HASH_SHIFT 9
#endif

#define GPROF_HASH_MASK (GPROF_HASH_SIZE-1)

DATA(_profile_hash_size)
	.long	GPROF_HASH_SIZE
ENDDATA(_profile_hash_size)



/*
 * Pointer that the compiler uses to call to the appropriate mcount function.
 */

DATA(_mcount_ptr)
	.long	EXT(_dummy_mcount)
ENDDATA(_mcount_ptr)

/*
 * Global profile variables.  The structure that accesses this in C is declared
 * in profile-internal.h.  All items in .data that follow this will be used as
 * one giant record, and each unique machine, thread, kgmon output or what have
 * you will create a separate instance.  Typically there is only one instance
 * which will be the memory laid out below.
 */

LCL(var_major_version)	= 0				/* major version number */
LCL(var_minor_version)	= LCL(var_major_version)+4	/* minor version number */
LCL(vars_size)		= LCL(var_minor_version)+4	/* size of _profile_vars structure */
LCL(plist_size)		= LCL(vars_size)+4		/* size of page_list structure */
LCL(acontext_size)	= LCL(plist_size)+4		/* size of allocation contexts */
LCL(callback_size)	= LCL(acontext_size)+4		/* size of callback structure */
LCL(type)		= LCL(callback_size)+4		/* profile type (gprof, prof) */
LCL(error_msg)		= LCL(type)+4			/* error message for perror */
LCL(filename)		= LCL(error_msg)+4		/* filename to write to */
LCL(str_ptr)		= LCL(filename)+4		/* string table pointer */
LCL(stream)		= LCL(str_ptr)+4		/* stdio stream to write to */
LCL(diag_stream)	= LCL(stream)+4			/* stdio stream to write diagnostics to */
LCL(fwrite_func)	= LCL(diag_stream)+4		/* function like fwrite to output bytes */
LCL(page_size)		= LCL(fwrite_func)+4		/* page size in bytes */
LCL(str_bytes)		= LCL(page_size)+4		/* # bytes in string table */
LCL(str_total)		= LCL(str_bytes)+4		/* # total bytes allocated for string table */
LCL(clock_ticks)	= LCL(str_total)+4		/* # clock ticks per second */

							/* profil variables */
LCL(profil_start)	= LCL(clock_ticks)+4		/* start of profil variables */
LCL(lowpc)		= LCL(clock_ticks)+4		/* lowest address */
LCL(highpc)		= LCL(lowpc)+4			/* highest address */
LCL(text_len)		= LCL(highpc)+4			/* highpc-lowpc */
LCL(profil_len)		= LCL(text_len)+4		/* size of profil buffer */
LCL(counter_size)	= LCL(profil_len)+4		/* size of indivual counter */
LCL(scale)		= LCL(counter_size)+4		/* scale factor */
LCL(profil_unused)	= LCL(scale)+4			/* unused fields */
LCL(profil_end)		= LCL(profil_unused)+4*8	/* end of profil_info structure */
LCL(profil_buf)		= LCL(profil_end)		/* buffer for profil */

							/* Output selection func ptrs */
LCL(output_init)	= LCL(profil_buf)+4		/* Initialization */
LCL(output)		= LCL(output_init)+4		/* Write out profiling info */
LCL(output_ptr)		= LCL(output)+4			/* Output specific data ptr */

							/* Memory allocation support */
LCL(acontext)		= LCL(output_ptr)+4		/* pointers to allocation context blocks */

LCL(bogus_func)		= LCL(acontext)+4*C_max		/* function to use if gprof arc is bad */
LCL(vars_unused)	= LCL(bogus_func)+4		/* future growth */

							/* flags */
LCL(init)		= LCL(vars_unused)+4*63		/* whether initializations were done */
LCL(active)		= LCL(init)+1			/* whether profiling is active */
LCL(do_profile)		= LCL(active)+1			/* whether to do profiling */
LCL(use_dci)		= LCL(do_profile)+1		/* whether to use DCI */
LCL(use_profil)		= LCL(use_dci)+1		/* whether to use profil */
LCL(recursive_alloc)	= LCL(use_profil)+1		/* alloc called recursively */
LCL(output_uarea)	= LCL(recursive_alloc)+1	/* output uarea */
LCL(output_stats)	= LCL(output_uarea)+1		/* output stats info */
LCL(output_clock)	= LCL(output_stats)+1		/* output the clock ticks */
LCL(multiple_sections)	= LCL(output_clock)+1		/* multiple sections are ok */
LCL(have_bb)		= LCL(multiple_sections)+1	/* whether we have basic block data */
LCL(init_format)	= LCL(have_bb)+1		/* The output format has been chosen */
LCL(debug)		= LCL(init_format)+1		/* Whether or not we are debugging */
LCL(check_funcs)	= LCL(debug)+1			/* Whether to check functions for validity */
LCL(flag_unused)	= LCL(check_funcs)+1		/* unused flags */
LCL(end_of_vars)	= LCL(flag_unused)+62		/* size of machine independent vars */

/*
 * Data that contains profile statistics that can be dumped out
 * into the {,g}mon.out file.  This is defined in profile-md.h.
 */

LCL(stats_start)	= LCL(end_of_vars)		/* start of stats substructure */
LCL(stats_major_version)= LCL(stats_start)		/* major version number */
LCL(stats_minor_version)= LCL(stats_major_version)+4	/* minor version number */
LCL(stats_size)		= LCL(stats_minor_version)+4	/* size of _profile_stats structure */
LCL(profil_buckets)	= LCL(stats_size)+4		/* # profil buckets */
LCL(my_cpu)		= LCL(profil_buckets)+4		/* identify which cpu/thread this is */
LCL(max_cpu)		= LCL(my_cpu)+4			/* identify which cpu/thread this is */
LCL(prof_records)	= LCL(max_cpu)+4		/* # of profiled functions */
LCL(gprof_records)	= LCL(prof_records)+4		/* # of gprof arcs created */
LCL(hash_buckets)	= LCL(gprof_records)+4		/* max gprof hash buckets on a chain */
LCL(bogus_count)	= LCL(hash_buckets)+4		/* # bogus functions found in gprof */

LCL(cnt)		= LCL(bogus_count)+4		/* # of _{prof,gprof}_mcount calls */
LCL(dummy)		= LCL(cnt)+8			/* # of _dummy_mcount calls */
LCL(old_mcount)		= LCL(dummy)+8			/* # of old mcount calls */
LCL(hash_search)	= LCL(old_mcount)+8		/* # gprof hash buckets searched */
LCL(hash_num)		= LCL(hash_search)+8		/* # times hash table searched */
LCL(user_ticks)		= LCL(hash_num)+8		/* # ticks within user space */
LCL(kernel_ticks)	= LCL(user_ticks)+8		/* # ticks within kernel space */
LCL(idle_ticks)		= LCL(kernel_ticks)+8		/* # ticks cpu was idle */
LCL(overflow_ticks)	= LCL(idle_ticks)+8		/* # ticks where histcounter overflowed */
LCL(acontext_locked)	= LCL(overflow_ticks)+8		/* # times an acontext was locked */
LCL(too_low)		= LCL(acontext_locked)+8	/* # times histogram tick too low */
LCL(too_high)		= LCL(too_low)+8		/* # times histogram tick too low */
LCL(prof_overflow)	= LCL(too_high)+8		/* # times the prof count field overflowed */
LCL(gprof_overflow)	= LCL(prof_overflow)+8		/* # times the gprof count field overflowed */
LCL(num_alloc)		= LCL(gprof_overflow)+8		/* # allocations in each context */
LCL(bytes_alloc)	= LCL(num_alloc)+4*C_max	/* bytes allocated in each context */
LCL(num_context)	= LCL(bytes_alloc)+4*C_max	/* # allocation context blocks */
LCL(wasted)		= LCL(num_context)+4*C_max	/* # bytes wasted */
LCL(overhead)		= LCL(wasted)+4*C_max		/* # bytes of overhead */
LCL(buckets)		= LCL(overhead)+4*C_max		/* # hash indexes that have n buckets */
LCL(cache_hits1)	= LCL(buckets)+4*10		/* # gprof cache hits in bucket #1 */
LCL(cache_hits2)	= LCL(cache_hits1)+8		/* # gprof cache hits in bucket #2 */
LCL(cache_hits3)	= LCL(cache_hits2)+8		/* # gprof cache hits in bucket #3 */
LCL(stats_unused)	= LCL(cache_hits3)+8		/* reserved for future use */
LCL(stats_end)		= LCL(stats_unused)+8*64	/* end of stats structure */

/*
 * Machine dependent variables that no C file should access (except for
 * profile-md.c).
 */

LCL(md_start)		= LCL(stats_end)		/* start of md structure */
LCL(md_major_version)	= LCL(md_start)			/* major version number */
LCL(md_minor_version)	= LCL(md_major_version)+4	/* minor version number */
LCL(md_size)		= LCL(md_minor_version)+4	/* size of _profile_stats structure */
LCL(hash_ptr)		= LCL(md_size)+4		/* gprof hash pointer */
LCL(hash_size)		= LCL(hash_ptr)+4		/* gprof hash size */
LCL(num_cache)		= LCL(hash_size)+4		/* # of cache entries */
LCL(save_mcount_ptr)	= LCL(num_cache)+4		/* save for mcount_ptr when suspending profiling */
LCL(mcount_ptr_ptr)	= LCL(save_mcount_ptr)+4	/* pointer to _mcount_ptr */
LCL(dummy_ptr)		= LCL(mcount_ptr_ptr)+4		/* pointer to gprof_dummy */
LCL(alloc_pages)	= LCL(dummy_ptr)+4		/* allocate more memory */
LCL(num_buffer)		= LCL(alloc_pages)+4		/* buffer to convert 64 bit ints in */
LCL(md_unused)		= LCL(num_buffer)+N_digit	/* unused fields */
LCL(md_end)		= LCL(md_unused)+4*58		/* end of md structure */
LCL(total_size)		= LCL(md_end)			/* size of entire structure */

/*
 * Size of the entire _profile_vars structure.
 */

DATA(_profile_size)
	.long	LCL(total_size)
ENDDATA(_profile_size)

/*
 * Size of the statistics substructure.
 */

DATA(_profile_stats_size)
	.long	LCL(stats_end)-LCL(stats_start)
ENDDATA(_profile_stats_size)

/*
 * Size of the profil info substructure.
 */

DATA(_profile_profil_size)
	.long	LCL(profil_end)-LCL(profil_start)
ENDDATA(_profile_profil_size)

/*
 * Size of the machine dependent substructure.
 */

DATA(_profile_md_size)
	.long	LCL(md_end)-LCL(md_start)
ENDDATA(_profile_profil_size)

/*
 * Whether statistics are supported.
 */

DATA(_profile_do_stats)
	.long	DO_STATS
ENDDATA(_profile_do_stats)

	.text

/*
 * Map LCL(xxx) -> into simpler names
 */

#define	V_acontext		LCL(acontext)
#define	V_acontext_locked	LCL(acontext_locked)
#define	V_alloc_pages		LCL(alloc_pages)
#define	V_bogus_func		LCL(bogus_func)
#define	V_bytes_alloc		LCL(bytes_alloc)
#define	V_cache_hits1		LCL(cache_hits1)
#define	V_cache_hits2		LCL(cache_hits2)
#define	V_cache_hits3		LCL(cache_hits3)
#define	V_cnt			LCL(cnt)
#define	V_cnt_overflow		LCL(cnt_overflow)
#define	V_check_funcs		LCL(check_funcs)
#define	V_dummy			LCL(dummy)
#define	V_dummy_overflow	LCL(dummy_overflow)
#define	V_dummy_ptr		LCL(dummy_ptr)
#define	V_gprof_records		LCL(gprof_records)
#define	V_hash_num		LCL(hash_num)
#define	V_hash_ptr		LCL(hash_ptr)
#define	V_hash_search		LCL(hash_search)
#define	V_mcount_ptr_ptr	LCL(mcount_ptr_ptr)
#define	V_num_alloc		LCL(num_alloc)
#define	V_num_buffer		LCL(num_buffer)
#define	V_num_context		LCL(num_context)
#define	V_old_mcount		LCL(old_mcount)
#define	V_old_mcount_overflow	LCL(old_mcount_overflow)
#define	V_overhead		LCL(overhead)
#define	V_page_size		LCL(page_size)
#define	V_prof_records		LCL(prof_records)
#define	V_recursive_alloc	LCL(recursive_alloc)
#define	V_wasted		LCL(wasted)

/*
 * Loadup %ebx with the address of _profile_vars.  On a multiprocessor, this
 * will loads up the appropriate machine's _profile_vars structure.
 * For ELF shared libraries, rely on the fact that we won't need a GOT,
 * except to load this pointer.
 */

#if defined (MACH_KERNEL)
#define ASSEMBLER
#include <i386/mp.h>

#if SQT
#include <i386/SQT/asm_macros.h>
#endif

#ifndef CPU_NUMBER
#error "Cannot determine how to get CPU number"
#endif

#define Vload	CPU_NUMBER(%ebx); movl EXT(_profile_vars_cpus)(,%ebx,4),%ebx

#else	/* not kernel */
#define	Vload	Gload; Egaddr(%ebx,_profile_vars)
#endif


/*
 * Allocate some memory for profiling.  This memory is guaranteed to
 * be zero.
 * %eax contains the memory size requested and will contain ptr on exit.
 * %ebx contains the address of the appropriate profile_vars structure.
 * %ecx is the number of the memory pool to allocate from (trashed on exit).
 * %edx is trashed.
 * %esi is preserved.
 * %edi is preserved.
 * %ebp is preserved.
 */

Entry(_profile_alloc_asm)
	ENTER
	pushl	%esi
	pushl	%edi

	movl	%ecx,%edi			/* move context number to saved reg */

#if NO_RECURSIVE_ALLOC
	movb	$-1,%cl
	xchgb	%cl,V_recursive_alloc(%ebx)
	cmpb	$0,%cl
	je	LCL(no_recurse)

	int	$3

	.align	ALIGN
LCL(no_recurse):
#endif

	leal	V_acontext(%ebx,%edi,4),%ecx

	/* Loop looking for a free allocation context. */
	/* %eax = size, %ebx = vars addr, %ecx = ptr to allocation context to try */
	/* %edi = context number */

	.align	ALIGN
LCL(alloc_loop):
	movl	%ecx,%esi			/* save ptr in case no more contexts */
	movl	A_next(%ecx),%ecx		/* next context block */
	cmpl	$0,%ecx
	je	LCL(alloc_context)		/* need to allocate a new context block */

	movl	$-1,%edx
	xchgl	%edx,A_lock(%ecx)		/* %edx == 0 if context available */

#if DO_STATS
	SDADDNEG(%edx,V_acontext_locked(%ebx))	/* increment counter if lock was held */
#endif

	cmpl	$0,%edx
	jne	LCL(alloc_loop)			/* go back if this context block is not available */

	/* Allocation context found (%ecx), now allocate. */
	movl	A_plist(%ecx),%edx		/* pointer to current block */
	cmpl	$0,%edx				/* first allocation? */
	je	LCL(alloc_new)

	cmpl	%eax,M_nfree(%edx)		/* see if we have enough space */
	jl	LCL(alloc_new)			/* jump if not enough space */

	/* Allocate from local block (and common exit) */
	/* %eax = bytes to allocate, %ebx = GOT, %ecx = context, %edx = memory block */
	/* %edi = context number */

	.align	ALIGN
LCL(alloc_ret):

#if DO_STATS
	SLOCK incl V_num_alloc(%ebx,%edi,4)	/* update global counters */
	SLOCK addl %eax,V_bytes_alloc(%ebx,%edi,4)
	SLOCK subl %eax,V_wasted(%ebx,%edi,4)
#endif

	movl	M_ptr(%edx),%esi		/* pointer return value */
	subl	%eax,M_nfree(%edx)		/* decrement bytes remaining */
	addl	%eax,M_nalloc(%edx)		/* increment bytes allocated */
	incl	M_num(%edx)			/* increment # allocations */
	addl	%eax,M_ptr(%edx)		/* advance pointer */
	movl	$0,A_lock(%ecx)			/* unlock context block */
	movl	%esi,%eax			/* return pointer */

#if NO_RECURSIVE_ALLOC
	movb	$0,V_recursive_alloc(%ebx)
#endif

	popl	%edi
	popl	%esi
	LEAVE0
	ret					/* return to the caller */

	/* Allocate space in whole number of pages */
	/* %eax = bytes to allocate, %ebx = vars address, %ecx = context */
	/* %edi = context number */

	.align	ALIGN
LCL(alloc_new):
	pushl	%eax				/* save regs */
	pushl	%ecx
	movl	V_page_size(%ebx),%edx
	addl	$(M_size-1),%eax		/* add in overhead size & subtract 1 */
	decl	%edx				/* page_size - 1 */
	addl	%edx,%eax			/* round up to whole number of pages */
	notl	%edx
	andl	%edx,%eax
	leal	-M_size(%eax),%esi		/* save allocation size */
	pushl	%eax				/* argument to _profile_alloc_pages */
	call	*V_alloc_pages(%ebx)		/* allocate some memory */
	addl	$4,%esp				/* pop off argument */

#if DO_STATS
	SLOCK addl %esi,V_wasted(%ebx,%edi,4)	/* udpate global counters */
	SLOCK addl $(M_size),V_overhead(%ebx,%edi,4)
#endif

	popl	%ecx				/* context block */
	movl	%eax,%edx			/* memory block pointer */
	movl	%esi,M_nfree(%edx)		/* # free bytes */
	addl	$(M_size),%eax			/* bump past overhead */
	movl	A_plist(%ecx),%esi		/* previous memory block or 0 */
	movl	%eax,M_first(%edx)		/* first space available */
	movl	%eax,M_ptr(%edx)		/* current address available */
	movl	%esi,M_next(%edx)		/* next memory block allocated */
	movl	%edx,A_plist(%ecx)		/* update current page list */
	popl	%eax				/* user size request */
	jmp	LCL(alloc_ret)			/* goto common return code */

	/* Allocate a context header in addition to memory block header + data */
	/* %eax = bytes to allocate, %ebx = GOT, %esi = ptr to store context ptr */
	/* %edi = context number */

	.align	ALIGN
LCL(alloc_context):
	pushl	%eax				/* save regs */
	pushl	%esi
	movl	V_page_size(%ebx),%edx
	addl	$(A_size+M_size-1),%eax		/* add in overhead size & subtract 1 */
	decl	%edx				/* page_size - 1 */
	addl	%edx,%eax			/* round up to whole number of pages */
	notl	%edx
	andl	%edx,%eax
	leal	-A_size-M_size(%eax),%esi	/* save allocation size */
	pushl	%eax				/* argument to _profile_alloc_pages */
	call	*V_alloc_pages(%ebx)		/* allocate some memory */
	addl	$4,%esp				/* pop off argument */

#if DO_STATS
	SLOCK incl V_num_context(%ebx,%edi,4)	/* bump # context blocks */
	SLOCK addl %esi,V_wasted(%ebx,%edi,4)	/* update global counters */
	SLOCK addl $(A_size+M_size),V_overhead(%ebx,%edi,4)
#endif

	movl	%eax,%ecx			/* context pointer */
	leal	A_size(%eax),%edx		/* memory block pointer */
	movl	%esi,M_nfree(%edx)		/* # free bytes */
	addl	$(A_size+M_size),%eax		/* bump past overhead */
	movl	%eax,M_first(%edx)		/* first space available */
	movl	%eax,M_ptr(%edx)		/* current address available */
	movl	$0,M_next(%edx)			/* next memory block allocated */
	movl	%edx,A_plist(%ecx)		/* head of memory block list */
	movl	$1,A_lock(%ecx)			/* set lock */
	popl	%esi				/* ptr to store context block link */
	movl	%ecx,%eax			/* context pointer temp */
	xchgl	%eax,A_next(%esi)		/* link into chain */
	movl	%eax,A_next(%ecx)		/* add links in case of threading */
	popl	%eax				/* user size request */
	jmp	LCL(alloc_ret)			/* goto common return code */

END(_profile_alloc_asm)

/*
 * C callable version of the profile memory allocator.
 * extern void *_profile_alloc(struct profile_vars *, size_t, acontext_type_t);
*/

Entry(_profile_alloc)
	ENTER
	pushl	%ebx
	movl	12+Estack(%esp),%eax		/* memory size */
	movl	8+Estack(%esp),%ebx		/* provile_vars address */
	addl	$3,%eax				/* round up to word boundary */
	movl	16+Estack(%esp),%ecx		/* which memory pool to allocate from */
	andl	$0xfffffffc,%eax
	call	EXT(_profile_alloc_asm)
	popl	%ebx
	LEAVE0
	ret
END(_profile_alloc)


/*
 * Dummy mcount routine that just returns.
 *
 *		+-------------------------------+
 *		|				|
 *		|				|
 *		| caller's caller stack,	|
 *		| saved registers, params.	|
 *		|				|
 *		|				|
 *		+-------------------------------+
 *		| caller's caller return addr.	|
 *		+-------------------------------+
 *	esp -->	| caller's return address	|
 *		+-------------------------------+
 *
 *	edx --> function unqiue LCL
 */

Entry(_dummy_mcount)
	ENTER

#if DO_STATS
	pushl	%ebx
	MP_DISABLE_PREEMPTION(%ebx)
	Vload
	SDINC(V_dummy(%ebx))
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret
END(_dummy_mcount)


/*
 * Entry point for System V based profiling, count how many times each function
 * is called.  The function label is passed in %edx, and the top two words on
 * the stack are the caller's address, and the caller's return address.
 *
 *		+-------------------------------+
 *		|				|
 *		|				|
 *		| caller's caller stack,	|
 *		| saved registers, params.	|
 *		|				|
 *		|				|
 *		+-------------------------------+
 *		| caller's caller return addr.	|
 *		+-------------------------------+
 *	esp -->	| caller's return address	|
 *		+-------------------------------+
 *
 *	edx --> function unique label
 *
 * We don't worry about the possibility about two threads calling
 * the same function for the first time simulataneously.  If that
 * happens, two records will be created, and one of the records
 * address will be stored in in the function unique label (which
 * is aligned by the compiler, so we don't have to watch out for
 * crossing page/cache boundaries).
 */

Entry(_prof_mcount)
	ENTER

#if DO_STATS
	pushl	%ebx
	MP_DISABLE_PREEMPTION(%ebx)
	Vload
	SDINC(V_cnt(%ebx))
#endif

	movl	(%edx),%eax			/* initialized? */
	cmpl	$0,%eax
	je	LCL(pnew)

	DINC2(P_count(%eax),P_overflow(%eax))	/* bump function count (double precision) */

#if DO_STATS
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret

	.align	ALIGN
LCL(pnew):

#if !DO_STATS
	pushl	%ebx
	MP_DISABLE_PREEMPTION(%ebx)
	Vload
#endif

	SLOCK incl V_prof_records(%ebx)
	pushl	%edx
	movl	$(P_size),%eax			/* allocation size */
	movl	$(C_prof),%ecx			/* allocation pool */
	call	EXT(_profile_alloc_asm)		/* allocate a new record */
	popl	%edx

	movl	Estack+4(%esp),%ecx		/* caller's address */
	movl	%ecx,P_addr(%eax)
	movl	$1,P_count(%eax)		/* call count */
	xchgl	%eax,(%edx)			/* update function header */
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
	LEAVE0
	ret

END(_prof_mcount)


/*
 * Entry point for BSD based graph profiling, count how many times each unique
 * call graph (caller + callee) is called.  The function label is passed in
 * %edx, and the top two words on the stack are the caller's address, and the
 * caller's return address.
 *
 *		+-------------------------------+
 *		|				|
 *		|				|
 *		| caller's caller stack,	|
 *		| saved registers, params.	|
 *		|				|
 *		|				|
 *		+-------------------------------+
 *		| caller's caller return addr.	|
 *		+-------------------------------+
 *	esp -->	| caller's return address	|
 *		+-------------------------------+
 *
 *	edx --> function unqiue label
 *
 * We don't worry about the possibility about two threads calling the same
 * function simulataneously.  If that happens, two records will be created, and
 * one of the records address will be stored in in the function unique label
 * (which is aligned by the compiler).
 *
 * By design, the gprof header is not locked.  Each of the cache pointers is
 * always a valid pointer (possibily to a null record), and if another thread
 * comes in and modifies the pointer, it does so automatically with a simple store.
 * Since all arcs are in the hash table, the caches are just to avoid doing
 * a multiplication in the common case, and if they don't match, the arcs will
 * still be found.
 */

Entry(_gprof_mcount)

	ENTER
	movl	Estack+4(%esp),%ecx		/* caller's caller address */

#if DO_STATS
	pushl	%ebx
	MP_DISABLE_PREEMPTION(%ebx)
	Vload
	SDINC(V_cnt(%ebx))			/* bump profile call counter (double int) */
#endif

	movl	(%edx),%eax			/* Gprof header allocated? */
	cmpl	$0,%eax
	je	LCL(gnew)			/* skip if first call */

	DINC2(H_prof+P_count(%eax),H_prof+P_overflow(%eax))	/* bump function count */

	/* See if this call arc is the same as the last time */
MARK(_gprof_mcount_cache1)
	movl	H_cache_ptr(%eax),%edx		/* last arc searched */
	cmpl	%ecx,G_frompc(%edx)		/* skip if not equal */
	jne	LCL(gcache2)

	/* Same as last time, increment and return */

	DINC2(G_count(%edx),G_overflow(%edx))	/* bump arc count */

#if DO_STATS
	SDINC(V_cache_hits1(%ebx))		/* update counter */
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret

	/* Search second cache entry */
	/* %eax = gprof func header, %ebx = vars address if DO_STATS, %ecx = caller's caller */
	/* %edx = first arc searched */
	/* %ebx if DO_STATS pushed on stack */

	.align	ALIGN
MARK(_gprof_mcount_cache2)
LCL(gcache2):
	pushl	%esi				/* get a saved register */
	movl	H_cache_ptr+4(%eax),%esi	/* 2nd arc to be searched */
	cmpl	%ecx,G_frompc(%esi)		/* skip if not equal */
	jne	LCL(gcache3)

	/* Element found, increment, reset last arc searched and return */

	DINC2(G_count(%esi),G_overflow(%esi))	/* bump arc count */

	movl	%esi,H_cache_ptr+0(%eax)	/* swap 1st and 2nd cached arcs */
	popl	%esi
	movl	%edx,H_cache_ptr+4(%eax)

#if DO_STATS
	SDINC(V_cache_hits2(%ebx))		/* update counter */
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret

	/* Search third cache entry */
	/* %eax = gprof func header, %ebx = vars address if DO_STATS, %ecx = caller's caller */
	/* %edx = first arc searched, %esi = second arc searched */
	/* %esi, %ebx if DO_STATS pushed on stack */

	.align	ALIGN
MARK(_gprof_mcount_cache3)
LCL(gcache3):
	pushl	%edi
	movl	H_cache_ptr+8(%eax),%edi	/* 3rd arc to be searched */
	cmpl	%ecx,G_frompc(%edi)		/* skip if not equal */
	jne	LCL(gnocache)

	/* Element found, increment, reset last arc searched and return */

	DINC2(G_count(%edi),G_overflow(%edi))	/* bump arc count */

	movl	%edi,H_cache_ptr+0(%eax)	/* make this 1st cached arc */
	movl	%esi,H_cache_ptr+8(%eax)
	movl	%edx,H_cache_ptr+4(%eax)
	popl	%edi
	popl	%esi

#if DO_STATS
	SDINC(V_cache_hits3(%ebx))		/* update counter */
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret

	/* No function context, allocate a new context */
	/* %ebx is the variables address if DO_STATS */
	/* %ecx is the caller's caller's address */
	/* %edx is the unique function pointer */
	/* %ebx if DO_STATS pushed on stack */

	.align	ALIGN
MARK(_gprof_mcount_new)
LCL(gnew):
	pushl	%esi
	pushl	%edi

#if !DO_STATS
	pushl	%ebx				/* Address of vars needed for alloc */
	MP_DISABLE_PREEMPTION(%ebx)
	Vload				       	/* stats already loaded address */
#endif

	SLOCK incl V_prof_records(%ebx)
	movl	%edx,%esi			/* save unique function ptr */
	movl	%ecx,%edi			/* and caller's caller address */
	movl	$(H_size),%eax			/* memory block size */
	movl	$(C_gfunc),%ecx			/* gprof function header memory pool */
	call	EXT(_profile_alloc_asm)

	movl	V_hash_ptr(%ebx),%ecx		/* copy hash_ptr to func header */
	movl	V_dummy_ptr(%ebx),%edx		/* dummy cache entry */
	movl	%ecx,H_hash_ptr(%eax)
	movl	%edx,H_cache_ptr+0(%eax)	/* store dummy cache ptrs */
	movl	%edx,H_cache_ptr+4(%eax)
	movl	%edx,H_cache_ptr+8(%eax)
	movl	%esi,H_unique_ptr(%eax)		/* remember function unique ptr */
	movl	Estack+12(%esp),%ecx		/* caller's address */
	movl	$1,H_prof+P_count(%eax)		/* function called once so far */
	movl	%ecx,H_prof+P_addr(%eax)	/* set up prof information */
	movl	%eax,(%esi)			/* update context block address */
	movl	%edi,%ecx			/* caller's caller address */
	movl	%edx,%esi			/* 2nd cached arc */

#if !DO_STATS
	popl	%ebx
#endif

	/* Fall through to add element to the hash table.  This may involve */
	/* searching a few hash table elements that don't need to be searched */
	/* since we have a new element, but it allows the hash table function */
	/* to be specified in only one place */

	/* Didn't find entry in cache, search the global hash table */
	/* %eax = gprof func header, %ebx = vars address if DO_STATS */
	/* %ecx = caller's caller */
	/* %edx, %esi = cached arcs that were searched */
	/* %edi, %esi, %ebx if DO_STATS pushed on stack */

	.align	ALIGN
MARK(_gprof_mcount_hash)
LCL(gnocache):

	pushl	%esi				/* save 2nd arc searched */
	pushl	%edx				/* save 1st arc searched */
	movl	%eax,%esi			/* save gprof func header */

#if DO_STATS
	SDINC(V_hash_num(%ebx))
	movl	Estack+20(%esp),%edi		/* caller's address */
#else
	movl	Estack+16(%esp),%edi		/* caller's address */
#endif
	movl	%ecx,%eax			/* caller's caller address */
	imull	%edi,%eax			/* multiply to get hash */
	movl	H_hash_ptr(%esi),%edx		/* hash pointer */
	shrl	$(GPROF_HASH_SHIFT),%eax	/* eliminate low order bits */
	andl	$(GPROF_HASH_MASK),%eax		/* mask to get hash value */
	leal	0(%edx,%eax,4),%eax		/* pointer to hash bucket */
	movl	%eax,%edx			/* save hash bucket address */

	/* %eax = old arc, %ebx = vars address if DO_STATS, %ecx = caller's caller */
	/* %edx = hash bucket address, %esi = gfunc ptr, %edi = caller's addr */
	/* 2 old arcs, %edi, %esi, %ebx if DO_STATS pushed on stack */

	.align	ALIGN
LCL(ghash):
	movl	G_next(%eax),%eax		/* get next hash element */
	cmpl	$0,%eax				/* end of line? */
	je	LCL(ghashnew)			/* skip if allocate new hash */

#if DO_STATS
	SDINC(V_hash_search(%ebx))
#endif

	cmpl	G_selfpc(%eax),%edi		/* loop back if not one we want */
	jne	LCL(ghash)

	cmpl	G_frompc(%eax),%ecx		/* loop back if not one we want */
	jne	LCL(ghash)

	/* Found an entry, increment count, set up for caching, and return */
	/* %eax = arc, %ebx = vars address if DO_STATS, %esi = func header */
	/* 2 old arcs, %edi, %esi, %ebx if DO_STATS pushed on stack */

	DINC2(G_count(%eax),G_overflow(%eax))	/* bump arc count */

	popl	%ecx				/* previous 1st arc searched */
	movl	%eax,H_cache_ptr+0(%esi)	/* this element is now 1st arc */
	popl	%edi				/* previous 2nd arc searched */
	movl	%ecx,H_cache_ptr+4(%esi)	/* new 2nd arc to be searched */
	movl	%edi,H_cache_ptr+8(%esi)	/* new 3rd arc to be searched */
	popl	%edi
	popl	%esi

#if DO_STATS
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret					/* return to user */

	/* Allocate new arc */
	/* %eax = old arc, %ebx = vars address if DO_STATS, %ecx = caller's caller */
	/* %edx = hash bucket address, %esi = gfunc ptr, %edi = caller's addr */
	/* 2 old arcs, %edi, %esi, %ebx if DO_STATS pushed on stack */

	.align	ALIGN
MARK(_gprof_mcount_hashnew)
LCL(ghashnew):

#if !DO_STATS
	pushl	%ebx				/* load address of vars if we haven't */
	MP_DISABLE_PREEMPTION(%ebx)
	Vload					/* already done so */
#endif

	SLOCK incl V_gprof_records(%ebx)
	pushl	%edx
	movl	%ecx,%edi			/* save caller's caller */
	movl	$(G_size),%eax			/* arc size */
	movl	$(C_gprof),%ecx			/* gprof memory pool */
	call	EXT(_profile_alloc_asm)
	popl	%edx

	movl	$1,G_count(%eax)		/* set call count */
	movl	Estack+20(%esp),%ecx		/* caller's address */
	movl	%edi,G_frompc(%eax)		/* caller's caller */
	movl	%ecx,G_selfpc(%eax)

#if !DO_STATS
	popl	%ebx				/* release %ebx if no stats */
#endif

	movl	(%edx),%ecx			/* first hash bucket */
	movl	%ecx,G_next(%eax)		/* update link */
	movl	%eax,%ecx			/* copy for xchgl */
	xchgl	%ecx,(%edx)			/* add to hash linked list */
	movl	%ecx,G_next(%eax)		/* update in case list changed */

	popl	%ecx				/* previous 1st arc searched */
	popl	%edi				/* previous 2nd arc searched */
	movl	%eax,H_cache_ptr+0(%esi)	/* this element is now 1st arc */
	movl	%ecx,H_cache_ptr+4(%esi)	/* new 2nd arc to be searched */
	movl	%edi,H_cache_ptr+8(%esi)	/* new 3rd arc to be searched */

	popl	%edi
	popl	%esi

#if DO_STATS
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
#endif

	LEAVE0
	ret					/* return to user */

END(_gprof_mcount)


/*
 * This function assumes that neither the caller or it's caller
 * has not omitted the frame pointer in order to get the caller's
 * caller.  The stack looks like the following at the time of the call:
 *
 *		+-------------------------------+
 *		|				|
 *		|				|
 *		| caller's caller stack,	|
 *		| saved registers, params.	|
 *		|				|
 *		|				|
 *		+-------------------------------+
 *		| caller's caller return addr.	|
 *		+-------------------------------+
 *	fp -->	| previous frame pointer	|
 *		+-------------------------------+
 *		|				|
 *		| caller's stack, saved regs,	|
 *		| params.			|
 *		|				|
 *		+-------------------------------+
 *	sp -->	| caller's return address	|
 *		+-------------------------------+
 *
 * Recent versions of the compiler put the address of the pointer
 * sized word in %edx.  Previous versions did not, but this code
 * does not support them.
 */

/*
 * Note that OSF/rose blew defining _mcount, since it prepends leading
 * underscores, and _mcount didn't have a second leading underscore.  However,
 * some of the kernel/server functions 'know' that mcount has a leading
 * underscore, so we satisfy both camps.
 */

#if OLD_MCOUNT
	.globl	mcount
	.globl	_mcount
	ELF_FUNC(mcount)
	ELF_FUNC(_mcount)
	.align	FALIGN
_mcount:
mcount:

	pushl	%ebx
	MP_DISABLE_PREEMPTION(%ebx)
	Vload

#if DO_STATS
	SDINC(V_old_mcount(%ebx))
#endif

	/* In calling the functions, we will actually leave 1 extra word on the */
	/* top of the stack, but generated code will not notice, since the function */
	/* uses a frame pointer */

	movl	V_mcount_ptr_ptr(%ebx),%ecx	/* address of mcount_ptr */
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
	movl	4(%ebp),%eax			/* caller's caller return address */
	xchgl	%eax,(%esp)			/* push & get return address */
	pushl	%eax				/* push return address */
	jmp	*(%ecx)				/* go to profile the function */

End(mcount)
End(_mcount)
#endif


#if !defined(KERNEL) && !defined(MACH_KERNEL)

/*
 * Convert a 64-bit integer to a string.
 * Arg #1 is a pointer to a string (at least 24 bytes) or NULL
 * Arg #2 is the low part of the 64-bit integer.
 * Arg #3 is the high part of the 64-bit integer.
 */

Entry(_profile_cnt_to_decimal)
	ENTER
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	Estack+16(%esp),%ebx		/* pointer or null */
	movl	Estack+20(%esp),%edi		/* low part of number */
	movl	$10,%ecx			/* divisor */
	cmpl	$0,%ebx				/* skip if pointer ok */
	jne	LCL(cvt_nonnull)

	MP_DISABLE_PREEMPTION(%ebx)
	Vload					/* get _profile_vars address */
	leal	V_num_buffer(%ebx),%ebx		/* temp buffer to use */

	.align	ALIGN
LCL(cvt_nonnull):
	addl	$(N_digit-1),%ebx		/* point string at end */
	movb	$0,0(%ebx)			/* null terminate string */

#if OVERFLOW
	movl	Estack+24(%esp),%esi		/* high part of number */
	cmpl	$0,%esi				/* any thing left in high part? */
	je	LCL(cvt_low)

	.align	ALIGN
LCL(cvt_high):
	movl	%esi,%eax			/* calculate high/10 & high%10 */
	xorl	%edx,%edx
	divl	%ecx
	movl	%eax,%esi

	movl	%edi,%eax			/* calculate (low + (high%10)*2^32) / 10 */
	divl	%ecx
	movl	%eax,%edi

	decl	%ebx				/* decrement string pointer */
	addl	$48,%edx			/* convert from 0..9 -> '0'..'9' */
	movb	%dl,0(%ebx)			/* store digit in string */
	cmpl	$0,%esi				/* any thing left in high part? */
	jne	LCL(cvt_high)

#endif	/* OVERFLOW */

	.align	ALIGN
LCL(cvt_low):
	movl	%edi,%eax			/* get low part into %eax */

	.align	ALIGN
LCL(cvt_low2):
	xorl	%edx,%edx			/* 0 */
	divl	%ecx				/* calculate next digit */
	decl	%ebx				/* decrement string pointer */
	addl	$48,%edx			/* convert from 0..9 -> '0'..'9' */
	movb	%dl,0(%ebx)			/* store digit in string */
	cmpl	$0,%eax				/* any more digits to convert? */
	jne	LCL(cvt_low2)

	movl	%ebx,%eax			/* return value */
	popl	%edi
	popl	%esi
	MP_ENABLE_PREEMPTION(%ebx)
	popl	%ebx
	LEAVE0
	ret

END(_profile_cnt_to_decimal)

#endif
