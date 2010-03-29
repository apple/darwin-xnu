/*
 * Copyright (c) 2003-2009 Apple Inc. All rights reserved.
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
#ifdef	PRIVATE

#ifndef _I386_CPU_CAPABILITIES_H
#define _I386_CPU_CAPABILITIES_H

#ifndef	__ASSEMBLER__
#include <stdint.h>
#endif
 
/*
 * This API only supported for Apple internal use.
 */

/* Bit definitions for _cpu_capabilities: */

#define	kHasMMX				0x00000001
#define	kHasSSE				0x00000002
#define	kHasSSE2			0x00000004
#define	kHasSSE3			0x00000008
#define	kCache32			0x00000010	/* cache line size is 32 bytes */
#define	kCache64			0x00000020
#define	kCache128			0x00000040
#define	kFastThreadLocalStorage		0x00000080	/* TLS ptr is kept in a user-mode-readable register */
#define kHasSupplementalSSE3		0x00000100
#define	k64Bit				0x00000200	/* processor supports EM64T (not what mode you're running in) */
#define	kHasSSE4_1			0x00000400
#define	kHasSSE4_2			0x00000800
#define	kInOrderPipeline		0x00002000	/* in-order execution */
#define	kSlow				0x00004000	/* tsc < nanosecond */
#define	kUP				0x00008000	/* set if (kNumCPUs == 1) */
#define	kNumCPUs			0x00FF0000	/* number of CPUs (see _NumCPUs() below) */

#define	kNumCPUsShift			16		/* see _NumCPUs() below */

#ifndef	__ASSEMBLER__
#include <sys/cdefs.h>

__BEGIN_DECLS
extern int  _get_cpu_capabilities( void );
__END_DECLS

inline static
int _NumCPUs( void )
{
	return (_get_cpu_capabilities() & kNumCPUs) >> kNumCPUsShift;
}

#endif /* __ASSEMBLER__ */


/*
 * The shared kernel/user "comm page(s)":
 *
 * The last several pages of every address space are reserved for the kernel/user
 * "comm area". During system initialization, the kernel populates the comm pages with
 * code customized for the particular processor and platform.
 *
 * Because Mach VM cannot map the last page of an address space, we don't use it.
 */
 
#define	_COMM_PAGE32_AREA_LENGTH	( 19 * 4096 )				/* reserved length of entire comm area */
#define _COMM_PAGE32_BASE_ADDRESS	( 0xfffec000 )				/* base address of allocated memory, -20 pages */
#define _COMM_PAGE32_START_ADDRESS	( 0xffff0000 )				/* address traditional commpage code starts on, -16 pages */
#define _COMM_PAGE32_AREA_USED		( 19 * 4096 )				/* this is the amt actually allocated */
#define _COMM_PAGE32_SIGS_OFFSET	0x8000					/* offset to routine signatures */

#define	_COMM_PAGE64_AREA_LENGTH	( 2 * 1024 * 1024 )			/* reserved length of entire comm area (2MB) */
#define _COMM_PAGE64_BASE_ADDRESS	( 0x00007fffffe00000ULL )		/* base address of allocated memory */
#define _COMM_PAGE64_START_ADDRESS	( _COMM_PAGE64_BASE_ADDRESS )		/* address traditional commpage code starts on */
#define _COMM_PAGE64_AREA_USED		( 2 * 4096 )				/* this is the amt actually populated */

/* no need for an Objective-C area on Intel */
#define _COMM_PAGE32_OBJC_SIZE		0ULL
#define _COMM_PAGE32_OBJC_BASE		0ULL
#define _COMM_PAGE64_OBJC_SIZE		0ULL
#define _COMM_PAGE64_OBJC_BASE		0ULL

#ifdef KERNEL_PRIVATE

/* Inside the kernel, comm page addresses are absolute addresses
 * assuming they are a part of the 32-bit commpage. They may
 * be mapped somewhere else, especially for the 64-bit commpage.
 */
#define _COMM_PAGE_START_ADDRESS	_COMM_PAGE32_START_ADDRESS
#define _COMM_PAGE_SIGS_OFFSET		_COMM_PAGE32_SIGS_OFFSET

#else /* !KERNEL_PRIVATE */

#if defined(__i386__)

#define	_COMM_PAGE_AREA_LENGTH		_COMM_PAGE32_AREA_LENGTH
#define _COMM_PAGE_BASE_ADDRESS		_COMM_PAGE32_BASE_ADDRESS
#define _COMM_PAGE_START_ADDRESS	_COMM_PAGE32_START_ADDRESS
#define _COMM_PAGE_AREA_USED		_COMM_PAGE32_AREA_USED
#define _COMM_PAGE_SIGS_OFFSET		_COMM_PAGE32_SIGS_OFFSET

#elif defined(__x86_64__)

#define	_COMM_PAGE_AREA_LENGTH		_COMM_PAGE64_AREA_LENGTH
#define _COMM_PAGE_BASE_ADDRESS		_COMM_PAGE64_BASE_ADDRESS
#define _COMM_PAGE_START_ADDRESS	_COMM_PAGE64_START_ADDRESS
#define _COMM_PAGE_AREA_USED		_COMM_PAGE64_AREA_USED

#else
#error architecture not supported
#endif
 
#endif /* !KERNEL_PRIVATE */

/* data in the comm page */
 
#define _COMM_PAGE_SIGNATURE		(_COMM_PAGE_START_ADDRESS+0x000)	/* first few bytes are a signature */
#define _COMM_PAGE_VERSION		(_COMM_PAGE_START_ADDRESS+0x01E)	/* 16-bit version# */
#define _COMM_PAGE_THIS_VERSION		11					/* version of the commarea format */
  
#define _COMM_PAGE_CPU_CAPABILITIES	(_COMM_PAGE_START_ADDRESS+0x020)	/* uint32_t _cpu_capabilities */
#define _COMM_PAGE_NCPUS		(_COMM_PAGE_START_ADDRESS+0x022)	/* uint8_t number of configured CPUs */
#define _COMM_PAGE_CACHE_LINESIZE	(_COMM_PAGE_START_ADDRESS+0x026)	/* uint16_t cache line size */

#define _COMM_PAGE_SCHED_GEN		(_COMM_PAGE_START_ADDRESS+0x028)	/* uint32_t scheduler generation number (count of pre-emptions) */
#define _COMM_PAGE_MEMORY_PRESSURE	(_COMM_PAGE_START_ADDRESS+0x02c)	/* uint32_t copy of vm_memory_pressure */
#define	_COMM_PAGE_SPIN_COUNT		(_COMM_PAGE_START_ADDRESS+0x030)	/* uint32_t max spin count for mutex's */

#define _COMM_PAGE_UNUSED1		(_COMM_PAGE_START_ADDRESS+0x034)	/* 12 unused bytes */

#ifdef KERNEL_PRIVATE

/* slots defined in all cases, but commpage setup code must not populate for 64-bit commpage */
#define _COMM_PAGE_2_TO_52		(_COMM_PAGE_START_ADDRESS+0x040)	/* double float constant 2**52 */
#define _COMM_PAGE_10_TO_6		(_COMM_PAGE_START_ADDRESS+0x048)	/* double float constant 10**6 */

#else /* !KERNEL_PRIVATE */

#if defined(__i386__)								/* following are not defined in 64-bit */
#define _COMM_PAGE_2_TO_52		(_COMM_PAGE_START_ADDRESS+0x040)	/* double float constant 2**52 */
#define _COMM_PAGE_10_TO_6		(_COMM_PAGE_START_ADDRESS+0x048)	/* double float constant 10**6 */
#else
#define _COMM_PAGE_UNUSED2		(_COMM_PAGE_START_ADDRESS+0x040)	/* 16 unused bytes */
#endif

#endif /* !KERNEL_PRIVATE */

#define	_COMM_PAGE_TIME_DATA_START	(_COMM_PAGE_START_ADDRESS+0x050)	/* base of offsets below (_NT_SCALE etc) */
#define _COMM_PAGE_NT_TSC_BASE		(_COMM_PAGE_START_ADDRESS+0x050)	/* used by nanotime() */
#define _COMM_PAGE_NT_SCALE		(_COMM_PAGE_START_ADDRESS+0x058)	/* used by nanotime() */
#define _COMM_PAGE_NT_SHIFT		(_COMM_PAGE_START_ADDRESS+0x05c)	/* used by nanotime() */
#define _COMM_PAGE_NT_NS_BASE		(_COMM_PAGE_START_ADDRESS+0x060)	/* used by nanotime() */
#define _COMM_PAGE_NT_GENERATION	(_COMM_PAGE_START_ADDRESS+0x068)	/* used by nanotime() */
#define _COMM_PAGE_GTOD_GENERATION	(_COMM_PAGE_START_ADDRESS+0x06c)	/* used by gettimeofday() */
#define _COMM_PAGE_GTOD_NS_BASE		(_COMM_PAGE_START_ADDRESS+0x070)	/* used by gettimeofday() */
#define _COMM_PAGE_GTOD_SEC_BASE	(_COMM_PAGE_START_ADDRESS+0x078)	/* used by gettimeofday() */

/* Warning: kernel commpage.h has a matching c typedef for the following.  They must be kept in sync.  */
/* These offsets are from _COMM_PAGE_TIME_DATA_START */

#define	_NT_TSC_BASE			0
#define	_NT_SCALE			8
#define	_NT_SHIFT			12
#define	_NT_NS_BASE			16
#define	_NT_GENERATION			24
#define	_GTOD_GENERATION		28
#define	_GTOD_NS_BASE			32
#define	_GTOD_SEC_BASE			40
 
 /* jump table (jmp to this address, which may be a branch to the actual code somewhere else) */
 /* When new jump table entries are added, corresponding symbols should be added below        */
 /* New slots should be allocated with at least 16-byte alignment. Some like bcopy require    */
 /* 32-byte alignment, and should be aligned as such in the assembly source before they are relocated */
#define _COMM_PAGE_COMPARE_AND_SWAP32   (_COMM_PAGE_START_ADDRESS+0x080)	/* compare-and-swap word */
#define _COMM_PAGE_COMPARE_AND_SWAP64   (_COMM_PAGE_START_ADDRESS+0x0c0)	/* compare-and-swap doubleword */
#define _COMM_PAGE_ENQUEUE              (_COMM_PAGE_START_ADDRESS+0x100)	/* enqueue */
#define _COMM_PAGE_DEQUEUE              (_COMM_PAGE_START_ADDRESS+0x140)	/* dequeue */
#define _COMM_PAGE_MEMORY_BARRIER       (_COMM_PAGE_START_ADDRESS+0x180)	/* memory barrier */
#define _COMM_PAGE_ATOMIC_ADD32         (_COMM_PAGE_START_ADDRESS+0x1a0)	/* add atomic word */
#define _COMM_PAGE_ATOMIC_ADD64         (_COMM_PAGE_START_ADDRESS+0x1c0)	/* add atomic doubleword */

#define	_COMM_PAGE_CPU_NUMBER		(_COMM_PAGE_START_ADDRESS+0x1e0)	/* user-level cpu_number() */

#define _COMM_PAGE_ABSOLUTE_TIME	(_COMM_PAGE_START_ADDRESS+0x200)	/* mach_absolute_time() */
#define _COMM_PAGE_SPINLOCK_TRY		(_COMM_PAGE_START_ADDRESS+0x220)	/* spinlock_try() */
#define _COMM_PAGE_SPINLOCK_LOCK	(_COMM_PAGE_START_ADDRESS+0x260)	/* spinlock_lock() */
#define _COMM_PAGE_SPINLOCK_UNLOCK	(_COMM_PAGE_START_ADDRESS+0x2a0)	/* spinlock_unlock() */
#define _COMM_PAGE_PTHREAD_GETSPECIFIC  (_COMM_PAGE_START_ADDRESS+0x2c0)	/* pthread_getspecific() */
#define _COMM_PAGE_GETTIMEOFDAY		(_COMM_PAGE_START_ADDRESS+0x2e0)	/* used by gettimeofday() */
#define _COMM_PAGE_FLUSH_DCACHE		(_COMM_PAGE_START_ADDRESS+0x4e0)	/* sys_dcache_flush() */
#define _COMM_PAGE_FLUSH_ICACHE		(_COMM_PAGE_START_ADDRESS+0x520)	/* sys_icache_invalidate() */
#define _COMM_PAGE_PTHREAD_SELF		(_COMM_PAGE_START_ADDRESS+0x580)	/* pthread_self() */

#define _COMM_PAGE_PREEMPT		(_COMM_PAGE_START_ADDRESS+0x5a0)	/* used by PFZ code */

#define _COMM_PAGE_RELINQUISH		(_COMM_PAGE_START_ADDRESS+0x5c0)	/* used by spinlocks */ 
#define _COMM_PAGE_BTS		        (_COMM_PAGE_START_ADDRESS+0x5e0)	/* bit test-and-set */
#define _COMM_PAGE_BTC			(_COMM_PAGE_START_ADDRESS+0x5f0)	/* bit test-and-clear */
 
#define _COMM_PAGE_BZERO		(_COMM_PAGE_START_ADDRESS+0x600)	/* bzero() */
#define _COMM_PAGE_BCOPY		(_COMM_PAGE_START_ADDRESS+0x780)	/* bcopy() */
#define	_COMM_PAGE_MEMCPY		(_COMM_PAGE_START_ADDRESS+0x7a0)	/* memcpy() */
#define	_COMM_PAGE_MEMMOVE		(_COMM_PAGE_START_ADDRESS+0x7a0)	/* memmove() */
#define	_COMM_PAGE_BCOPY_END		(_COMM_PAGE_START_ADDRESS+0xfff)	/* used by rosetta */

#define	_COMM_PAGE_MEMSET_PATTERN       (_COMM_PAGE_START_ADDRESS+0x1000)	/* used by nonzero memset() */
#define	_COMM_PAGE_LONGCOPY		(_COMM_PAGE_START_ADDRESS+0x1200)	/* used by bcopy() for very long operands */
#define	_COMM_PAGE_LONGCOPY_END		(_COMM_PAGE_START_ADDRESS+0x15ff)	/* used by rosetta */

#define _COMM_PAGE_BACKOFF		(_COMM_PAGE_START_ADDRESS+0x1600)	/* called from PFZ */
#define _COMM_PAGE_FIFO_ENQUEUE		(_COMM_PAGE_START_ADDRESS+0x1680)	/* FIFO enqueue */
#define _COMM_PAGE_FIFO_DEQUEUE		(_COMM_PAGE_START_ADDRESS+0x16c0)	/* FIFO dequeue */
#define	_COMM_PAGE_NANOTIME		(_COMM_PAGE_START_ADDRESS+0x1700)	/* nanotime() */
#define	_COMM_PAGE_MUTEX_LOCK		(_COMM_PAGE_START_ADDRESS+0x1780)	/* pthread_mutex_lock() */

#define	_COMM_PAGE_UNUSED5		(_COMM_PAGE_START_ADDRESS+0x17e0)	/* unused space for regular code up to 0x1c00 */

#define _COMM_PAGE_PFZ_START		(_COMM_PAGE_START_ADDRESS+0x1c00)	/* start of Preemption Free Zone */

#define _COMM_PAGE_PFZ_ENQUEUE		(_COMM_PAGE_START_ADDRESS+0x1c00)	/* internal routine for FIFO enqueue */
#define _COMM_PAGE_PFZ_DEQUEUE		(_COMM_PAGE_START_ADDRESS+0x1c80)	/* internal routine for FIFO dequeue */
#define	_COMM_PAGE_PFZ_MUTEX_LOCK	(_COMM_PAGE_START_ADDRESS+0x1d00)	/* internal routine for pthread_mutex_lock() */

#define	_COMM_PAGE_UNUSED6		(_COMM_PAGE_START_ADDRESS+0x1d80)	/* unused space for PFZ code up to 0x1fff */

#define _COMM_PAGE_PFZ_END		(_COMM_PAGE_START_ADDRESS+0x1fff)	/* end of Preemption Free Zone */

#define _COMM_PAGE_END			(_COMM_PAGE_START_ADDRESS+0x1fff)	/* end of common page - insert new stuff here */

/* _COMM_PAGE_COMPARE_AND_SWAP{32,64}B are not used on x86 and are
 * maintained here for source compatability.  These will be removed at
 * some point, so don't go relying on them. */
#define _COMM_PAGE_COMPARE_AND_SWAP32B  (_COMM_PAGE_START_ADDRESS+0xf80)	/* compare-and-swap word w barrier */
#define _COMM_PAGE_COMPARE_AND_SWAP64B  (_COMM_PAGE_START_ADDRESS+0xfc0)	/* compare-and-swap doubleword w barrier */

#ifdef __ASSEMBLER__
#ifdef __COMM_PAGE_SYMBOLS

#define CREATE_COMM_PAGE_SYMBOL(symbol_name, symbol_address)		\
				.org	(symbol_address - (_COMM_PAGE_START_ADDRESS & 0xFFFFE000)) ;\
symbol_name: nop

	.text		/* Required to make a well behaved symbol file */

	CREATE_COMM_PAGE_SYMBOL(___compare_and_swap32, _COMM_PAGE_COMPARE_AND_SWAP32)
	CREATE_COMM_PAGE_SYMBOL(___compare_and_swap64, _COMM_PAGE_COMPARE_AND_SWAP64)
	CREATE_COMM_PAGE_SYMBOL(___atomic_enqueue, _COMM_PAGE_ENQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___atomic_dequeue, _COMM_PAGE_DEQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___memory_barrier, _COMM_PAGE_MEMORY_BARRIER)
	CREATE_COMM_PAGE_SYMBOL(___atomic_add32, _COMM_PAGE_ATOMIC_ADD32)
	CREATE_COMM_PAGE_SYMBOL(___atomic_add64, _COMM_PAGE_ATOMIC_ADD64)
	CREATE_COMM_PAGE_SYMBOL(___cpu_number, _COMM_PAGE_CPU_NUMBER)
	CREATE_COMM_PAGE_SYMBOL(___mach_absolute_time, _COMM_PAGE_ABSOLUTE_TIME)
	CREATE_COMM_PAGE_SYMBOL(___spin_lock_try, _COMM_PAGE_SPINLOCK_TRY)
	CREATE_COMM_PAGE_SYMBOL(___spin_lock, _COMM_PAGE_SPINLOCK_LOCK)
	CREATE_COMM_PAGE_SYMBOL(___spin_unlock, _COMM_PAGE_SPINLOCK_UNLOCK)
	CREATE_COMM_PAGE_SYMBOL(___pthread_getspecific, _COMM_PAGE_PTHREAD_GETSPECIFIC)
	CREATE_COMM_PAGE_SYMBOL(___gettimeofday, _COMM_PAGE_GETTIMEOFDAY)
	CREATE_COMM_PAGE_SYMBOL(___sys_dcache_flush, _COMM_PAGE_FLUSH_DCACHE)
	CREATE_COMM_PAGE_SYMBOL(___sys_icache_invalidate, _COMM_PAGE_FLUSH_ICACHE)
	CREATE_COMM_PAGE_SYMBOL(___pthread_self, _COMM_PAGE_PTHREAD_SELF)
	CREATE_COMM_PAGE_SYMBOL(___pfz_preempt, _COMM_PAGE_PREEMPT)
	CREATE_COMM_PAGE_SYMBOL(___spin_lock_relinquish, _COMM_PAGE_RELINQUISH)
	CREATE_COMM_PAGE_SYMBOL(___bit_test_and_set, _COMM_PAGE_BTS)
	CREATE_COMM_PAGE_SYMBOL(___bit_test_and_clear, _COMM_PAGE_BTC)
	CREATE_COMM_PAGE_SYMBOL(___bzero, _COMM_PAGE_BZERO)
	CREATE_COMM_PAGE_SYMBOL(___bcopy, _COMM_PAGE_BCOPY)
	CREATE_COMM_PAGE_SYMBOL(___memcpy, _COMM_PAGE_MEMCPY)
/*	CREATE_COMM_PAGE_SYMBOL(___memmove, _COMM_PAGE_MEMMOVE) */
	CREATE_COMM_PAGE_SYMBOL(___memset_pattern, _COMM_PAGE_MEMSET_PATTERN)
	CREATE_COMM_PAGE_SYMBOL(___longcopy, _COMM_PAGE_LONGCOPY)
	CREATE_COMM_PAGE_SYMBOL(___backoff, _COMM_PAGE_BACKOFF)
	CREATE_COMM_PAGE_SYMBOL(___fifo_enqueue, _COMM_PAGE_FIFO_ENQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___fifo_dequeue, _COMM_PAGE_FIFO_DEQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___nanotime, _COMM_PAGE_NANOTIME)
	CREATE_COMM_PAGE_SYMBOL(___mutex_lock, _COMM_PAGE_MUTEX_LOCK)
	CREATE_COMM_PAGE_SYMBOL(___pfz_enqueue, _COMM_PAGE_PFZ_ENQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___pfz_dequeue, _COMM_PAGE_PFZ_DEQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___pfz_mutex_lock, _COMM_PAGE_PFZ_MUTEX_LOCK)
	CREATE_COMM_PAGE_SYMBOL(___end_comm_page, _COMM_PAGE_END)

	.data		/* Required to make a well behaved symbol file */
	.long	0	/* Required to make a well behaved symbol file */

#endif /* __COMM_PAGE_SYMBOLS */
#endif /* __ASSEMBLER__ */

#endif /* _I386_CPU_CAPABILITIES_H */
#endif /* PRIVATE */
