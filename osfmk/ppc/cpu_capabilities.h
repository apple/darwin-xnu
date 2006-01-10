/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
#ifdef	PRIVATE

#ifndef _PPC_CPU_CAPABILITIES_H
#define _PPC_CPU_CAPABILITIES_H

/* _cpu_capabilities
 *
 * This is the authoritative way to determine from user mode what
 * implementation-specific processor features are available.
 * This API is only supported for Apple internal use.
 */

#ifndef	__ASSEMBLER__
 
extern int _cpu_capabilities;
 
#endif /* __ASSEMBLER__ */

/* Bit definitions for _cpu_capabilities: */

#define	kHasAltivec				0x00000001
#define	k64Bit					0x00000002	// 64-bit GPRs
#define	kCache32				0x00000004	// cache line size is 32 bytes
#define	kCache64				0x00000008
#define	kCache128				0x00000010
#define	kDcbaRecommended		0x00000020	// PPC: dcba is available and recommended
#define	kDcbaAvailable			0x00000040	// PPC: dcba is available (but may or may not be recommended)
#define	kDataStreamsRecommended	0x00000080	// PPC: dst, dstt, dstst, dss, and dssall instructions available and recommended
#define	kDataStreamsAvailable	0x00000100	// PPC: dst, dstt, dstst, dss, and dssall instructions available (may or may not be rec'd)
#define	kDcbtStreamsRecommended	0x00000200	// PPC: enhanced dcbt instruction available and recommended
#define	kDcbtStreamsAvailable	0x00000400	// PPC: enhanced dcbt instruction available (but may or may not be recommended)
#define	kFastThreadLocalStorage	0x00000800	// TLS ptr is kept in a user-mode-readable register

#define	kUP						0x00008000	// set if (kNumCPUs == 1)
#define	kNumCPUs				0x00FF0000	// number of CPUs (see _NumCPUs() below)

#define	kNumCPUsShift			16			// see _NumCPUs() below

#define	kHasGraphicsOps			0x08000000	// PPC: has fres, frsqrte, and fsel instructions
#define	kHasStfiwx				0x10000000	// PPC: has stfiwx instruction
#define	kHasFsqrt				0x20000000	// PPC: has fsqrt and fsqrts instructions

#ifndef	__ASSEMBLER__
 
static __inline__ int _NumCPUs( void ) { return (_cpu_capabilities & kNumCPUs) >> kNumCPUsShift; }

#endif /* __ASSEMBLER__ */


/*
 * The shared kernel/user "comm page(s)":
 *
 * The last eight pages of every address space are reserved for the kernel/user
 * "comm area".  Because they can be addressed via a sign-extended 16-bit field,
 * it is particularly efficient to access code or data in the comm area with
 * absolute branches (ba, bla, bca) or absolute load/stores ("lwz r0,-4096(0)").
 * Because the comm area can be reached from anywhere, dyld is not needed.
 * Although eight pages are reserved, presently only two are populated and mapped.
 *
 * Routines on the comm page(s) can be thought of as the firmware for extended processor
 * instructions, whose opcodes are special forms of "bla".  Ie, they are cpu
 * capabilities.  During system initialization, the kernel populates the comm page with
 * code customized for the particular processor and platform.
 *
 * Because Mach VM cannot map the last page of an address space, the max length of
 * the comm area is seven pages.
 */
 
#define _COMM_PAGE_BASE_ADDRESS			(-8*4096)						// start at page -8, ie 0xFFFF8000
#define	_COMM_PAGE_AREA_LENGTH			( 7*4096)						// reserved length of entire comm area
#define	_COMM_PAGE_AREA_USED			( 2*4096)						// we use two pages so far

/* The Objective-C runtime fixed address page to optimize message dispatch */
#define _OBJC_PAGE_BASE_ADDRESS			(-20*4096)						// start at page -20, ie 0xFFFEC000
 
/* data in the comm page */
 
#define _COMM_PAGE_SIGNATURE			(_COMM_PAGE_BASE_ADDRESS+0x000)	// first few bytes are a signature
#define _COMM_PAGE_VERSION				(_COMM_PAGE_BASE_ADDRESS+0x01E)	// 16-bit version#
#define	_COMM_PAGE_THIS_VERSION			2								// this is version 2 of the commarea format
  
#define _COMM_PAGE_CPU_CAPABILITIES		(_COMM_PAGE_BASE_ADDRESS+0x020)	// mirror of extern int _cpu_capabilities
#define _COMM_PAGE_NCPUS				(_COMM_PAGE_BASE_ADDRESS+0x021)	// number of configured CPUs
#define _COMM_PAGE_ALTIVEC				(_COMM_PAGE_BASE_ADDRESS+0x024)	// nonzero if Altivec available
#define _COMM_PAGE_64_BIT				(_COMM_PAGE_BASE_ADDRESS+0x025)	// nonzero if 64-bit processor
#define _COMM_PAGE_CACHE_LINESIZE		(_COMM_PAGE_BASE_ADDRESS+0x026)	// cache line size (16-bit field)
 
#define _COMM_PAGE_UNUSED1				(_COMM_PAGE_BASE_ADDRESS+0x028)	// 24 unused bytes
 
#define _COMM_PAGE_2_TO_52				(_COMM_PAGE_BASE_ADDRESS+0x040)	// double float constant 2**52
#define _COMM_PAGE_10_TO_6				(_COMM_PAGE_BASE_ADDRESS+0x048)	// double float constant 10**6
#define _COMM_PAGE_MAGIC_FE             (_COMM_PAGE_BASE_ADDRESS+0x050) // magic constant 0xFEFEFEFEFEFEFEFF (to find 0s)
#define _COMM_PAGE_MAGIC_80             (_COMM_PAGE_BASE_ADDRESS+0x058) // magic constant 0x8080808080808080 (to find 0s)
 
#define _COMM_PAGE_TIMEBASE				(_COMM_PAGE_BASE_ADDRESS+0x060)	// used by gettimeofday()
#define _COMM_PAGE_TIMESTAMP			(_COMM_PAGE_BASE_ADDRESS+0x068)	// used by gettimeofday()
#define _COMM_PAGE_SEC_PER_TICK			(_COMM_PAGE_BASE_ADDRESS+0x070)	// used by gettimeofday()
 
 /* jump table (bla to this address, which may be a branch to the actual code somewhere else) */
 /* When new jump table entries are added, corresponding symbols should be added below         */
 
#define _COMM_PAGE_COMPARE_AND_SWAP32   (_COMM_PAGE_BASE_ADDRESS+0x080) // compare-and-swap word, no barrier
#define _COMM_PAGE_COMPARE_AND_SWAP64   (_COMM_PAGE_BASE_ADDRESS+0x0c0) // compare-and-swap doubleword, no barrier
#define _COMM_PAGE_ENQUEUE				(_COMM_PAGE_BASE_ADDRESS+0x100) // enqueue
#define _COMM_PAGE_DEQUEUE				(_COMM_PAGE_BASE_ADDRESS+0x140) // dequeue
#define _COMM_PAGE_MEMORY_BARRIER		(_COMM_PAGE_BASE_ADDRESS+0x180) // memory barrier
#define _COMM_PAGE_ATOMIC_ADD32			(_COMM_PAGE_BASE_ADDRESS+0x1a0) // add atomic word
#define _COMM_PAGE_ATOMIC_ADD64			(_COMM_PAGE_BASE_ADDRESS+0x1c0) // add atomic doubleword

#define _COMM_PAGE_UNUSED3				(_COMM_PAGE_BASE_ADDRESS+0x1e0) // 32 unused bytes

#define _COMM_PAGE_ABSOLUTE_TIME		(_COMM_PAGE_BASE_ADDRESS+0x200)	// mach_absolute_time()
#define _COMM_PAGE_SPINLOCK_TRY			(_COMM_PAGE_BASE_ADDRESS+0x220)	// spinlock_try()
#define _COMM_PAGE_SPINLOCK_LOCK		(_COMM_PAGE_BASE_ADDRESS+0x260)	// spinlock_lock()
#define _COMM_PAGE_SPINLOCK_UNLOCK		(_COMM_PAGE_BASE_ADDRESS+0x2a0)	// spinlock_unlock()
#define _COMM_PAGE_PTHREAD_GETSPECIFIC	(_COMM_PAGE_BASE_ADDRESS+0x2c0)	// pthread_getspecific()
#define _COMM_PAGE_GETTIMEOFDAY			(_COMM_PAGE_BASE_ADDRESS+0x2e0)	// used by gettimeofday()
#define _COMM_PAGE_FLUSH_DCACHE			(_COMM_PAGE_BASE_ADDRESS+0x4e0)	// sys_dcache_flush()
#define _COMM_PAGE_FLUSH_ICACHE			(_COMM_PAGE_BASE_ADDRESS+0x520)	// sys_icache_invalidate()
#define _COMM_PAGE_PTHREAD_SELF			(_COMM_PAGE_BASE_ADDRESS+0x580)	// pthread_self()

#define	_COMM_PAGE_UNUSED4				(_COMM_PAGE_BASE_ADDRESS+0x5a0)	// 32 unused bytes

#define	_COMM_PAGE_RELINQUISH			(_COMM_PAGE_BASE_ADDRESS+0x5c0)	// used by spinlocks
 
#define _COMM_PAGE_UNUSED5				(_COMM_PAGE_BASE_ADDRESS+0x5e0)	// 32 unused bytes
 
#define _COMM_PAGE_BZERO				(_COMM_PAGE_BASE_ADDRESS+0x600)	// bzero()
#define _COMM_PAGE_BCOPY				(_COMM_PAGE_BASE_ADDRESS+0x780)	// bcopy()
#define	_COMM_PAGE_MEMCPY				(_COMM_PAGE_BASE_ADDRESS+0x7a0)	// memcpy()
#define	_COMM_PAGE_MEMMOVE				(_COMM_PAGE_BASE_ADDRESS+0x7a0)	// memmove()

#define _COMM_PAGE_COMPARE_AND_SWAP32B  (_COMM_PAGE_BASE_ADDRESS+0xf80)	// compare-and-swap word w barrier
#define _COMM_PAGE_COMPARE_AND_SWAP64B  (_COMM_PAGE_BASE_ADDRESS+0xfc0)	// compare-and-swap doubleword w barrier

#define	_COMM_PAGE_MEMSET_PATTERN       (_COMM_PAGE_BASE_ADDRESS+0x1000)// used by nonzero memset()
#define	_COMM_PAGE_BIGCOPY				(_COMM_PAGE_BASE_ADDRESS+0x1140)// very-long-operand copies

#define _COMM_PAGE_END					(_COMM_PAGE_BASE_ADDRESS+0x1700)// end of commpage area

#ifdef __ASSEMBLER__
#ifdef __COMM_PAGE_SYMBOLS

#define CREATE_COMM_PAGE_SYMBOL(symbol_name, symbol_address)		\
				.org	(symbol_address - _COMM_PAGE_BASE_ADDRESS) @\
symbol_name: nop

	.text		// Required to make a well behaved symbol file

	CREATE_COMM_PAGE_SYMBOL(___compare_and_swap32, _COMM_PAGE_COMPARE_AND_SWAP32)
	CREATE_COMM_PAGE_SYMBOL(___compare_and_swap64, _COMM_PAGE_COMPARE_AND_SWAP64)
	CREATE_COMM_PAGE_SYMBOL(___atomic_enqueue, _COMM_PAGE_ENQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___atomic_dequeue, _COMM_PAGE_DEQUEUE)
	CREATE_COMM_PAGE_SYMBOL(___memory_barrier, _COMM_PAGE_MEMORY_BARRIER)
	CREATE_COMM_PAGE_SYMBOL(___atomic_add32, _COMM_PAGE_ATOMIC_ADD32)
	CREATE_COMM_PAGE_SYMBOL(___atomic_add64, _COMM_PAGE_ATOMIC_ADD64)
	CREATE_COMM_PAGE_SYMBOL(___mach_absolute_time, _COMM_PAGE_ABSOLUTE_TIME)
	CREATE_COMM_PAGE_SYMBOL(___spin_lock_try, _COMM_PAGE_SPINLOCK_TRY)
	CREATE_COMM_PAGE_SYMBOL(___spin_lock, _COMM_PAGE_SPINLOCK_LOCK)
	CREATE_COMM_PAGE_SYMBOL(___spin_unlock, _COMM_PAGE_SPINLOCK_UNLOCK)
	CREATE_COMM_PAGE_SYMBOL(___pthread_getspecific, _COMM_PAGE_PTHREAD_GETSPECIFIC)
	CREATE_COMM_PAGE_SYMBOL(___gettimeofday, _COMM_PAGE_GETTIMEOFDAY)
	CREATE_COMM_PAGE_SYMBOL(___sys_dcache_flush, _COMM_PAGE_FLUSH_DCACHE)
	CREATE_COMM_PAGE_SYMBOL(___sys_icache_invalidate, _COMM_PAGE_FLUSH_ICACHE)
	CREATE_COMM_PAGE_SYMBOL(___pthread_self, _COMM_PAGE_PTHREAD_SELF)
	CREATE_COMM_PAGE_SYMBOL(___spin_lock_relinquish, _COMM_PAGE_RELINQUISH)
	CREATE_COMM_PAGE_SYMBOL(___bzero, _COMM_PAGE_BZERO)
	CREATE_COMM_PAGE_SYMBOL(___bcopy, _COMM_PAGE_BCOPY)
	CREATE_COMM_PAGE_SYMBOL(___memcpy, _COMM_PAGE_MEMCPY)
//	CREATE_COMM_PAGE_SYMBOL(___memmove, _COMM_PAGE_MEMMOVE)
	CREATE_COMM_PAGE_SYMBOL(___compare_and_swap32b, _COMM_PAGE_COMPARE_AND_SWAP32B)
	CREATE_COMM_PAGE_SYMBOL(___compare_and_swap64b, _COMM_PAGE_COMPARE_AND_SWAP64B)
    CREATE_COMM_PAGE_SYMBOL(___memset_pattern, _COMM_PAGE_MEMSET_PATTERN)
	CREATE_COMM_PAGE_SYMBOL(___bigcopy, _COMM_PAGE_BIGCOPY)
	
	CREATE_COMM_PAGE_SYMBOL(___end_comm_page, _COMM_PAGE_END)

	.data		// Required to make a well behaved symbol file
	.long	0	// Required to make a well behaved symbol file

#endif /* __COMM_PAGE_SYMBOLS */
#endif /* __ASSEMBLER__ */

#endif /* _PPC_CPU_CAPABILITIES_H */
#endif /* PRIVATE */
