/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

#ifndef _PPC_CPU_CAPABILITIES_H
#define _PPC_CPU_CAPABILITIES_H

/* Sadly, some clients of this interface misspell __APPLE_API_PRIVATE.
 * To avoid breaking them, we accept the incorrect _APPLE_API_PRIVATE.
 */
#ifdef	_APPLE_API_PRIVATE
#ifndef __APPLE_API_PRIVATE
#define	__APPLE_API_PRIVATE
#endif	/* __APPLE_API_PRIVATE */
#endif	/* _APPLE_API_PRIVATE */
 
#ifndef __APPLE_API_PRIVATE
#error	cpu_capabilities.h is for Apple Internal use only
#else	/* __APPLE_API_PRIVATE */

/* _cpu_capabilities
 *
 * This is the authoritative way to determine from user mode what
 * implementation-specific processor features are available.
 * This API only supported for Apple internal use.
 * 
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
#define	kDcbaAvailable			0x00000040	// PPC: dcba is available but is not recommended
#define	kDataStreamsRecommended	0x00000080	// PPC: dst, dstt, dstst, dss, and dssall instructions available and recommended
#define	kDataStreamsAvailable	0x00000100	// PPC: dst, dstt, dstst, dss, and dssall instructions available but not recommended
#define	kDcbtStreamsRecommended	0x00000200	// PPC: enhanced dcbt instruction available and recommended
#define	kDcbtStreamsAvailable	0x00000400	// PPC: enhanced dcbt instruction available and recommended

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
 
/* data in the comm page */
 
#define _COMM_PAGE_SIGNATURE			(_COMM_PAGE_BASE_ADDRESS+0x000)	// first few bytes are a signature
#define _COMM_PAGE_VERSION				(_COMM_PAGE_BASE_ADDRESS+0x01E)	// 16-bit version#
#define	_COMM_PAGE_THIS_VERSION			1								// this is version 1 of the commarea format
  
#define _COMM_PAGE_CPU_CAPABILITIES		(_COMM_PAGE_BASE_ADDRESS+0x020)	// mirror of extern int _cpu_capabilities
#define _COMM_PAGE_NCPUS				(_COMM_PAGE_BASE_ADDRESS+0x021)	// number of configured CPUs
#define _COMM_PAGE_ALTIVEC				(_COMM_PAGE_BASE_ADDRESS+0x024)	// nonzero if Altivec available
#define _COMM_PAGE_64_BIT				(_COMM_PAGE_BASE_ADDRESS+0x025)	// nonzero if 64-bit processor
#define _COMM_PAGE_CACHE_LINESIZE		(_COMM_PAGE_BASE_ADDRESS+0x026)	// cache line size (16-bit field)
 
#define _COMM_PAGE_UNUSED1				(_COMM_PAGE_BASE_ADDRESS+0x030)	// 16 unused bytes
 
#define _COMM_PAGE_2_TO_52				(_COMM_PAGE_BASE_ADDRESS+0x040)	// double float constant 2**52
#define _COMM_PAGE_10_TO_6				(_COMM_PAGE_BASE_ADDRESS+0x048)	// double float constant 10**6
 
#define _COMM_PAGE_UNUSED2				(_COMM_PAGE_BASE_ADDRESS+0x050)	// 16 unused bytes
 
#define _COMM_PAGE_TIMEBASE				(_COMM_PAGE_BASE_ADDRESS+0x060)	// used by gettimeofday()
#define _COMM_PAGE_TIMESTAMP			(_COMM_PAGE_BASE_ADDRESS+0x068)	// used by gettimeofday()
#define _COMM_PAGE_SEC_PER_TICK			(_COMM_PAGE_BASE_ADDRESS+0x070)	// used by gettimeofday()
 
#define _COMM_PAGE_UNUSED3				(_COMM_PAGE_BASE_ADDRESS+0x080)	// 384 unused bytes
 
 /* jump table (bla to this address, which may be a branch to the actual code somewhere else) */
 
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

#define	_COMM_PAGE_UNUSED6				(_COMM_PAGE_BASE_ADDRESS+0xF80)	// 128 unused bytes

#define	_COMM_PAGE_BIGCOPY				(_COMM_PAGE_BASE_ADDRESS+0x1000)// very-long-operand copies

#endif /* __APPLE_API_PRIVATE */
#endif /* _PPC_CPU_CAPABILITIES_H */
