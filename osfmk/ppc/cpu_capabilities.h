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
#endif /* __APPLE_API_PRIVATE */
#endif /* _PPC_CPU_CAPABILITIES_H */
