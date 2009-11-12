/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 *		Header files for the Low Memory Globals (lg) 
 */
#ifndef	_LOW_MEMORY_GLOBALS_H_
#define	_LOW_MEMORY_GLOBALS_H_

#if defined(__x86_64__)
#include <x86_64/lowglobals.h>
#elif !defined(__i386__)
#error	Wrong architecture - this file is meant for i386
#endif

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>

/*
 * Don't change these structures unless you change the corresponding assembly code
 * which is in lowmem_vectors.s
 */
 
/* 
 *	This is where we put constants, pointers, and data areas that must be accessed
 *	quickly through assembler.  They are designed to be accessed directly with 
 *	absolute addresses, not via a base register.  This is a global area, and not
 *	per processor.
 */
 
#pragma pack(4)		/* Make sure the structure stays as we defined it */
typedef struct lowglo {

	unsigned char	lgVerCode[8];		/* 0x2000 System verification code */
	unsigned long long lgZero;		/* 0x2008 Double constant 0 */
	uint32_t	lgRsv010;		/* 0x2010 Reserved */
	uint32_t	lgCHUDXNUfnStart;	/* 0x2014 CHUD XNU function glue
						 * table */
	uint32_t	lgRsv018;		/* 0x2018 Reserved */
	uint32_t	lgVersion;		/* 0x201C Pointer to kernel version string */
	uint32_t	lgRsv020[280];		/* 0X2020 Reserved */
	uint32_t	lgKmodptr;		/* 0x2480 Pointer to kmod, debugging aid */
	uint32_t	lgTransOff;		/* 0x2484 Pointer to kdp_trans_off, debugging aid */
	uint32_t	lgReadIO;		/* 0x2488 Pointer to kdp_read_io, debugging aid */
	uint32_t	lgDevSlot1;		/* 0x248C For developer use */
	uint32_t	lgDevSlot2;		/* 0x2490 For developer use */
	uint32_t	lgOSVersion;		/* 0x2494 Pointer to OS version string */
	uint32_t	lgRebootFlag;		/* 0x2498 Pointer to debugger reboot trigger */
	uint32_t        lgManualPktAddr;        /* 0x249C Pointer to manual packet structure */
	uint32_t	lgRsv49C[728];		/* 0x24A0 Reserved - push to 1 page */
} lowglo;
#pragma pack()
extern lowglo lowGlo;
#endif /* _LOW_MEMORY_GLOBALS_H_ */
