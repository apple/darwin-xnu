/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*
 *		Header files for the Low Memory Globals (lg) 
 */
#ifndef	_LOW_MEMORY_GLOBALS_H_
#define	_LOW_MEMORY_GLOBALS_H_

#include <cpus.h>

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <ppc/proc_reg.h>
#include <ppc/savearea.h>
#include <ppc/low_trace.h>
#include <ppc/Diagnostics.h>

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
 
#pragma pack(4)								/* Make sure the structure stays as we defined it */
typedef struct lowglo {

	unsigned long	lgForceAddr[5*1024];	/* 0000 Force to page 5 */
	unsigned char	lgVerCode[8];			/* 5000 System verification code */
	unsigned long long lgZero;				/* 5008 Double constant 0 */
	unsigned int	lgPPStart;				/* 5010 Start of per_proc blocks */
	unsigned int	lgRsv014[27];			/* 5014 reserved */
	traceWork		lgTrcWork;				/* 5080 Tracing control block - trcWork */
	unsigned int	lgRsv0A0[24];			/* 50A0 reserved */
	struct Saveanchor	lgSaveanchor;		/* 5100 Savearea anchor - saveanchor */
	unsigned int	lgRsv140[16];			/* 5140 reserved */
	unsigned int	lgTlbieLck;				/* 5180 TLBIE lock */
	unsigned int	lgRsv184[31];			/* 5184 reserved - push to next line */
	struct diagWork	lgdgWork;				/* 5200 Start of diagnostic work area */
	unsigned int	lgRsv220[24];			/* 5220 reserved */
	unsigned int	lgRst280[32];			/* 5280 reserved */
	unsigned int	lgKillResv;				/* 5300 line used to kill reservations */
	unsigned int	lgKillResvpad[31];		/* 5304 pad reservation kill line */
	unsigned int	lgRsv380[768];			/* 5380 reserved - push to 1 page */

} lowglo;

extern lowglo lowGlo;

#endif /* _LOW_MEMORY_GLOBALS_H_ */
