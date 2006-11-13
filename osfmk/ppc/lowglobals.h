/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 *		Header files for the Low Memory Globals (lg) 
 */
#ifndef	_LOW_MEMORY_GLOBALS_H_
#define	_LOW_MEMORY_GLOBALS_H_

#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <ppc/proc_reg.h>
#include <ppc/savearea.h>
#include <ppc/low_trace.h>
#include <ppc/Diagnostics.h>
#include <ppc/mappings.h>

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
	unsigned int    lgCHUDXNUfnStart;		/* 5014 CHUD XNU function glue table */
	unsigned int	lgMckFlags;				/* 5018 Machine check flags */
	unsigned int    lgVersion;				/* 501C Pointer to kernel version string */
	uint64_t		lgPMWvaddr;				/* 5020 physical memory window virtual address */
	uint64_t		lgUMWvaddr;				/* 5028 user memory window virtual address */
	unsigned int	lgVMMforcedFeats;		/* 5030 VMM boot-args forced feature flags */
	unsigned int	lgMaxDec;				/* 5034 Maximum decrementer we can set */
	unsigned int	lgPmsCtlp;				/* 5038 Pointer to power management stepper control */
	unsigned int	lgRsv03C[17];			/* 503C reserved */
	traceWork		lgTrcWork;				/* 5080 Tracing control block - trcWork */
	unsigned int	lgRsv0A0[24];			/* 50A0 reserved */
	struct Saveanchor	lgSaveanchor;		/* 5100 Savearea anchor - saveanchor */
	unsigned int	lgRsv140[16];			/* 5140 reserved */
	unsigned int	lgTlbieLck;				/* 5180 TLBIE lock */
	unsigned int	lgRsv184[31];			/* 5184 reserved - push to next line */
	struct diagWork	lgdgWork;				/* 5200 Start of diagnostic work area */
	unsigned int	lglcksWork;				/* 5220 lcks option */
	unsigned int	lgRsv224[23];			/* 5224 reserved */
	pcfg 			lgpPcfg[8];				/* 5280 Page configurations */
	unsigned int	lgRst2A0[24];			/* 52A0 reserved */
	unsigned int	lgKillResv;				/* 5300 line used to kill reservations */
	unsigned int	lgKillResvpad[31];		/* 5304 pad reservation kill line */

	unsigned int	lgRsv380[32];			/* 5380 - 5400 reserved  */

	unsigned int	lgRsv400[32];			/* 5400 - 5480 reserved  */
	uint32_t		lgKmodptr;		/* 0x5480 Pointer to kmod, debugging aid */
	uint32_t		lgTransOff;		/* 0x5484 Pointer to kdp_trans_off, debugging aid */
	uint32_t		lgReadIO;		/* 0x5488 Pointer to kdp_read_io, debugging aid */
	uint32_t		lgDevSlot1;		/* 0x548C For developer use */
	uint32_t		lgDevSlot2;		/* 0x5490 For developer use */
	uint32_t		lgRsv494[731];		/* 0x5494 reserved - push to 1 page */

} lowglo;

extern lowglo lowGlo;

#endif /* _LOW_MEMORY_GLOBALS_H_ */
