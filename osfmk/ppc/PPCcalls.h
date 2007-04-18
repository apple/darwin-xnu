/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 *	To add a new entry:
 *		Add an "PPCTRAP(routine)" to the table below
 *
 *		Add trap definition to mach/ppc/syscall_sw.h and
 *		recompile user library.
 *
 *	Note:
 *		The maximum number of calls is 0x1000 (4096 for the hexually challanged)
 *
 */

typedef	int (*PPCcallEnt)(struct savearea *save);

#define PPCcall(rout) rout
#define dis (PPCcallEnt)0

PPCcallEnt	PPCcalls[] = {

	PPCcall(diagCall),				/* 0x6000 Call diagnostics routines */
	PPCcall(vmm_get_version),		/* 0x6001 Get Virtual Machine Monitor version */
	PPCcall(vmm_get_features),		/* 0x6002 Get Virtual Machine Monitor supported features */
	PPCcall(vmm_init_context),		/* 0x6003 Initialize a VMM context */
	PPCcall(vmm_dispatch),			/* 0x6004 Dispatch a Virtual Machine Monitor call */	
	PPCcall(bb_enable_bluebox),		/* 0x6005 Enable this thread for use in the blue box virtual machine */
	PPCcall(bb_disable_bluebox),	/* 0x6006 Disable this thread for use in the blue box virtual machine */
	PPCcall(bb_settaskenv),			/* 0x6007 Set the BlueBox per thread task environment data */
	PPCcall(vmm_stop_vm),			/* 0x6008 Stop a running VM */

	PPCcall(dis),					/* 0x6009 CHUD Interface hook */
	
	PPCcall(ppcNull),				/* 0x600A Null PPC syscall */
	PPCcall(perfmon_control),		/* 0x600B performance monitor */
	PPCcall(ppcNullinst),			/* 0x600C Instrumented Null PPC syscall */
	PPCcall(pmsCntrl),				/* 0x600D Power Management Stepper */
	PPCcall(dis),					/* 0x600E disabled */
	PPCcall(dis),					/* 0x600F disabled */
	PPCcall(dis),					/* 0x6010 disabled */
	PPCcall(dis),					/* 0x6011 disabled */
	PPCcall(dis),					/* 0x6012 disabled */
	PPCcall(dis),					/* 0x6013 disabled */
	PPCcall(dis),					/* 0x6014 disabled */
	PPCcall(dis),					/* 0x6015 disabled */
	PPCcall(dis),					/* 0x6016 disabled */
	PPCcall(dis),					/* 0x6017 disabled */
	PPCcall(dis),					/* 0x6018 disabled */
	PPCcall(dis),					/* 0x6019 disabled */
	PPCcall(dis),					/* 0x601A disabled */
	PPCcall(dis),					/* 0x601B disabled */
	PPCcall(dis),					/* 0x601C disabled */
	PPCcall(dis),					/* 0x601D disabled */
	PPCcall(dis),					/* 0x601E disabled */
	PPCcall(dis),					/* 0x601F disabled */
};

#undef dis
