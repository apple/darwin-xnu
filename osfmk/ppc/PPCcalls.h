/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
	
	PPCcall(dis),					/* 0x600A disabled */
	PPCcall(dis),					/* 0x600B disabled */
	PPCcall(dis),					/* 0x600C disabled */
	PPCcall(dis),					/* 0x600D disabled */
	PPCcall(dis),					/* 0x600E disabled */
	PPCcall(dis),					/* 0x600F disabled */
};

#undef dis
