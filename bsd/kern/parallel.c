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
 * Mach Operating System
 * Copyright (c) 1989 Carnegie-Mellon University
 * Copyright (c) 1988 Carnegie-Mellon University
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:06:13  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1997/09/30 02:44:39  wsanchez
 * Import of kernel from umeshv/kernel
 *
 * Revision 2.4  89/12/22  15:52:48  rpd
 * 	MACH_HOST support: when releasing master, context switch away
 * 	immediately if thread is not assigned to default processor set.
 * 	[89/11/16            dlb]
 * 
 * Revision 2.3  89/10/11  14:19:20  dlb
 * 	Processor logic - explicitly record bound processor in thread
 * 	instead of changing whichq pointer.
 * 	[88/09/30            dlb]
 * 
 * Revision 2.2  89/02/25  18:07:24  gm0w
 * 	Changes for cleanup.
 * 
 * 15-Oct-87  David Golub (dbg) at Carnegie-Mellon University
 *	Use thread_bind (inline version) to bind thread to master cpu
 *	while holding unix-lock.
 *
 *  9-Oct-87  Robert Baron (rvb) at Carnegie-Mellon University
 *	Define unix_reset for longjmp/setjmp reset.
 *
 * 25-Sep-87  Robert Baron (rvb) at Carnegie-Mellon University
 *	Clean out some debugging code.
 *
 * 21-Sep-87  Robert Baron (rvb) at Carnegie-Mellon University
 *	Created.
 *
 */


#include <cpus.h>
#include <mach_host.h>

#if	NCPUS > 1

#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/parallel.h>

void unix_master()
{
	register thread_t t = current_thread();
	
	if (! (++( t->unix_lock )))	{

		/* thread_bind(t, master_processor); */
		t->bound_processor = master_processor;

		if (cpu_number() != master_cpu) {
			t->interruptible = FALSE;
			thread_block(0);
		}
	}
}

void unix_release()
{
	register thread_t t = current_thread();

	t->unix_lock--;
	if (t->unix_lock < 0) {
		/* thread_bind(t, PROCESSOR_NULL); */
		t->bound_processor = PROCESSOR_NULL;
#if	MACH_HOST
		if (t->processor_set != &default_pset)
			thread_block(0);
#endif	MACH_HOST
	}
}

void unix_reset()
{
	register thread_t	t = current_thread();

	if (t->unix_lock != -1)
		t->unix_lock = 0;
}

#endif	NCPUS > 1
