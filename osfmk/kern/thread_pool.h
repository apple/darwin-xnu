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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:32  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:57  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.7.4  1995/01/18  18:35:03  ezf
 * 	updated Utah CR notice
 * 	[1995/01/18  18:30:36  ezf]
 *
 * Revision 1.1.7.3  1995/01/10  05:15:24  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	* Rev 1.1.8.2  1994/11/08  15:33:03  watkins
 * 	  Add declaration for thread_pool_put_act.
 * 	[1994/12/09  21:10:56  dwm]
 * 
 * Revision 1.1.7.1  1994/09/23  02:31:15  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:38:04  ezf]
 * 
 * Revision 1.1.2.9  1994/06/09  14:14:07  dswartz
 * 	Preemption merge.
 * 	[1994/06/09  14:08:37  dswartz]
 * 
 * Revision 1.1.2.8  1994/06/01  19:30:14  bolinger
 * 	mk6 CR125:  Update to reflect changes in access to thread_pool
 * 	of a thread_act.
 * 	[1994/06/01  19:18:25  bolinger]
 * 
 * Revision 1.1.2.7  1994/03/17  22:38:37  dwm
 * 	The infamous name change:  thread_activation + thread_shuttle = thread.
 * 	[1994/03/17  21:28:18  dwm]
 * 
 * Revision 1.1.2.6  1994/02/09  00:42:42  dwm
 * 	Put a variety of debugging code under MACH_ASSERT,
 * 	to enhance PROD performance a bit.
 * 	[1994/02/09  00:35:13  dwm]
 * 
 * Revision 1.1.2.5  1994/01/21  23:45:08  dwm
 * 	Thread_pools now embedded directly in port/pset,
 * 	delete refcount, modify protos.
 * 	[1994/01/21  23:43:13  dwm]
 * 
 * Revision 1.1.2.4  1994/01/17  19:09:32  dwm
 * 	Fix ref/dealloc macros, missing semicolon.
 * 	[1994/01/17  19:09:16  dwm]
 * 
 * Revision 1.1.2.3  1994/01/17  18:08:57  dwm
 * 	Add finer grained act tracing.
 * 	[1994/01/17  16:06:54  dwm]
 * 
 * Revision 1.1.2.2  1994/01/14  18:42:05  bolinger
 * 	Update to reflect thread_pool_block() -> thread_pool_get_act() name
 * 	change.
 * 	[1994/01/14  18:18:40  bolinger]
 * 
 * Revision 1.1.2.1  1994/01/12  17:53:21  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	[1994/01/12  17:15:24  dwm]
 * 
 * $EndLog$
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 *      Author: Bryan Ford, University of Utah CSL
 *
 *	File:	thread_pool.h
 *
 *	Defines the thread_pool: a pool of available activations.
 *
 */

#ifndef	_KERN_THREAD_POOL_H_
#define _KERN_THREAD_POOL_H_

#include <mach/kern_return.h>
#include <kern/lock.h>
#include <mach_assert.h>

typedef struct thread_pool {

	/* List of available activations, all active but not in use.  */
	struct thread_activation	*thr_acts;

	/* true if somebody is waiting for an activation from this pool */
	int waiting;

} thread_pool, *thread_pool_t;
#define THREAD_POOL_NULL	((thread_pool_t)0)

/* Exported to kern/startup.c only */
kern_return_t	thread_pool_init(thread_pool_t new_thread_pool);

/* Get an activation from a thread_pool, blocking if need be */
extern struct thread_activation *thread_pool_get_act( ipc_port_t );
extern void thread_pool_put_act( thread_act_t );

/* Wake up a waiter upon return to thread_pool */
extern void thread_pool_wakeup( thread_pool_t );

#if	MACH_ASSERT
/*
 * Debugging support - "watchacts", a patchable selective trigger
 */
extern unsigned int watchacts;	/* debug printf trigger */
#define WA_SCHED	0x001	/* kern/sched_prim.c	*/
#define WA_THR		0x002	/* kern/thread.c	*/
#define WA_ACT_LNK	0x004	/* kern/thread_act.c act mgmt	*/
#define WA_ACT_HDLR	0x008	/* kern/thread_act.c act hldrs	*/
#define WA_TASK		0x010	/* kern/task.c		*/
#define WA_BOOT		0x020	/* bootstrap,startup.c	*/
#define WA_PCB		0x040	/* machine/pcb.c	*/
#define WA_PORT		0x080	/* ports + port sets	*/
#define WA_EXIT		0x100	/* exit path		*/
#define WA_SWITCH	0x200	/* context switch (!!)	*/
#define WA_STATE	0x400	/* get/set state  (!!)	*/
#define WA_ALL		(~0)
#endif	/* MACH_ASSERT */

#endif /* _KERN_THREAD_POOL_H_ */
