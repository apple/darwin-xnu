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
 * Revision 1.1.7.6  1995/08/21  20:44:57  devrcs
 * 	Fix ri-osc CR1405: Zero act->thread_pool_next when act not on pool.
 * 	[1995/07/25  20:19:06  bolinger]
 *
 * Revision 1.1.7.5  1995/01/18  18:35:00  ezf
 * 	updated Utah CR notice
 * 	[1995/01/18  18:30:33  ezf]
 * 
 * Revision 1.1.7.4  1995/01/10  05:15:20  devrcs
 * 	mk6 CR801 - merge up from nmk18b4 to nmk18b7
 * 	Comments from merged code below, as marked
 * 	[1994/12/09  21:10:54  dwm]
 * 
 * 	mk6 CR668 - 1.3b26 merge
 * 	event_t casts
 * 	[1994/11/04  09:39:15  dwm]
 * 
 * Revision 1.1.7.3  1994/11/23  16:01:15  devrcs
 * 	BEGIN comments from merge of nmk18b4 - nmk18b7
 * 	Cleared `handlers' field of activation when returning
 * 	it to thread pool.
 * 	[1994/11/23  03:48:31  burke]
 * 
 * 	Added an assert to `thread_pool_put_act()' to check
 * 	for presence of handlers when returning an activation
 * 	to its pool.
 * 	[1994/11/18  13:36:29  rkc]
 * 
 * 	Changed `thread_pool_put_act()'s call to `act_set_thread_pool()' to
 * 	be a call to `act_locked_act_set_thread_pool()' to obey locking
 * 	assumptions.
 * 	[1994/11/10  23:29:51  rkc]
 * 
 * 	Cosmetic changes to thread_pool_put_act.
 * 	[1994/11/09  21:49:57  watkins]
 * 
 * 	Check out for merge.
 * 	[1994/11/09  14:16:43  watkins]
 * 
 * Revision 1.1.9.2  1994/11/08  15:32:42  watkins
 * 	Add thread_pool_put_act.
 * 	END comments from merge of nmk18b4 - nmk18b7
 * 	[1994/11/09  14:16:33  watkins]
 * 
 * Revision 1.1.7.2  1994/09/23  02:31:05  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:38:01  ezf]
 * 
 * Revision 1.1.7.1  1994/09/02  02:40:54  watkins
 * 	Check for destroyed thread pool port after thread_pool_get_act
 * 	blocks.
 * 	[1994/09/02  02:37:46  watkins]
 * 
 * Revision 1.1.2.8  1994/06/09  14:14:04  dswartz
 * 	Preemption merge.
 * 	[1994/06/09  14:08:35  dswartz]
 * 
 * Revision 1.1.2.7  1994/06/01  19:30:10  bolinger
 * 	mk6 CR125:  Update to reflect new naming for thread_pool of
 * 	thread_act.
 * 	[1994/06/01  19:14:46  bolinger]
 * 
 * Revision 1.1.2.6  1994/03/17  22:38:34  dwm
 * 	The infamous name change:  thread_activation + thread_shuttle = thread.
 * 	[1994/03/17  21:28:15  dwm]
 * 
 * Revision 1.1.2.5  1994/02/09  00:42:29  dwm
 * 	Put a variety of debugging code under MACH_ASSERT,
 * 	to enhance PROD performance a bit.
 * 	[1994/02/09  00:35:07  dwm]
 * 
 * Revision 1.1.2.4  1994/02/04  03:46:25  condict
 * 	Put if MACH_ASSERT around debugging printfs.
 * 	[1994/02/04  03:44:10  condict]
 * 
 * Revision 1.1.2.3  1994/01/21  23:45:15  dwm
 * 	Thread_pools now embedded directly in port/pset.
 * 	Adjust thread_pool_create.
 * 	[1994/01/21  23:43:18  dwm]
 * 
 * Revision 1.1.2.2  1994/01/14  18:42:01  bolinger
 * 	Rename thread_pool_block() to thread_pool_get_act() [sic], to
 * 	better reflect its function.  Add leading comment and assertion
 * 	checks.
 * 	[1994/01/14  18:18:11  bolinger]
 * 
 * Revision 1.1.2.1  1994/01/12  17:53:17  dwm
 * 	Coloc: initial restructuring to follow Utah model.
 * 	[1994/01/12  17:15:21  dwm]
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
 *	File:	thread_pool.c
 *
 *	thread_pool management routines
 *
 */

#include <kern/ipc_mig.h>
#include <kern/ipc_tt.h>
#include <kern/mach_param.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/task.h>
#include <kern/thread_act.h>

#include <mach/kern_return.h>
#include <kern/thread_pool.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/sched_prim.h>


/* Initialize a new EMPTY thread_pool.  */
kern_return_t
thread_pool_init(thread_pool_t new_thread_pool)
{
	assert(new_thread_pool != THREAD_POOL_NULL);

	/* Start with one reference for the caller */
	new_thread_pool->thr_acts = (struct thread_activation *)0;
	return KERN_SUCCESS;
}


/*
 * Obtain an activation from a thread pool, blocking if
 * necessary.  Return the activation locked, since it's
 * in an inconsistent state (not in a pool, not attached
 * to a thread).
 *
 * Called with ip_lock() held for pool_port.  Returns
 * the same way.
 *
 * If the thread pool port is destroyed while we are blocked,
 * then return a null activation. Callers must check for this
 * error case.
 */
thread_act_t
thread_pool_get_act(ipc_port_t pool_port)
{
	thread_pool_t thread_pool = &pool_port->ip_thread_pool;
	thread_act_t thr_act;

#if	MACH_ASSERT
	assert(thread_pool != THREAD_POOL_NULL);
	if (watchacts & WA_ACT_LNK)
		printf("thread_pool_block: %x, waiting=%d\n",
		       thread_pool, thread_pool->waiting);
#endif

	while ((thr_act = thread_pool->thr_acts) == THR_ACT_NULL) {
		if (!ip_active(pool_port))
			return THR_ACT_NULL;
		thread_pool->waiting = 1;
		assert_wait((event_t)thread_pool, THREAD_INTERRUPTIBLE);
		ip_unlock(pool_port);
		thread_block((void (*)(void)) 0);       /* block self */
		ip_lock(pool_port);
	}
	assert(thr_act->thread == THREAD_NULL);
	assert(thr_act->suspend_count == 0);
	thread_pool->thr_acts = thr_act->thread_pool_next;
	act_lock(thr_act);
	thr_act->thread_pool_next = 0;

#if	MACH_ASSERT
	if (watchacts & WA_ACT_LNK)
		printf("thread_pool_block: return %x, next=%x\n",
		       thr_act, thread_pool->thr_acts);
#endif
	return thr_act;
}

/*
 * 	thread_pool_put_act
 *
 *	Return an activation to its pool. Assumes the activation
 *	and pool (if it exists) are locked.
 */
void
thread_pool_put_act( thread_act_t thr_act )
{
        thread_pool_t   thr_pool;

	/*
	 *	Find the thread pool for this activation.
	 */	
        if (thr_act->pool_port)
            thr_pool = &thr_act->pool_port->ip_thread_pool;
        else
            thr_pool = THREAD_POOL_NULL;

        /* 
	 *	Return act to the thread_pool's list, if it is still
	 *	alive. Otherwise, remove it from its thread_pool, which
	 *	will deallocate it and destroy it.
	 */
        if (thr_act->active) {
                assert(thr_pool);
		thr_act->handlers = NULL;
                thr_act->thread_pool_next = thr_pool->thr_acts;
                thr_pool->thr_acts = thr_act;
                if (thr_pool->waiting)
                        thread_pool_wakeup(thr_pool);
        } else if (thr_pool) {
                assert(thr_act->pool_port);
                act_locked_act_set_thread_pool(thr_act, IP_NULL);
        }

	return;
}
 

/*
 * Called with ip_lock() held for port containing thread_pool.
 * Returns same way.
 */
void
thread_pool_wakeup(thread_pool_t thread_pool)
{
#if	MACH_ASSERT
	assert(thread_pool != THREAD_POOL_NULL);
	if (watchacts & WA_ACT_LNK)
		printf("thread_pool_wakeup: %x, waiting=%d, head=%x\n",
		   thread_pool, thread_pool->waiting, thread_pool->thr_acts);
#endif	/* MACH_ASSERT */

	if (thread_pool->waiting) {
		thread_wakeup((event_t)thread_pool);
		thread_pool->waiting = 0;
	}
}
