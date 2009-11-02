/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
#include <mach_kdb.h>
#include <mach_ldebug.h>
#include <debug.h>

#include <mach/kern_return.h>
#include <mach/mach_host_server.h>
#include <mach_debug/lockgroup_info.h>

#include <kern/locks.h>
#include <kern/misc_protos.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <kern/sched_prim.h>
#include <kern/debug.h>
#include <string.h>


#include <sys/kdebug.h>

#define	LCK_MTX_SLEEP_CODE		0
#define	LCK_MTX_SLEEP_DEADLINE_CODE	1
#define	LCK_MTX_LCK_WAIT_CODE		2
#define	LCK_MTX_UNLCK_WAKEUP_CODE	3


static queue_head_t	lck_grp_queue;
static unsigned int	lck_grp_cnt;

decl_mutex_data(static,lck_grp_lock)

lck_grp_attr_t	LockDefaultGroupAttr;
lck_grp_t	LockCompatGroup;
lck_attr_t	LockDefaultLckAttr;

/*
 * Routine:	lck_mod_init
 */

void
lck_mod_init(
	void)
{
	queue_init(&lck_grp_queue);
	mutex_init(&lck_grp_lock, 0);
	lck_grp_cnt = 0;
	lck_grp_attr_setdefault( &LockDefaultGroupAttr);
	lck_grp_init( &LockCompatGroup, "Compatibility APIs", LCK_GRP_ATTR_NULL);
	lck_attr_setdefault(&LockDefaultLckAttr);
}

/*
 * Routine:	lck_grp_attr_alloc_init
 */

lck_grp_attr_t	*
lck_grp_attr_alloc_init(
	void)
{
	lck_grp_attr_t	*attr;

	if ((attr = (lck_grp_attr_t *)kalloc(sizeof(lck_grp_attr_t))) != 0)
		lck_grp_attr_setdefault(attr);

	return(attr);
}


/*
 * Routine:	lck_grp_attr_setdefault
 */

void
lck_grp_attr_setdefault(
	lck_grp_attr_t	*attr)
{
	if (LcksOpts & enaLkStat)
		attr->grp_attr_val = LCK_GRP_ATTR_STAT;
	else
		attr->grp_attr_val = 0;
}


/*
 * Routine: 	lck_grp_attr_setstat
 */

void
lck_grp_attr_setstat(
	lck_grp_attr_t	*attr)
{
	(void)hw_atomic_or((uint32_t *)&attr->grp_attr_val, LCK_GRP_ATTR_STAT);
}


/*
 * Routine: 	lck_grp_attr_free
 */

void
lck_grp_attr_free(
	lck_grp_attr_t	*attr)
{
	kfree(attr, sizeof(lck_grp_attr_t));
}


/*
 * Routine: 	lck_grp_alloc_init
 */

lck_grp_t *
lck_grp_alloc_init(
	const char*	grp_name,
	lck_grp_attr_t	*attr)
{
	lck_grp_t	*grp;

	if ((grp = (lck_grp_t *)kalloc(sizeof(lck_grp_t))) != 0)
		lck_grp_init(grp, grp_name, attr);

	return(grp);
}


/*
 * Routine: 	lck_grp_init
 */

void
lck_grp_init(
	lck_grp_t		*grp,               
	const char*		grp_name,           
	lck_grp_attr_t	*attr)             
{
	bzero((void *)grp, sizeof(lck_grp_t));

	(void) strncpy(grp->lck_grp_name, grp_name, LCK_GRP_MAX_NAME);

	if (attr != LCK_GRP_ATTR_NULL)
		grp->lck_grp_attr = attr->grp_attr_val;
	else if (LcksOpts & enaLkStat)
                grp->lck_grp_attr = LCK_GRP_ATTR_STAT;
        else
                grp->lck_grp_attr = LCK_ATTR_NONE;

	grp->lck_grp_refcnt = 1;

	mutex_lock(&lck_grp_lock);
	enqueue_tail(&lck_grp_queue, (queue_entry_t)grp);
	lck_grp_cnt++;
	mutex_unlock(&lck_grp_lock);

}


/*
 * Routine: 	lck_grp_free
 */

void
lck_grp_free(
	lck_grp_t	*grp)
{
	mutex_lock(&lck_grp_lock);
	lck_grp_cnt--;
	(void)remque((queue_entry_t)grp);
	mutex_unlock(&lck_grp_lock);
	lck_grp_deallocate(grp);
}


/*
 * Routine: 	lck_grp_reference
 */

void
lck_grp_reference(
	lck_grp_t	*grp)
{
	(void)hw_atomic_add((uint32_t *)(&grp->lck_grp_refcnt), 1);
}


/*
 * Routine: 	lck_grp_deallocate
 */

void
lck_grp_deallocate(
	lck_grp_t	*grp)
{
	if (hw_atomic_sub((uint32_t *)(&grp->lck_grp_refcnt), 1) == 0)
	 	kfree(grp, sizeof(lck_grp_t));
}

/*
 * Routine:	lck_grp_lckcnt_incr
 */

void
lck_grp_lckcnt_incr(
	lck_grp_t	*grp,
	lck_type_t	lck_type)
{
	unsigned int	*lckcnt;

	switch (lck_type) {
	case LCK_TYPE_SPIN:
		lckcnt = &grp->lck_grp_spincnt;
		break;
	case LCK_TYPE_MTX:
		lckcnt = &grp->lck_grp_mtxcnt;
		break;
	case LCK_TYPE_RW:
		lckcnt = &grp->lck_grp_rwcnt;
		break;
	default:
		return panic("lck_grp_lckcnt_incr(): invalid lock type: %d\n", lck_type);
	}

	(void)hw_atomic_add((uint32_t *)lckcnt, 1);
}

/*
 * Routine:	lck_grp_lckcnt_decr
 */

void
lck_grp_lckcnt_decr(
	lck_grp_t	*grp,
	lck_type_t	lck_type)
{
	unsigned int	*lckcnt;

	switch (lck_type) {
	case LCK_TYPE_SPIN:
		lckcnt = &grp->lck_grp_spincnt;
		break;
	case LCK_TYPE_MTX:
		lckcnt = &grp->lck_grp_mtxcnt;
		break;
	case LCK_TYPE_RW:
		lckcnt = &grp->lck_grp_rwcnt;
		break;
	default:
		return panic("lck_grp_lckcnt_decr(): invalid lock type: %d\n", lck_type);
	}

	(void)hw_atomic_sub((uint32_t *)lckcnt, 1);
}

/*
 * Routine:	lck_attr_alloc_init
 */

lck_attr_t *
lck_attr_alloc_init(
	void)
{
	lck_attr_t	*attr;

	if ((attr = (lck_attr_t *)kalloc(sizeof(lck_attr_t))) != 0)
		lck_attr_setdefault(attr);

	return(attr);
}


/*
 * Routine:	lck_attr_setdefault
 */

void
lck_attr_setdefault(
	lck_attr_t	*attr)
{
#if     !DEBUG
	if (LcksOpts & enaLkDeb)
		attr->lck_attr_val =  LCK_ATTR_DEBUG;
	else
		attr->lck_attr_val =  LCK_ATTR_NONE;
#else
	attr->lck_attr_val =  LCK_ATTR_DEBUG;
#endif

}


/*
 * Routine:	lck_attr_setdebug
 */
void
lck_attr_setdebug(
	lck_attr_t	*attr)
{
	(void)hw_atomic_or((uint32_t *)&attr->lck_attr_val, LCK_ATTR_DEBUG);
}


/*
 * Routine:	lck_attr_free
 */
void
lck_attr_free(
	lck_attr_t	*attr)
{
	kfree(attr, sizeof(lck_attr_t));
}


/*
 * Routine:	lck_spin_sleep
 */
wait_result_t
lck_spin_sleep(
        lck_spin_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible)
{
	wait_result_t	res;
 
	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK))
			lck_spin_lock(lck);
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_spin_unlock(lck);

	return res;
}


/*
 * Routine:	lck_spin_sleep_deadline
 */
wait_result_t
lck_spin_sleep_deadline(
        lck_spin_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible,
	uint64_t		deadline)
{
	wait_result_t   res;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_spin_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK))
			lck_spin_lock(lck);
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_spin_unlock(lck);

	return res;
}


/*
 * Routine:	lck_mtx_sleep
 */
wait_result_t
lck_mtx_sleep(
        lck_mtx_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible)
{
	wait_result_t	res;
 
	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_START,
		     (int)lck, (int)lck_sleep_action, (int)event, (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK))
			lck_mtx_lock(lck);
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_mtx_unlock(lck);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}


/*
 * Routine:	lck_mtx_sleep_deadline
 */
wait_result_t
lck_mtx_sleep_deadline(
        lck_mtx_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible,
	uint64_t		deadline)
{
	wait_result_t   res;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_START,
		     (int)lck, (int)lck_sleep_action, (int)event, (int)interruptible, 0);

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_mtx_unlock(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK))
			lck_mtx_lock(lck);
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		lck_mtx_unlock(lck);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_SLEEP_DEADLINE_CODE) | DBG_FUNC_END, (int)res, 0, 0, 0, 0);

	return res;
}

/*
 * Routine: 	lck_mtx_lock_wait
 *
 * Invoked in order to wait on contention.
 *
 * Called with the interlock locked and
 * returns it unlocked.
 */
void
lck_mtx_lock_wait (
	lck_mtx_t			*lck,
	thread_t			holder)
{
	thread_t		self = current_thread();
	lck_mtx_t		*mutex;
	integer_t		priority;
	spl_t			s = splsched();

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_START, (int)lck, (int)holder, 0, 0, 0);

	priority = self->sched_pri;
	if (priority < self->priority)
		priority = self->priority;
	if (priority > MINPRI_KERNEL)
		priority = MINPRI_KERNEL;
	else
	if (priority < BASEPRI_DEFAULT)
		priority = BASEPRI_DEFAULT;

	thread_lock(holder);
	if (mutex->lck_mtx_pri == 0)
		holder->promotions++;
	if (holder->priority < MINPRI_KERNEL) {
		holder->sched_mode |= TH_MODE_PROMOTED;
		if (	mutex->lck_mtx_pri < priority	&&
				holder->sched_pri < priority		) {
			KERNEL_DEBUG_CONSTANT(
				MACHDBG_CODE(DBG_MACH_SCHED,MACH_PROMOTE) | DBG_FUNC_NONE,
					holder->sched_pri, priority, (int)holder, (int)lck, 0);

			set_sched_pri(holder, priority);
		}
	}
	thread_unlock(holder);
	splx(s);

	if (mutex->lck_mtx_pri < priority)
		mutex->lck_mtx_pri = priority;
	if (self->pending_promoter[self->pending_promoter_index] == NULL) {
		self->pending_promoter[self->pending_promoter_index] = mutex;
		mutex->lck_mtx_waiters++;
	}
	else
	if (self->pending_promoter[self->pending_promoter_index] != mutex) {
		self->pending_promoter[++self->pending_promoter_index] = mutex;
		mutex->lck_mtx_waiters++;
	}

	assert_wait((event_t)(((unsigned int*)lck)+((sizeof(lck_mtx_t)-1)/sizeof(unsigned int))), THREAD_UNINT);
	lck_mtx_ilk_unlock(mutex);

	thread_block(THREAD_CONTINUE_NULL);

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_LCK_WAIT_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

/*
 * Routine: 	lck_mtx_lock_acquire
 *
 * Invoked on acquiring the mutex when there is
 * contention.
 *
 * Returns the current number of waiters.
 *
 * Called with the interlock locked.
 */
int
lck_mtx_lock_acquire(
	lck_mtx_t		*lck)
{
	thread_t		thread = current_thread();
	lck_mtx_t		*mutex;

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;

	if (thread->pending_promoter[thread->pending_promoter_index] == mutex) {
		thread->pending_promoter[thread->pending_promoter_index] = NULL;
		if (thread->pending_promoter_index > 0)
			thread->pending_promoter_index--;
		mutex->lck_mtx_waiters--;
	}

	if (mutex->lck_mtx_waiters > 0) {
		integer_t		priority = mutex->lck_mtx_pri;
		spl_t			s = splsched();

		thread_lock(thread);
		thread->promotions++;
		if (thread->priority < MINPRI_KERNEL) {
			thread->sched_mode |= TH_MODE_PROMOTED;
			if (thread->sched_pri < priority) {
				KERNEL_DEBUG_CONSTANT(
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_PROMOTE) | DBG_FUNC_NONE,
						thread->sched_pri, priority, 0, (int)lck, 0);

				set_sched_pri(thread, priority);
			}
		}
		thread_unlock(thread);
		splx(s);
	}
	else
		mutex->lck_mtx_pri = 0;

	return (mutex->lck_mtx_waiters);
}

/*
 * Routine: 	lck_mtx_unlock_wakeup
 *
 * Invoked on unlock when there is contention.
 *
 * Called with the interlock locked.
 */
void
lck_mtx_unlock_wakeup (
	lck_mtx_t			*lck,
	thread_t			holder)
{
	thread_t		thread = current_thread();
	lck_mtx_t		*mutex;

	if (lck->lck_mtx_tag != LCK_MTX_TAG_INDIRECT)
		mutex = lck;
	else
		mutex = &lck->lck_mtx_ptr->lck_mtx;


	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_START, (int)lck, (int)holder, 0, 0, 0);

	if (thread != holder)
		panic("lck_mtx_unlock_wakeup: mutex %x holder %x\n", mutex, holder);

	if (thread->promotions > 0) {
		spl_t		s = splsched();

		thread_lock(thread);
		if (	--thread->promotions == 0				&&
				(thread->sched_mode & TH_MODE_PROMOTED)		) {
			thread->sched_mode &= ~TH_MODE_PROMOTED;
			if (thread->sched_mode & TH_MODE_ISDEPRESSED) {
				KERNEL_DEBUG_CONSTANT(
					MACHDBG_CODE(DBG_MACH_SCHED,MACH_DEMOTE) | DBG_FUNC_NONE,
						  thread->sched_pri, DEPRESSPRI, 0, (int)lck, 0);

				set_sched_pri(thread, DEPRESSPRI);
			}
			else {
				if (thread->priority < thread->sched_pri) {
					KERNEL_DEBUG_CONSTANT(
						MACHDBG_CODE(DBG_MACH_SCHED,MACH_DEMOTE) |
															DBG_FUNC_NONE,
							thread->sched_pri, thread->priority,
									0, (int)lck, 0);
				}

				compute_priority(thread, FALSE);
			}
		}
		thread_unlock(thread);
		splx(s);
	}
	assert(mutex->lck_mtx_waiters > 0);
	thread_wakeup_one((event_t)(((unsigned int*)lck)+(sizeof(lck_mtx_t)-1)/sizeof(unsigned int)));

	KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_LOCKS, LCK_MTX_UNLCK_WAKEUP_CODE) | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

/*
 * Routine: 	mutex_pause
 *
 * Called by former callers of simple_lock_pause().
 */

void
mutex_pause(void)
{
	wait_result_t wait_result;

	wait_result = assert_wait_timeout((event_t)mutex_pause, THREAD_UNINT, 1, 1000*NSEC_PER_USEC);
	assert(wait_result == THREAD_WAITING);

	wait_result = thread_block(THREAD_CONTINUE_NULL);
	assert(wait_result == THREAD_TIMED_OUT);
}

/*
 * Routine:	lck_rw_sleep
 */
wait_result_t
lck_rw_sleep(
        lck_rw_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible)
{
	wait_result_t	res;
	lck_rw_type_t	lck_rw_type;
 
	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait(event, interruptible);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED|LCK_SLEEP_EXCLUSIVE)))
				lck_rw_lock(lck, lck_rw_type);
			else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE)
				lck_rw_lock_exclusive(lck);
			else
				lck_rw_lock_shared(lck);
		}
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		(void)lck_rw_done(lck);

	return res;
}


/*
 * Routine:	lck_rw_sleep_deadline
 */
wait_result_t
lck_rw_sleep_deadline(
	lck_rw_t		*lck,
	lck_sleep_action_t	lck_sleep_action,
	event_t			event,
	wait_interrupt_t	interruptible,
	uint64_t		deadline)
{
	wait_result_t   res;
	lck_rw_type_t	lck_rw_type;

	if ((lck_sleep_action & ~LCK_SLEEP_MASK) != 0)
		panic("Invalid lock sleep action %x\n", lck_sleep_action);

	res = assert_wait_deadline(event, interruptible, deadline);
	if (res == THREAD_WAITING) {
		lck_rw_type = lck_rw_done(lck);
		res = thread_block(THREAD_CONTINUE_NULL);
		if (!(lck_sleep_action & LCK_SLEEP_UNLOCK)) {
			if (!(lck_sleep_action & (LCK_SLEEP_SHARED|LCK_SLEEP_EXCLUSIVE)))
				lck_rw_lock(lck, lck_rw_type);
			else if (lck_sleep_action & LCK_SLEEP_EXCLUSIVE)
				lck_rw_lock_exclusive(lck);
			else
				lck_rw_lock_shared(lck);
		}
	}
	else
	if (lck_sleep_action & LCK_SLEEP_UNLOCK)
		(void)lck_rw_done(lck);

	return res;
}

kern_return_t
host_lockgroup_info(
	host_t					host,
	lockgroup_info_array_t	*lockgroup_infop,
	mach_msg_type_number_t	*lockgroup_infoCntp)
{
	lockgroup_info_t	*lockgroup_info_base;
	lockgroup_info_t	*lockgroup_info;
	vm_offset_t			lockgroup_info_addr;
	vm_size_t			lockgroup_info_size;
	lck_grp_t			*lck_grp;
	unsigned int		i;
	vm_size_t			used;
	vm_map_copy_t		copy;
	kern_return_t		kr;

	if (host == HOST_NULL)
		return KERN_INVALID_HOST;

	mutex_lock(&lck_grp_lock);

	lockgroup_info_size = round_page(lck_grp_cnt * sizeof *lockgroup_info);
	kr = kmem_alloc_pageable(ipc_kernel_map,
						 &lockgroup_info_addr, lockgroup_info_size);
	if (kr != KERN_SUCCESS) {
		mutex_unlock(&lck_grp_lock);
		return(kr);
	}

	lockgroup_info_base = (lockgroup_info_t *) lockgroup_info_addr;
	lck_grp = (lck_grp_t *)queue_first(&lck_grp_queue);
	lockgroup_info = lockgroup_info_base;

	for (i = 0; i < lck_grp_cnt; i++) {

		lockgroup_info->lock_spin_cnt = lck_grp->lck_grp_spincnt;
		lockgroup_info->lock_spin_util_cnt = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_util_cnt;
		lockgroup_info->lock_spin_held_cnt = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_held_cnt;
		lockgroup_info->lock_spin_miss_cnt = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_miss_cnt;
		lockgroup_info->lock_spin_held_max = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_held_max;
		lockgroup_info->lock_spin_held_cum = lck_grp->lck_grp_stat.lck_grp_spin_stat.lck_grp_spin_held_cum;

		lockgroup_info->lock_mtx_cnt = lck_grp->lck_grp_mtxcnt;
		lockgroup_info->lock_mtx_util_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_util_cnt;
		lockgroup_info->lock_mtx_held_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_cnt;
		lockgroup_info->lock_mtx_miss_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_miss_cnt;
		lockgroup_info->lock_mtx_wait_cnt = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cnt;
		lockgroup_info->lock_mtx_held_max = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_max;
		lockgroup_info->lock_mtx_held_cum = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_cum;
		lockgroup_info->lock_mtx_wait_max = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_max;
		lockgroup_info->lock_mtx_wait_cum = lck_grp->lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cum;

		lockgroup_info->lock_rw_cnt = lck_grp->lck_grp_rwcnt;
		lockgroup_info->lock_rw_util_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_util_cnt;
		lockgroup_info->lock_rw_held_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_held_cnt;
		lockgroup_info->lock_rw_miss_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_miss_cnt;
		lockgroup_info->lock_rw_wait_cnt = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cnt;
		lockgroup_info->lock_rw_held_max = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_held_max;
		lockgroup_info->lock_rw_held_cum = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_held_cum;
		lockgroup_info->lock_rw_wait_max = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_max;
		lockgroup_info->lock_rw_wait_cum = lck_grp->lck_grp_stat.lck_grp_rw_stat.lck_grp_rw_wait_cum;

		(void) strncpy(lockgroup_info->lockgroup_name,lck_grp->lck_grp_name, LOCKGROUP_MAX_NAME);

		lck_grp = (lck_grp_t *)(queue_next((queue_entry_t)(lck_grp)));
		lockgroup_info++;
	}

	*lockgroup_infoCntp = lck_grp_cnt;
	mutex_unlock(&lck_grp_lock);

	used = (*lockgroup_infoCntp) * sizeof *lockgroup_info;

	if (used != lockgroup_info_size)
		bzero((char *) lockgroup_info, lockgroup_info_size - used);

	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)lockgroup_info_addr,
			   (vm_map_size_t)lockgroup_info_size, TRUE, &copy);
	assert(kr == KERN_SUCCESS);

	*lockgroup_infop = (lockgroup_info_t *) copy;

	return(KERN_SUCCESS);
}

/*
 * Compatibility module 
 */

extern lck_rw_t		*lock_alloc_EXT( boolean_t can_sleep, unsigned short  tag0, unsigned short  tag1);
extern void		lock_done_EXT(lck_rw_t *lock);
extern void		lock_free_EXT(lck_rw_t *lock);
extern void		lock_init_EXT(lck_rw_t *lock, boolean_t can_sleep, unsigned short tag0, unsigned short tag1);
extern void		lock_read_EXT(lck_rw_t *lock);
extern boolean_t	lock_read_to_write_EXT(lck_rw_t *lock);
extern void		lock_write_EXT(lck_rw_t *lock);
extern void		lock_write_to_read_EXT(lck_rw_t	*lock);
extern wait_result_t	thread_sleep_lock_write_EXT( 
				event_t event, lck_rw_t *lock, wait_interrupt_t interruptible);

extern lck_mtx_t	*mutex_alloc_EXT(unsigned short tag);
extern void		mutex_free_EXT(lck_mtx_t *mutex);
extern void		mutex_init_EXT(lck_mtx_t *mutex, unsigned short tag);
extern void		mutex_lock_EXT(lck_mtx_t *mutex);
extern boolean_t	mutex_try_EXT(lck_mtx_t *mutex);
extern void		mutex_unlock_EXT(lck_mtx_t *mutex);
extern wait_result_t	thread_sleep_mutex_EXT(
				event_t event, lck_mtx_t *mutex, wait_interrupt_t interruptible);
extern wait_result_t	thread_sleep_mutex_deadline_EXT(
				event_t event, lck_mtx_t *mutex, uint64_t deadline, wait_interrupt_t interruptible);

extern void		usimple_lock_EXT(lck_spin_t *lock);
extern void		usimple_lock_init_EXT(lck_spin_t *lock, unsigned short tag);
extern unsigned int	usimple_lock_try_EXT(lck_spin_t *lock);
extern void		usimple_unlock_EXT(lck_spin_t *lock);
extern wait_result_t	thread_sleep_usimple_lock_EXT(event_t event, lck_spin_t *lock, wait_interrupt_t interruptible);

lck_rw_t * 
lock_alloc_EXT(
	__unused boolean_t       can_sleep,
	__unused unsigned short  tag0,
	__unused unsigned short  tag1)
{
	return( lck_rw_alloc_init( &LockCompatGroup, LCK_ATTR_NULL));
}

void
lock_done_EXT(
	lck_rw_t	*lock)
{
	(void) lck_rw_done(lock);
}

void
lock_free_EXT(
	lck_rw_t	*lock)
{
	lck_rw_free(lock, &LockCompatGroup);
}

void
lock_init_EXT(
	lck_rw_t	*lock,
	__unused boolean_t	can_sleep,
	__unused unsigned short	tag0,
	__unused unsigned short	tag1)
{
	lck_rw_init(lock, &LockCompatGroup, LCK_ATTR_NULL);	
}

void
lock_read_EXT(
	lck_rw_t	*lock)
{
	lck_rw_lock_shared( lock);
}

boolean_t
lock_read_to_write_EXT(
	lck_rw_t	*lock)
{
	return( lck_rw_lock_shared_to_exclusive(lock));
}

void
lock_write_EXT(
	lck_rw_t	*lock)
{
	lck_rw_lock_exclusive(lock);
}

void
lock_write_to_read_EXT(
	lck_rw_t	*lock)
{
	lck_rw_lock_exclusive_to_shared(lock);
}

wait_result_t
thread_sleep_lock_write_EXT(
	event_t			event,
	lck_rw_t		*lock,
	wait_interrupt_t	interruptible)
{
	return( lck_rw_sleep(lock, LCK_SLEEP_EXCLUSIVE, event, interruptible));
}

lck_mtx_t *
mutex_alloc_EXT(
	__unused unsigned short		tag)
{
	return(lck_mtx_alloc_init(&LockCompatGroup, LCK_ATTR_NULL));
}

void
mutex_free_EXT(
	lck_mtx_t		*mutex)
{
	lck_mtx_free(mutex, &LockCompatGroup);	
}

void
mutex_init_EXT(
	lck_mtx_t		*mutex,
	__unused unsigned short	tag)
{
	lck_mtx_init(mutex, &LockCompatGroup, LCK_ATTR_NULL);	
}

void
mutex_lock_EXT(
	lck_mtx_t		*mutex)
{
	lck_mtx_lock(mutex);
}

boolean_t
mutex_try_EXT(
	lck_mtx_t		*mutex)
{
	return(lck_mtx_try_lock(mutex));
}

void
mutex_unlock_EXT(
	lck_mtx_t		*mutex)
{
	lck_mtx_unlock(mutex);
}

wait_result_t
thread_sleep_mutex_EXT(
	event_t			event,
	lck_mtx_t		*mutex,
	wait_interrupt_t        interruptible)
{
	return( lck_mtx_sleep(mutex, LCK_SLEEP_DEFAULT, event, interruptible));
}

wait_result_t
thread_sleep_mutex_deadline_EXT(
	event_t			event,
	lck_mtx_t		*mutex,
	uint64_t		deadline,
	wait_interrupt_t        interruptible)
{
	return( lck_mtx_sleep_deadline(mutex, LCK_SLEEP_DEFAULT, event, interruptible, deadline));
}

void
usimple_lock_EXT(
	lck_spin_t		*lock)
{
	lck_spin_lock(lock);
}

void
usimple_lock_init_EXT(
	lck_spin_t		*lock,
	__unused unsigned short	tag)
{
	lck_spin_init(lock, &LockCompatGroup, LCK_ATTR_NULL);
}

unsigned int
usimple_lock_try_EXT(
	lck_spin_t		*lock)
{
	lck_spin_try_lock(lock);
}

void
usimple_unlock_EXT(
	lck_spin_t		*lock)
{
	lck_spin_unlock(lock);
}

wait_result_t
thread_sleep_usimple_lock_EXT(
	event_t			event,
	lck_spin_t		*lock,
	wait_interrupt_t	interruptible)
{
	return( lck_spin_sleep(lock, LCK_SLEEP_DEFAULT, event, interruptible));
}
