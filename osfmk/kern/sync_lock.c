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
 * @OSF_COPYRIGHT@
 * 
 */
/*
 *	File:	kern/sync_lock.c
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed lock synchronization services.
 */

#include <kern/etap_macros.h>
#include <kern/misc_protos.h>
#include <kern/sync_lock.h>
#include <kern/sched_prim.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_sync.h>
#include <kern/etap_macros.h>
#include <kern/thread.h>
#include <kern/task.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

/*
 *	Ulock ownership MACROS
 *
 *	Assumes: ulock internal lock is held 
 */

#define ulock_ownership_set(ul, th)				\
	MACRO_BEGIN						\
	thread_act_t _th_act;					\
	_th_act = (th)->top_act;				\
	act_lock(_th_act);					\
	enqueue (&_th_act->held_ulocks, (queue_entry_t) (ul));  \
	act_unlock(_th_act);					\
	(ul)->holder = _th_act;					\
	MACRO_END

#define ulock_ownership_clear(ul)				\
	MACRO_BEGIN						\
	thread_act_t _th_act;					\
	_th_act = (ul)->holder;					\
        if (_th_act->active) {					\
		act_lock(_th_act);				\
		remqueue(&_th_act->held_ulocks,			\
			 (queue_entry_t) (ul));			\
		act_unlock(_th_act);				\
	} else {						\
		remqueue(&_th_act->held_ulocks,			\
			 (queue_entry_t) (ul));			\
	}							\
	(ul)->holder = THR_ACT_NULL;				\
	MACRO_END

/*
 *	Lock set ownership MACROS
 */

#define lock_set_ownership_set(ls, t)				\
	MACRO_BEGIN						\
	task_lock((t));						\
	enqueue_head(&(t)->lock_set_list, (queue_entry_t) (ls));\
	(t)->lock_sets_owned++;					\
	task_unlock((t));					\
	(ls)->owner = (t);					\
	MACRO_END

#define lock_set_ownership_clear(ls, t)				\
	MACRO_BEGIN						\
	task_lock((t));						\
	remqueue(&(t)->lock_set_list, (queue_entry_t) (ls));	\
	(t)->lock_sets_owned--;					\
	task_unlock((t));					\
	MACRO_END

unsigned int lock_set_event;
#define LOCK_SET_EVENT ((event_t)&lock_set_event)

unsigned int lock_set_handoff;
#define LOCK_SET_HANDOFF ((event_t)&lock_set_handoff)

/*
 *	ROUTINE:	lock_set_init		[private]
 *
 *	Initialize the lock_set subsystem.
 *
 *	For now, we don't have anything to do here.
 */
void
lock_set_init(void)
{
	return;
}


/*
 *	ROUTINE:	lock_set_create		[exported]
 *
 *	Creates a lock set.
 *	The port representing the lock set is returned as a parameter.
 */      
kern_return_t
lock_set_create (
	task_t		task,
	lock_set_t	*new_lock_set,
	int		n_ulocks,
	int		policy)
{
	lock_set_t 	lock_set = LOCK_SET_NULL;
	ulock_t		ulock;
	int 		size;
	int 		x;

	*new_lock_set = LOCK_SET_NULL;

	if (task == TASK_NULL || n_ulocks <= 0 || policy > SYNC_POLICY_MAX)
		return KERN_INVALID_ARGUMENT;

	size = sizeof(struct lock_set) + (sizeof(struct ulock) * (n_ulocks-1));
	lock_set = (lock_set_t) kalloc (size);

	if (lock_set == LOCK_SET_NULL)
		return KERN_RESOURCE_SHORTAGE; 


	lock_set_lock_init(lock_set);
	lock_set->n_ulocks = n_ulocks;
	lock_set->ref_count = 1;

	/*
	 *  Create and initialize the lock set port
	 */
	lock_set->port = ipc_port_alloc_kernel();
	if (lock_set->port == IP_NULL) {	
		/* This will deallocate the lock set */
		lock_set_dereference(lock_set);
		return KERN_RESOURCE_SHORTAGE; 
	}

	ipc_kobject_set (lock_set->port,
			(ipc_kobject_t) lock_set,
			IKOT_LOCK_SET);

	/*
	 *  Initialize each ulock in the lock set
	 */

	for (x=0; x < n_ulocks; x++) {
		ulock = (ulock_t) &lock_set->ulock_list[x];
		ulock_lock_init(ulock);
		ulock->lock_set  = lock_set;
		ulock->holder	 = THR_ACT_NULL;
		ulock->blocked   = FALSE;
		ulock->unstable	 = FALSE;
		ulock->ho_wait	 = FALSE;
		wait_queue_init(&ulock->wait_queue, policy);
	}

	lock_set_ownership_set(lock_set, task);

	lock_set->active = TRUE;
	*new_lock_set = lock_set;

	return KERN_SUCCESS;
}

/*
 *	ROUTINE:	lock_set_destroy	[exported]
 *	
 *	Destroys a lock set.  This call will only succeed if the
 *	specified task is the SAME task name specified at the lock set's
 *	creation.
 *
 *	NOTES:
 *	- All threads currently blocked on the lock set's ulocks are awoken.
 *	- These threads will return with the KERN_LOCK_SET_DESTROYED error.
 */
kern_return_t
lock_set_destroy (task_t task, lock_set_t lock_set)
{
	thread_t	thread;
	ulock_t		ulock;
	int		i;

	if (task == TASK_NULL || lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_set->owner != task)
		return KERN_INVALID_RIGHT;

	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	/*
	 *  Deactivate lock set
	 */
	lock_set->active = FALSE;

	/*
	 *  If a ulock is currently held in the target lock set:
	 *
	 *  1) Wakeup all threads blocked on the ulock (if any).  Threads
	 *     may be blocked waiting normally, or waiting for a handoff.
	 *     Blocked threads will return with KERN_LOCK_SET_DESTROYED.
	 *
	 *  2) ulock ownership is cleared.
	 *     The thread currently holding the ulock is revoked of its
	 *     ownership.
	 */
	for (i = 0; i < lock_set->n_ulocks; i++) {
		ulock = &lock_set->ulock_list[i];

		ulock_lock(ulock);

		if (ulock->accept_wait) {
			ulock->accept_wait = FALSE;
			wait_queue_wakeup_one(&ulock->wait_queue,
					      LOCK_SET_HANDOFF,
					      THREAD_RESTART);
		}
					  
		if (ulock->holder) {
			if (ulock->blocked) {
				ulock->blocked = FALSE;
				wait_queue_wakeup_all(&ulock->wait_queue,
						      LOCK_SET_EVENT,
						      THREAD_RESTART);
			}
			if (ulock->ho_wait) {
				ulock->ho_wait = FALSE;
				wait_queue_wakeup_one(&ulock->wait_queue,
						      LOCK_SET_HANDOFF,
						      THREAD_RESTART);
			}
			ulock_ownership_clear(ulock);
		}
		
		ulock_unlock(ulock);
	}

	lock_set_unlock(lock_set);
	lock_set_ownership_clear(lock_set, task);

	/*
	 *  Deallocate	
	 *
	 *  Drop the lock set reference, which inturn destroys the
	 *  lock set structure if the reference count goes to zero.
	 */

	ipc_port_dealloc_kernel(lock_set->port);
	lock_set_dereference(lock_set);

	return KERN_SUCCESS;
}

kern_return_t
lock_acquire (lock_set_t lock_set, int lock_id)
{
	ulock_t   ulock;

	if (lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_id < 0 || lock_id >= lock_set->n_ulocks)
		return KERN_INVALID_ARGUMENT;

 retry:
	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	ulock = (ulock_t) &lock_set->ulock_list[lock_id];
	ulock_lock(ulock);
	lock_set_unlock(lock_set);

	/*
	 *  Block the current thread if the lock is already held.
	 */

	if (ulock->holder != THR_ACT_NULL) {
		int wait_result;

		lock_set_unlock(lock_set);

		if (ulock->holder == current_act()) {
			ulock_unlock(ulock);
			return KERN_LOCK_OWNED_SELF;
		}

		ulock->blocked = TRUE;
		(void)wait_queue_assert_wait(&ulock->wait_queue,
				       LOCK_SET_EVENT,
				       THREAD_ABORTSAFE);
		ulock_unlock(ulock);

		/*
		 *  Block - Wait for lock to become available.
		 */

		wait_result = thread_block((void (*)(void))0);

		/*
		 *  Check the result status:
		 *
		 *  Check to see why thread was woken up.  In all cases, we
		 *  already have been removed from the queue.
		 */
		switch (wait_result) {
		case THREAD_AWAKENED:
			/* lock transitioned from old locker to us */
			/* he already made us owner */
			return (ulock->unstable) ? KERN_LOCK_UNSTABLE :
				                   KERN_SUCCESS;

		case THREAD_INTERRUPTED:
			return KERN_ABORTED;

		case THREAD_RESTART:
			goto retry;  /* probably a dead lock_set */

		default:
			panic("lock_acquire\n");
		}
	}

	/*
	 *  Assign lock ownership
	 */
	ulock_ownership_set(ulock, current_thread());
	ulock_unlock(ulock);

	return (ulock->unstable) ? KERN_LOCK_UNSTABLE : KERN_SUCCESS;
}

kern_return_t
lock_release (lock_set_t lock_set, int lock_id)
{
	ulock_t	 ulock;

	if (lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_id < 0 || lock_id >= lock_set->n_ulocks)
		return KERN_INVALID_ARGUMENT;

	ulock = (ulock_t) &lock_set->ulock_list[lock_id];

	return (lock_release_internal(ulock, current_act()));
}

kern_return_t
lock_try (lock_set_t lock_set, int lock_id)
{
	ulock_t   ulock;


	if (lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_id < 0 || lock_id >= lock_set->n_ulocks)
		return KERN_INVALID_ARGUMENT;


	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	ulock = (ulock_t) &lock_set->ulock_list[lock_id];
	ulock_lock(ulock);
	lock_set_unlock(lock_set);

	/*
	 *  If the lock is already owned, we return without blocking.
	 *
	 *  An ownership status is returned to inform the caller as to
	 *  whether it already holds the lock or another thread does.
	 */

	if (ulock->holder != THR_ACT_NULL) {
		lock_set_unlock(lock_set);

		if (ulock->holder == current_act()) {
			ulock_unlock(ulock);
			return KERN_LOCK_OWNED_SELF;
		}
		
		ulock_unlock(ulock);
		return KERN_LOCK_OWNED;
 	}

	/*
	 *  Add the ulock to the lock set's held_ulocks list.
	 */

	ulock_ownership_set(ulock, current_thread());
	ulock_unlock(ulock);

	return (ulock->unstable) ? KERN_LOCK_UNSTABLE : KERN_SUCCESS;
}

kern_return_t
lock_make_stable (lock_set_t lock_set, int lock_id)
{
	ulock_t	 ulock;


	if (lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_id < 0 || lock_id >= lock_set->n_ulocks)
		return KERN_INVALID_ARGUMENT;


	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	ulock = (ulock_t) &lock_set->ulock_list[lock_id];
	ulock_lock(ulock);
	lock_set_unlock(lock_set);

	if (ulock->holder != current_act()) {
		ulock_unlock(ulock);
		return KERN_INVALID_RIGHT;
	}

	ulock->unstable = FALSE;
	ulock_unlock(ulock);

	return KERN_SUCCESS;
}

/*
 *	ROUTINE:	lock_make_unstable	[internal]
 *
 *	Marks the lock as unstable.
 *
 *	NOTES:
 *	- All future acquisitions of the lock will return with a
 *	  KERN_LOCK_UNSTABLE status, until the lock is made stable again.
 */
kern_return_t
lock_make_unstable (ulock_t ulock, thread_act_t thr_act)
{
	lock_set_t	lock_set;


	lock_set = ulock->lock_set;
	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	ulock_lock(ulock);
	lock_set_unlock(lock_set);

	if (ulock->holder != thr_act) {
		ulock_unlock(ulock);
		return KERN_INVALID_RIGHT;
	}

	ulock->unstable = TRUE;
	ulock_unlock(ulock);

	return KERN_SUCCESS;
}

/*
 *	ROUTINE:	lock_release_internal	[internal]
 *
 *	Releases the ulock.
 *	If any threads are blocked waiting for the ulock, one is woken-up.
 *
 */
kern_return_t
lock_release_internal (ulock_t ulock, thread_act_t thr_act)
{
	lock_set_t	lock_set;
	int		result;


	if ((lock_set = ulock->lock_set) == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}
	ulock_lock(ulock);
	lock_set_unlock(lock_set);		

	if (ulock->holder != thr_act) {
		ulock_unlock(ulock);
		lock_set_unlock(lock_set);
		return KERN_INVALID_RIGHT;
	}

 	/*
	 *  If we have a hint that threads might be waiting,
	 *  try to transfer the lock ownership to a waiting thread
	 *  and wake it up.
	 */
	if (ulock->blocked) {
		wait_queue_t	wq = &ulock->wait_queue;
		thread_t	thread;
		spl_t		s;

		s = splsched();
		wait_queue_lock(wq);
		thread = wait_queue_wakeup_identity_locked(wq,
							   LOCK_SET_EVENT,
							   THREAD_AWAKENED,
							   TRUE);
		/* wait_queue now unlocked, thread locked */

		if (thread != THREAD_NULL) {
			/*
			 * JMM - These ownership transfer macros have a
			 * locking/race problem.  To keep the thread from
			 * changing states on us (nullifying the ownership
			 * assignment) we need to keep the thread locked
			 * during the assignment.  But we can't because the
			 * macros take an activation lock, which is a mutex.
			 * Since this code was already broken before I got
			 * here, I will leave it for now.
			 */
			thread_unlock(thread);
			splx(s);

			/*
			 *  Transfer ulock ownership
			 *  from the current thread to the acquisition thread.
			 */
			ulock_ownership_clear(ulock);
			ulock_ownership_set(ulock, thread);
			ulock_unlock(ulock);
			
			return KERN_SUCCESS;
		} else {
			ulock->blocked = FALSE;
			splx(s);
		}
	}

	/*
	 *  Disown ulock
	 */
	ulock_ownership_clear(ulock);
	ulock_unlock(ulock);

	return KERN_SUCCESS;
}

kern_return_t
lock_handoff (lock_set_t lock_set, int lock_id)
{
	ulock_t   ulock;
	int	  wait_result;


	if (lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_id < 0 || lock_id >= lock_set->n_ulocks)
		return KERN_INVALID_ARGUMENT;

 retry:
	lock_set_lock(lock_set);

	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	ulock = (ulock_t) &lock_set->ulock_list[lock_id];
	ulock_lock(ulock);
	lock_set_unlock(lock_set);

	if (ulock->holder != current_act()) {
		ulock_unlock(ulock);
		lock_set_unlock(lock_set);
		return KERN_INVALID_RIGHT;
	}
	
	/*
	 *  If the accepting thread (the receiver) is already waiting
	 *  to accept the lock from the handoff thread (the sender),
	 *  then perform the hand-off now.
	 */

	if (ulock->accept_wait) {
		wait_queue_t	wq = &ulock->wait_queue;
		thread_t	thread;
		spl_t		s;

		/*
		 *  See who the lucky devil is, if he is still there waiting.
		 */
		s = splsched();
		wait_queue_lock(wq);
		thread = wait_queue_wakeup_identity_locked(
					   wq,
					   LOCK_SET_HANDOFF,
					   THREAD_AWAKENED,
					   TRUE);
		/* wait queue unlocked, thread locked */

		/*
		 *  Transfer lock ownership
		 */
		if (thread != THREAD_NULL) {
			/*
			 * JMM - These ownership transfer macros have a
			 * locking/race problem.  To keep the thread from
			 * changing states on us (nullifying the ownership
			 * assignment) we need to keep the thread locked
			 * during the assignment.  But we can't because the
			 * macros take an activation lock, which is a mutex.
			 * Since this code was already broken before I got
			 * here, I will leave it for now.
			 */
			thread_unlock(thread);
			splx(s);
			
			ulock_ownership_clear(ulock);
			ulock_ownership_set(ulock, thread);
			ulock->accept_wait = FALSE;
			ulock_unlock(ulock);
			return KERN_SUCCESS;
		} else {

			/*
			 * OOPS.  The accepting thread must have been aborted.
			 * and is racing back to clear the flag that says is
			 * waiting for an accept.  He will clear it when we
			 * release the lock, so just fall thru and wait for
			 * the next accept thread (that's the way it is
			 * specified).
			 */
			splx(s);
		}
	}

	/*
	 * Indicate that there is a hand-off thread waiting, and then wait
	 * for an accepting thread.
	 */
	ulock->ho_wait = TRUE;
	(void)wait_queue_assert_wait(&ulock->wait_queue,
			       LOCK_SET_HANDOFF,
			       THREAD_ABORTSAFE);
	ulock_unlock(ulock);

 	ETAP_SET_REASON(current_thread(), BLOCKED_ON_LOCK_HANDOFF);
	wait_result = thread_block((void (*)(void))0);

	/*
	 *  If the thread was woken-up via some action other than
	 *  lock_handoff_accept or lock_set_destroy (i.e. thread_terminate),
	 *  then we need to clear the ulock's handoff state.
	 */
	switch (wait_result) {

	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	case THREAD_INTERRUPTED:
		ulock_lock(ulock);
		assert(ulock->holder == current_act());
		ulock->ho_wait = FALSE;
		ulock_unlock(ulock);
		return KERN_ABORTED;

	case THREAD_RESTART:
		goto retry;

	default:
		panic("lock_handoff");
	}
}

kern_return_t
lock_handoff_accept (lock_set_t lock_set, int lock_id)
{
	ulock_t   ulock;
	int	  wait_result;


	if (lock_set == LOCK_SET_NULL)
		return KERN_INVALID_ARGUMENT;

	if (lock_id < 0 || lock_id >= lock_set->n_ulocks)
		return KERN_INVALID_ARGUMENT;

 retry:
	lock_set_lock(lock_set);
	if (!lock_set->active) {
		lock_set_unlock(lock_set);
		return KERN_LOCK_SET_DESTROYED;
	}

	ulock = (ulock_t) &lock_set->ulock_list[lock_id];
	ulock_lock(ulock);
	lock_set_unlock(lock_set);

	/*
	 * If there is another accepting thread that beat us, just
	 * return with an error.
	 */
	if (ulock->accept_wait) {
		ulock_unlock(ulock);
		return KERN_ALREADY_WAITING;
	}

	if (ulock->holder == current_act()) {
		ulock_unlock(ulock);
		return KERN_LOCK_OWNED_SELF;
	}

	/*
	 *  If the handoff thread (the sender) is already waiting to
	 *  hand-off the lock to the accepting thread (the receiver),
	 *  then perform the hand-off now.
	 */
	if (ulock->ho_wait) {
		wait_queue_t	wq = &ulock->wait_queue;
		thread_t	thread;

		/*
		 *  See who the lucky devil is, if he is still there waiting.
		 */
		assert(ulock->holder != THR_ACT_NULL);
		thread = ulock->holder->thread;

		if (wait_queue_wakeup_thread(wq,
					    LOCK_SET_HANDOFF,
					    thread,
					    THREAD_AWAKENED) == KERN_SUCCESS) {
			/*
			 * Holder thread was still waiting to give it
			 * away.  Take over ownership.
			 */
			ulock_ownership_clear(ulock);
			ulock_ownership_set(ulock, current_thread());
			ulock->ho_wait = FALSE;
			ulock_unlock(ulock);
			return (ulock->unstable) ? KERN_LOCK_UNSTABLE :
						   KERN_SUCCESS;
		}
			
		/*
		 * OOPS.  The owner was aborted out of the handoff.
		 * He will clear his own flag when he gets back.
		 * in the meantime, we will wait as if we didn't
		 * even see his flag (by falling thru).
		 */
	}		

	ulock->accept_wait = TRUE;
	(void)wait_queue_assert_wait(&ulock->wait_queue,
			       LOCK_SET_HANDOFF,
			       THREAD_ABORTSAFE);
	ulock_unlock(ulock);

 	ETAP_SET_REASON(current_thread(), BLOCKED_ON_LOCK_HANDOFF);
	wait_result = thread_block((void (*)(void))0);

	/*
	 *  If the thread was woken-up via some action other than
	 *  lock_handoff_accept or lock_set_destroy (i.e. thread_terminate),
	 *  then we need to clear the ulock's handoff state.
	 */
	switch (wait_result) {

	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	case THREAD_INTERRUPTED:
		ulock_lock(ulock);
		ulock->accept_wait = FALSE;
		ulock_unlock(ulock);
		return KERN_ABORTED;

	case THREAD_RESTART:
		goto retry;

	default:
		panic("lock_handoff_accept");
	}
}

/*
 *	Routine:	lock_set_reference
 *
 *	Take out a reference on a lock set.  This keeps the data structure
 *	in existence (but the lock set may be deactivated).
 */
void
lock_set_reference(lock_set_t lock_set)
{
	lock_set_lock(lock_set);
	lock_set->ref_count++;
	lock_set_unlock(lock_set);
}

/*
 *	Routine:	lock_set_dereference
 *
 *	Release a reference on a lock set.  If this is the last reference,
 *	the lock set data structure is deallocated.
 */
void
lock_set_dereference(lock_set_t lock_set)
{
	int	ref_count;
	int 	size;

	lock_set_lock(lock_set);
	ref_count = --(lock_set->ref_count);
	lock_set_unlock(lock_set);

	if (ref_count == 0) {
		size =	sizeof(struct lock_set) +
			(sizeof(struct ulock) * (lock_set->n_ulocks - 1));
		kfree((vm_offset_t) lock_set, size);
	}
}
