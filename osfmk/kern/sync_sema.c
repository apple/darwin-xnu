/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 * 
 */
/*
 *	File:	kern/sync_sema.c
 *	Author:	Joseph CaraDonna
 *
 *	Contains RT distributed semaphore synchronization services.
 */

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/kern_return.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <mach/task.h>

#include <kern/misc_protos.h>
#include <kern/sync_sema.h>
#include <kern/spl.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_sync.h>
#include <kern/ipc_tt.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <kern/host.h>
#include <kern/wait_queue.h>
#include <kern/zalloc.h>
#include <kern/mach_param.h>

#include <libkern/OSAtomic.h>

static unsigned int semaphore_event;
#define SEMAPHORE_EVENT CAST_EVENT64_T(&semaphore_event)

zone_t semaphore_zone;
unsigned int semaphore_max;

/* Forward declarations */


kern_return_t 
semaphore_wait_trap_internal(
				mach_port_name_t name,
				void (*caller_cont)(kern_return_t));

kern_return_t 
semaphore_wait_signal_trap_internal(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name,
				void (*caller_cont)(kern_return_t));

kern_return_t 
semaphore_timedwait_trap_internal(
				mach_port_name_t name,
				unsigned int sec,
				clock_res_t nsec,
				void (*caller_cont)(kern_return_t));

kern_return_t 
semaphore_timedwait_signal_trap_internal(
				mach_port_name_t wait_name,
				mach_port_name_t signal_name,
				unsigned int sec,
				clock_res_t nsec,
				void (*caller_cont)(kern_return_t));

kern_return_t
semaphore_signal_internal_trap(mach_port_name_t sema_name);

kern_return_t
semaphore_signal_internal(
			semaphore_t		semaphore,
			thread_t			thread,
			int				options);

kern_return_t
semaphore_convert_wait_result(
			int				wait_result);

void
semaphore_wait_continue(void);

static kern_return_t
semaphore_wait_internal(
			semaphore_t		wait_semaphore,
			semaphore_t		signal_semaphore,
			uint64_t		deadline,
			int				option,
			void (*caller_cont)(kern_return_t));

static __inline__ uint64_t
semaphore_deadline(
	unsigned int		sec,
	clock_res_t			nsec)
{
	uint64_t	abstime;

	nanoseconds_to_absolutetime((uint64_t)sec *	NSEC_PER_SEC + nsec, &abstime);
	clock_absolutetime_interval_to_deadline(abstime, &abstime);

	return (abstime);
}

/*
 *	ROUTINE:	semaphore_init		[private]
 *
 *	Initialize the semaphore mechanisms.
 *	Right now, we only need to initialize the semaphore zone.
 */      
void
semaphore_init(void)
{
  semaphore_zone = zinit(sizeof(struct semaphore),
			semaphore_max * sizeof(struct semaphore),
			sizeof(struct semaphore),
			"semaphores");
  zone_change(semaphore_zone, Z_NOENCRYPT, TRUE);
}

/*
 *	Routine:	semaphore_create
 *
 *	Creates a semaphore.
 *	The port representing the semaphore is returned as a parameter.
 */
kern_return_t
semaphore_create(
	task_t			task,
	semaphore_t		*new_semaphore,
	int				policy,
	int				value)
{
	semaphore_t		 s = SEMAPHORE_NULL;
	kern_return_t		kret;


	*new_semaphore = SEMAPHORE_NULL;
	if (task == TASK_NULL || value < 0 || policy > SYNC_POLICY_MAX)
		return KERN_INVALID_ARGUMENT;

	s = (semaphore_t) zalloc (semaphore_zone);

	if (s == SEMAPHORE_NULL)
		return KERN_RESOURCE_SHORTAGE; 

	kret = wait_queue_init(&s->wait_queue, policy); /* also inits lock */
	if (kret != KERN_SUCCESS) {
		zfree(semaphore_zone, s);
		return kret;
	}

	s->count = value;

	/*
	 * One reference for caller, one for port, and one for owner
	 * task (if not the kernel itself).
	 */
	s->ref_count = (task == kernel_task) ? 2 : 3;

	/*
	 *  Create and initialize the semaphore port
	 */
	s->port	= ipc_port_alloc_kernel();
	if (s->port == IP_NULL) {	
		zfree(semaphore_zone, s);
		return KERN_RESOURCE_SHORTAGE; 
	}

	ipc_kobject_set (s->port, (ipc_kobject_t) s, IKOT_SEMAPHORE);

	/*
	 *  Associate the new semaphore with the task by adding
	 *  the new semaphore to the task's semaphore list.
	 *
	 *  Associate the task with the new semaphore by having the
	 *  semaphores task pointer point to the owning task's structure.
	 */
	task_lock(task);
	enqueue_head(&task->semaphore_list, (queue_entry_t) s);
	task->semaphores_owned++;
	s->owner = task;
	s->active = TRUE;
	task_unlock(task);

	*new_semaphore = s;

	return KERN_SUCCESS;
}		  

/*
 *	Routine:	semaphore_destroy
 *
 *	Destroys a semaphore.  This call will only succeed if the
 *	specified task is the SAME task name specified at the semaphore's
 *	creation.
 *
 *	All threads currently blocked on the semaphore are awoken.  These
 *	threads will return with the KERN_TERMINATED error.
 */
kern_return_t
semaphore_destroy(
	task_t			task,
	semaphore_t		semaphore)
{
	int				old_count;
	spl_t			spl_level;


	if (task == TASK_NULL || semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	/*
	 *  Disown semaphore
	 */
	task_lock(task);
	if (semaphore->owner != task) {
		task_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}
	remqueue((queue_entry_t) semaphore);
	semaphore->owner = TASK_NULL;
	task->semaphores_owned--;
	task_unlock(task);

	spl_level = splsched();
	semaphore_lock(semaphore);

	/*
	 *  Deactivate semaphore
	 */
	assert(semaphore->active);
	semaphore->active = FALSE;

	/*
	 *  Wakeup blocked threads  
	 */
	old_count = semaphore->count;
	semaphore->count = 0;

	if (old_count < 0) {
		wait_queue_wakeup64_all_locked(&semaphore->wait_queue,
					     SEMAPHORE_EVENT,
					     THREAD_RESTART,
					     TRUE);		/* unlock? */
	} else {
		semaphore_unlock(semaphore);
	}
	splx(spl_level);

	/*
	 *  Deallocate
	 *
	 *  Drop the task's semaphore reference, which in turn deallocates
	 *  the semaphore structure if the reference count goes to zero.
	 */
	semaphore_dereference(semaphore);
	return KERN_SUCCESS;
}

/*
 *	Routine:	semaphore_signal_internal
 *
 *		Signals the semaphore as direct.  
 *	Assumptions:
 *		Semaphore is locked.
 */
kern_return_t
semaphore_signal_internal(
	semaphore_t		semaphore,
	thread_t		thread,
	int				options)
{
	kern_return_t kr;
	spl_t  spl_level;

	spl_level = splsched();
	semaphore_lock(semaphore);

	if (!semaphore->active) {
		semaphore_unlock(semaphore);
		splx(spl_level);
		return KERN_TERMINATED;
	}

	if (thread != THREAD_NULL) {
		if (semaphore->count < 0) {
			kr = wait_queue_wakeup64_thread_locked(
			        	&semaphore->wait_queue,
					SEMAPHORE_EVENT,
					thread,
					THREAD_AWAKENED,
					TRUE);  /* unlock? */
		} else {
			semaphore_unlock(semaphore);
			kr = KERN_NOT_WAITING;
		}
		splx(spl_level);
		return kr;
	} 

	if (options & SEMAPHORE_SIGNAL_ALL) {
		int old_count = semaphore->count;

		if (old_count < 0) {
			semaphore->count = 0;  /* always reset */
			kr = wait_queue_wakeup64_all_locked(
					&semaphore->wait_queue,
					SEMAPHORE_EVENT,
					THREAD_AWAKENED,
					TRUE);		/* unlock? */
		} else {
			if (options & SEMAPHORE_SIGNAL_PREPOST)
				semaphore->count++;
			semaphore_unlock(semaphore);
			kr = KERN_SUCCESS;
		}
		splx(spl_level);
		return kr;
	}
	
	if (semaphore->count < 0) {
		if (wait_queue_wakeup64_one_locked(
					&semaphore->wait_queue,
					SEMAPHORE_EVENT,
					THREAD_AWAKENED,
					FALSE) == KERN_SUCCESS) {
			semaphore_unlock(semaphore);
			splx(spl_level);
			return KERN_SUCCESS;
		} else
			semaphore->count = 0;  /* all waiters gone */
	}

	if (options & SEMAPHORE_SIGNAL_PREPOST) {
		semaphore->count++;
	}

	semaphore_unlock(semaphore);
	splx(spl_level);
	return KERN_NOT_WAITING;
}

/*
 *	Routine:	semaphore_signal_thread
 *
 *	If the specified thread is blocked on the semaphore, it is
 *	woken up.  If a NULL thread was supplied, then any one
 *	thread is woken up.  Otherwise the caller gets KERN_NOT_WAITING
 *	and the	semaphore is unchanged.
 */
kern_return_t
semaphore_signal_thread(
	semaphore_t	semaphore,
	thread_t	thread)
{
	kern_return_t		ret;

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	ret = semaphore_signal_internal(semaphore,
					thread,
					SEMAPHORE_OPTION_NONE);
	return ret;
}	

/*
 *	Routine:	semaphore_signal_thread_trap
 *
 *	Trap interface to the semaphore_signal_thread function.
 */
kern_return_t
semaphore_signal_thread_trap(
	struct semaphore_signal_thread_trap_args *args)
{
	mach_port_name_t sema_name = args->signal_name;
	mach_port_name_t thread_name = args->thread_name;
	semaphore_t	semaphore;
	thread_t	thread;
	kern_return_t	kr;

	/* 
	 * MACH_PORT_NULL is not an error. It means that we want to
	 * select any one thread that is already waiting, but not to
	 * pre-post the semaphore.
	 */
	if (thread_name != MACH_PORT_NULL) {
		thread = port_name_to_thread(thread_name);
		if (thread == THREAD_NULL)
			return KERN_INVALID_ARGUMENT;
	} else
		thread = THREAD_NULL;

	kr = port_name_to_semaphore(sema_name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_signal_internal(semaphore,
				thread,
				SEMAPHORE_OPTION_NONE);
		semaphore_dereference(semaphore);
	}
	if (thread != THREAD_NULL) {
		thread_deallocate(thread);
	}
	return kr;
}



/*
 *	Routine:	semaphore_signal
 *
 *		Traditional (in-kernel client and MIG interface) semaphore
 *		signal routine.  Most users will access the trap version.
 *
 *		This interface in not defined to return info about whether
 *		this call found a thread waiting or not.  The internal
 *		routines (and future external routines) do.  We have to
 *		convert those into plain KERN_SUCCESS returns.
 */
kern_return_t
semaphore_signal(
	semaphore_t		semaphore)
{
	kern_return_t		kr;

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	kr = semaphore_signal_internal(semaphore,
				       THREAD_NULL, 
				       SEMAPHORE_SIGNAL_PREPOST);
	if (kr == KERN_NOT_WAITING)
		return KERN_SUCCESS;
	return kr;
}

/*
 *	Routine:	semaphore_signal_trap
 *
 *	Trap interface to the semaphore_signal function.
 */
kern_return_t
semaphore_signal_trap(
	struct semaphore_signal_trap_args *args)
{
	mach_port_name_t sema_name = args->signal_name;

	return (semaphore_signal_internal_trap(sema_name));
}

kern_return_t
semaphore_signal_internal_trap(mach_port_name_t sema_name)
{
	semaphore_t	semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(sema_name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_signal_internal(semaphore, 
				THREAD_NULL, 
				SEMAPHORE_SIGNAL_PREPOST);
		semaphore_dereference(semaphore);
		if (kr == KERN_NOT_WAITING)
			kr = KERN_SUCCESS;
	}
	return kr;
}

/*
 *	Routine:	semaphore_signal_all
 *
 *	Awakens ALL threads currently blocked on the semaphore.
 *	The semaphore count returns to zero.
 */
kern_return_t
semaphore_signal_all(
	semaphore_t		semaphore)
{
	kern_return_t kr;

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	kr = semaphore_signal_internal(semaphore,
				       THREAD_NULL, 
				       SEMAPHORE_SIGNAL_ALL);
	if (kr == KERN_NOT_WAITING)
		return KERN_SUCCESS;
	return kr;
}

/*
 *	Routine:	semaphore_signal_all_trap
 *
 *	Trap interface to the semaphore_signal_all function.
 */
kern_return_t
semaphore_signal_all_trap(
	struct semaphore_signal_all_trap_args *args)
{
	mach_port_name_t sema_name = args->signal_name;
	semaphore_t	semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(sema_name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_signal_internal(semaphore,
				THREAD_NULL, 
				SEMAPHORE_SIGNAL_ALL);
		semaphore_dereference(semaphore);
		if (kr == KERN_NOT_WAITING)
			kr = KERN_SUCCESS;
	}
	return kr;
}

/*
 *	Routine:	semaphore_convert_wait_result
 *
 *	Generate the return code after a semaphore wait/block.  It
 *	takes the wait result as an input and coverts that to an
 *	appropriate result.
 */
kern_return_t
semaphore_convert_wait_result(int wait_result)
{
	switch (wait_result) {
	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	case THREAD_TIMED_OUT:
		return KERN_OPERATION_TIMED_OUT;
		
	case THREAD_INTERRUPTED:
		return KERN_ABORTED;

	case THREAD_RESTART:
		return KERN_TERMINATED;

	default:
		panic("semaphore_block\n");
		return KERN_FAILURE;
	}
}

/*
 *	Routine:	semaphore_wait_continue
 *
 *	Common continuation routine after waiting on a semphore.
 *	It returns directly to user space.
 */
void
semaphore_wait_continue(void)
{
	thread_t self = current_thread();
	int wait_result = self->wait_result;
	void (*caller_cont)(kern_return_t) = self->sth_continuation;

	assert(self->sth_waitsemaphore != SEMAPHORE_NULL);
	semaphore_dereference(self->sth_waitsemaphore);
	if (self->sth_signalsemaphore != SEMAPHORE_NULL)
		semaphore_dereference(self->sth_signalsemaphore);

	assert(caller_cont != (void (*)(kern_return_t))0);
	(*caller_cont)(semaphore_convert_wait_result(wait_result));
}

/*
 *	Routine:	semaphore_wait_internal
 *
 *		Decrements the semaphore count by one.  If the count is
 *		negative after the decrement, the calling thread blocks
 *		(possibly at a continuation and/or with a timeout).
 *
 *	Assumptions:
 *		The reference
 *		A reference is held on the signal semaphore.
 */
static kern_return_t
semaphore_wait_internal(
	semaphore_t		wait_semaphore,
	semaphore_t		signal_semaphore,
	uint64_t		deadline,
	int				option,
	void 			(*caller_cont)(kern_return_t))
{
	int					wait_result;
	spl_t				spl_level;
	kern_return_t		kr = KERN_ALREADY_WAITING;

	spl_level = splsched();
	semaphore_lock(wait_semaphore);

	if (!wait_semaphore->active) {
		kr = KERN_TERMINATED;
	} else if (wait_semaphore->count > 0) {
		wait_semaphore->count--;
		kr = KERN_SUCCESS;
	} else if (option & SEMAPHORE_TIMEOUT_NOBLOCK) {
		kr = KERN_OPERATION_TIMED_OUT;
	} else {
		thread_t	self = current_thread();

		wait_semaphore->count = -1;  /* we don't keep an actual count */
		thread_lock(self);
		(void)wait_queue_assert_wait64_locked(
					&wait_semaphore->wait_queue,
					SEMAPHORE_EVENT,
					THREAD_ABORTSAFE,
					TIMEOUT_URGENCY_USER_NORMAL,
					deadline, 0,
					self);
		thread_unlock(self);
	}
	semaphore_unlock(wait_semaphore);
	splx(spl_level);

	/*
	 * wait_semaphore is unlocked so we are free to go ahead and
	 * signal the signal_semaphore (if one was provided).
	 */
	if (signal_semaphore != SEMAPHORE_NULL) {
		kern_return_t signal_kr;

		/*
		 * lock the signal semaphore reference we got and signal it.
		 * This will NOT block (we cannot block after having asserted
		 * our intention to wait above).
		 */
		signal_kr = semaphore_signal_internal(signal_semaphore,
						      THREAD_NULL,
						      SEMAPHORE_SIGNAL_PREPOST);

		if (signal_kr == KERN_NOT_WAITING)
			signal_kr = KERN_SUCCESS;
		else if (signal_kr == KERN_TERMINATED) {
			/* 
			 * Uh!Oh!  The semaphore we were to signal died.
			 * We have to get ourselves out of the wait in
			 * case we get stuck here forever (it is assumed
			 * that the semaphore we were posting is gating
			 * the decision by someone else to post the
			 * semaphore we are waiting on).  People will
			 * discover the other dead semaphore soon enough.
			 * If we got out of the wait cleanly (someone
			 * already posted a wakeup to us) then return that
			 * (most important) result.  Otherwise,
			 * return the KERN_TERMINATED status.
			 */
			thread_t self = current_thread();

			clear_wait(self, THREAD_INTERRUPTED);
			kr = semaphore_convert_wait_result(self->wait_result);
			if (kr == KERN_ABORTED)
				kr = KERN_TERMINATED;
		}
	}
	
	/*
	 * If we had an error, or we didn't really need to wait we can
	 * return now that we have signalled the signal semaphore.
	 */
	if (kr != KERN_ALREADY_WAITING)
		return kr;

	/*
	 * Now, we can block.  If the caller supplied a continuation
	 * pointer of his own for after the block, block with the
	 * appropriate semaphore continuation.  Thiswill gather the
	 * semaphore results, release references on the semaphore(s),
	 * and then call the caller's continuation.
	 */
	if (caller_cont) {
		thread_t self = current_thread();

		self->sth_continuation = caller_cont;
		self->sth_waitsemaphore = wait_semaphore;
		self->sth_signalsemaphore = signal_semaphore;
		wait_result = thread_block((thread_continue_t)semaphore_wait_continue);
	}
	else {
		wait_result = thread_block(THREAD_CONTINUE_NULL);
	}

	return (semaphore_convert_wait_result(wait_result));
}


/*
 *	Routine:	semaphore_wait
 *
 *	Traditional (non-continuation) interface presented to
 * 	in-kernel clients to wait on a semaphore.
 */
kern_return_t
semaphore_wait(
	semaphore_t		semaphore)
{	

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	return(semaphore_wait_internal(semaphore,
					   SEMAPHORE_NULL,
					   0ULL, SEMAPHORE_OPTION_NONE,
				       (void (*)(kern_return_t))0));
}

kern_return_t
semaphore_wait_noblock(
	semaphore_t		semaphore)
{	

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	return(semaphore_wait_internal(semaphore,
					   SEMAPHORE_NULL,
					   0ULL, SEMAPHORE_TIMEOUT_NOBLOCK,
				       (void (*)(kern_return_t))0));
}

kern_return_t
semaphore_wait_deadline(
	semaphore_t		semaphore,
	uint64_t		deadline)
{	

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;

	return(semaphore_wait_internal(semaphore,
					   SEMAPHORE_NULL,
					   deadline, SEMAPHORE_OPTION_NONE,
				       (void (*)(kern_return_t))0));
}

/*
 *	Trap:	semaphore_wait_trap
 *
 *	Trap version of semaphore wait.  Called on behalf of user-level
 *	clients.
 */

kern_return_t
semaphore_wait_trap(
	struct semaphore_wait_trap_args *args)
{
	return(semaphore_wait_trap_internal(args->wait_name, thread_syscall_return));
}



kern_return_t
semaphore_wait_trap_internal(
	mach_port_name_t name, 
	void (*caller_cont)(kern_return_t))
{	
	semaphore_t	semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(name, &semaphore);
	if (kr == KERN_SUCCESS) {
		kr = semaphore_wait_internal(semaphore,
				SEMAPHORE_NULL,
				0ULL, SEMAPHORE_OPTION_NONE,
				caller_cont);
		semaphore_dereference(semaphore);
	}
	return kr;
}

/*
 *	Routine:	semaphore_timedwait
 *
 *	Traditional (non-continuation) interface presented to
 * 	in-kernel clients to wait on a semaphore with a timeout.
 *
 *	A timeout of {0,0} is considered non-blocking.
 */
kern_return_t
semaphore_timedwait(
	semaphore_t		semaphore,
	mach_timespec_t		wait_time)
{
	int				option = SEMAPHORE_OPTION_NONE;
	uint64_t		deadline = 0;

	if (semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;
	
	if(BAD_MACH_TIMESPEC(&wait_time))
		return KERN_INVALID_VALUE;

	if (wait_time.tv_sec == 0 && wait_time.tv_nsec == 0)
		option = SEMAPHORE_TIMEOUT_NOBLOCK;
	else
		deadline = semaphore_deadline(wait_time.tv_sec, wait_time.tv_nsec);
	
	return (semaphore_wait_internal(semaphore,
					SEMAPHORE_NULL,
					deadline, option,
					(void(*)(kern_return_t))0));
	
}

/*
 *	Trap:	semaphore_timedwait_trap
 *
 *	Trap version of a semaphore_timedwait.  The timeout parameter
 *	is passed in two distinct parts and re-assembled on this side
 *	of the trap interface (to accomodate calling conventions that
 *	pass structures as pointers instead of inline in registers without
 *	having to add a copyin).
 *
 *	A timeout of {0,0} is considered non-blocking.
 */
kern_return_t
semaphore_timedwait_trap(
	struct semaphore_timedwait_trap_args *args)
{	

	return(semaphore_timedwait_trap_internal(args->wait_name, args->sec, args->nsec, thread_syscall_return));
}


kern_return_t
semaphore_timedwait_trap_internal(
	mach_port_name_t name,
	unsigned int            sec,
	clock_res_t             nsec,
	void (*caller_cont)(kern_return_t))
{
	semaphore_t semaphore;
	mach_timespec_t wait_time;
	kern_return_t kr;

	wait_time.tv_sec = sec;
	wait_time.tv_nsec = nsec;
	if(BAD_MACH_TIMESPEC(&wait_time))
		return KERN_INVALID_VALUE;
	
	kr = port_name_to_semaphore(name, &semaphore);
	if (kr == KERN_SUCCESS) {
		int				option = SEMAPHORE_OPTION_NONE;
		uint64_t		deadline = 0;

		if (sec == 0 && nsec == 0)
			option = SEMAPHORE_TIMEOUT_NOBLOCK;
		else
			deadline = semaphore_deadline(sec, nsec);

		kr = semaphore_wait_internal(semaphore,
				SEMAPHORE_NULL,
				deadline, option,
				caller_cont);
		semaphore_dereference(semaphore);
	}
	return kr;
}

/*
 *	Routine:	semaphore_wait_signal
 *
 *	Atomically register a wait on a semaphore and THEN signal
 *	another.  This is the in-kernel entry point that does not
 *	block at a continuation and does not free a signal_semaphore
 *      reference.
 */
kern_return_t
semaphore_wait_signal(
	semaphore_t		wait_semaphore,
	semaphore_t		signal_semaphore)
{
	if (wait_semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;
	
	return(semaphore_wait_internal(wait_semaphore,
				       signal_semaphore,
					   0ULL, SEMAPHORE_OPTION_NONE,
				       (void(*)(kern_return_t))0));
}

/*
 *	Trap:	semaphore_wait_signal_trap
 *
 *	Atomically register a wait on a semaphore and THEN signal
 *	another.  This is the trap version from user space.  
 */
kern_return_t
semaphore_wait_signal_trap(
	struct semaphore_wait_signal_trap_args *args)
{
	return(semaphore_wait_signal_trap_internal(args->wait_name, args->signal_name, thread_syscall_return));
}

kern_return_t
semaphore_wait_signal_trap_internal(
	mach_port_name_t wait_name,
	mach_port_name_t signal_name,
	void (*caller_cont)(kern_return_t))
{
	semaphore_t wait_semaphore;
	semaphore_t signal_semaphore;
	kern_return_t kr;

	kr = port_name_to_semaphore(signal_name, &signal_semaphore);
	if (kr == KERN_SUCCESS) {
		kr = port_name_to_semaphore(wait_name, &wait_semaphore);
		if (kr == KERN_SUCCESS) {
			kr = semaphore_wait_internal(wait_semaphore,
					signal_semaphore,
					0ULL, SEMAPHORE_OPTION_NONE,
					caller_cont);
			semaphore_dereference(wait_semaphore);
		}
		semaphore_dereference(signal_semaphore);
	}
	return kr;
}


/*
 *	Routine:	semaphore_timedwait_signal
 *
 *	Atomically register a wait on a semaphore and THEN signal
 *	another.  This is the in-kernel entry point that does not
 *	block at a continuation.
 *
 *	A timeout of {0,0} is considered non-blocking.
 */
kern_return_t
semaphore_timedwait_signal(
	semaphore_t		wait_semaphore,
	semaphore_t		signal_semaphore,
	mach_timespec_t		wait_time)
{
	int				option = SEMAPHORE_OPTION_NONE;
	uint64_t		deadline = 0;

	if (wait_semaphore == SEMAPHORE_NULL)
		return KERN_INVALID_ARGUMENT;
	
	if(BAD_MACH_TIMESPEC(&wait_time))
		return KERN_INVALID_VALUE;

	if (wait_time.tv_sec == 0 && wait_time.tv_nsec == 0)
		option = SEMAPHORE_TIMEOUT_NOBLOCK;
	else
		deadline = semaphore_deadline(wait_time.tv_sec, wait_time.tv_nsec);
	
	return(semaphore_wait_internal(wait_semaphore,
				       signal_semaphore,
					   deadline, option,
				       (void(*)(kern_return_t))0));
}

/*
 *	Trap:	semaphore_timedwait_signal_trap
 *
 *	Atomically register a timed wait on a semaphore and THEN signal
 *	another.  This is the trap version from user space.  
 */
kern_return_t
semaphore_timedwait_signal_trap(
	struct semaphore_timedwait_signal_trap_args *args)
{
	return(semaphore_timedwait_signal_trap_internal(args->wait_name, args->signal_name, args->sec, args->nsec, thread_syscall_return));
}

kern_return_t
semaphore_timedwait_signal_trap_internal(
	mach_port_name_t wait_name,
	mach_port_name_t signal_name,
	unsigned int sec,
	clock_res_t nsec,
	void (*caller_cont)(kern_return_t))
{
	semaphore_t wait_semaphore;
	semaphore_t signal_semaphore;
	mach_timespec_t wait_time;
	kern_return_t kr;

	wait_time.tv_sec = sec;
	wait_time.tv_nsec = nsec;
	if(BAD_MACH_TIMESPEC(&wait_time))
		return KERN_INVALID_VALUE;
	
	kr = port_name_to_semaphore(signal_name, &signal_semaphore);
	if (kr == KERN_SUCCESS) {
		kr = port_name_to_semaphore(wait_name, &wait_semaphore);
		if (kr == KERN_SUCCESS) {
			int				option = SEMAPHORE_OPTION_NONE;
			uint64_t		deadline = 0;

			if (sec == 0 && nsec == 0)
				option = SEMAPHORE_TIMEOUT_NOBLOCK;
			else
				deadline = semaphore_deadline(sec, nsec);

			kr = semaphore_wait_internal(wait_semaphore,
					signal_semaphore,
					deadline, option,
					caller_cont);
			semaphore_dereference(wait_semaphore);
		}
		semaphore_dereference(signal_semaphore);
	}
	return kr;
}


/*
 *	Routine:	semaphore_reference
 *
 *	Take out a reference on a semaphore.  This keeps the data structure
 *	in existence (but the semaphore may be deactivated).
 */
void
semaphore_reference(
	semaphore_t		semaphore)
{
	(void)hw_atomic_add(&semaphore->ref_count, 1);
}

/*
 *	Routine:	semaphore_dereference
 *
 *	Release a reference on a semaphore.  If this is the last reference,
 *	the semaphore data structure is deallocated.
 */
void
semaphore_dereference(
	semaphore_t		semaphore)
{
	int			ref_count;

	if (semaphore != NULL) {
		ref_count = hw_atomic_sub(&semaphore->ref_count, 1);

		if (ref_count == 1) {
			ipc_port_t port = semaphore->port;

			if (IP_VALID(port) && 
			    OSCompareAndSwapPtr(port, IP_NULL, &semaphore->port)) {
				/*
				 * We get to disassociate the port from the sema and
				 * drop the port's reference on the sema.
				 */
				ipc_port_dealloc_kernel(port);
				ref_count = hw_atomic_sub(&semaphore->ref_count, 1);
			}
		}
		if (ref_count == 0) {
			assert(wait_queue_empty(&semaphore->wait_queue));
			zfree(semaphore_zone, semaphore);
		}
	}
}
