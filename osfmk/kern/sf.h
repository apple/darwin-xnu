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

#ifndef	_KERN_SF_H_
#define _KERN_SF_H_

/*
 * The calls most likely to change are: policy_thread_done and
 * policy_thread_begin.  They're the policy calls related to 
 * context switching. I'm not satisfied with what I have now and
 * these are the forms I'm trying next.
 * 
 * I still have to merge the data type names from my different sandboxes
 * and I don't really talk about locking except for the run queue locking.
 * 
 * There is a big change for run queues: there is a single lock for an
 * entire run queue array structure (instead of a lock per queue header).
 * It's OK for a policy to reorganize a particular queue BUT it has to
 * disable the queue header (sched_queue_disable).  Since a queue header
 * isn't shared by multiple policies and the framework won't touch the
 * queue header if it's disabled, the policy can do anything it wants
 * without taking out a global lock.
 * 
 * The only run queue primitives provided are the really fast ones:
 * insert at the head (sched_queue_preempt), insert at the tail
 * and if the queue was empty check for preemption 
 * (sched_queue_add_preempt), just insert at the tail
 * (sched_queue_add_only), and remove (sched_queue_remove).  Everything
 * else needs to be done by first disabling the queue header (and then
 * you can do whatever you want to the queue).
 * 
 * BTW, the convention here is:
 * 
 *    policy_xxx - calls from the framework into policies (via the
 * 	pointers in the policy object)
 * 
 *    sched_xxx - scheduling mechanisms provided by the framework
 *         which can be called by policies.
 * 
 * ----------
 * 
 * Initializes an instance of a scheduling policy assigning it the
 * corresponding policy_id and run queue headers.
 * 
 * policy_init(
 *     sched_policy_object	 *policy,
 *     int policy_id,
 * 	   int minpri, maxpri);
 * 
 * Enable/disable a scheduling policy on a processor [set]
 * 
 * policy_enable_processor_set(
 *     sched_policy_object *policy,			/ * policy * /
 *     processor_set_t processor_set );		/ * processor set * /
 * 
 * policy_disable_processor_set(
 *     sched_policy_object *policy,
 *     processor_set_t processor_set);
 * 
 * policy_enable_processor(
 *     sched_policy_object *policy,
 *     processor_t processor );
 * 
 * policy_disable_processor(
 *     sched_policy_object *policy,
 *     processor_t processor);
 * 
 * Notifies the policy that the thread has become runnable
 * 
 * policy_thread_unblock(
 *     sched_policy_object *policy,
 *     thread_t thread )
 * 
 * Notifies the policy that the current thread is done or
 * a new thread has been selected to run
 * 
 * policy_thread_done(
 *     sched_policy_object *policy,
 *     thread_t *old_thread );
 * 
 * policy_thread_begin(
 *     sched_policy_object *policy,
 *     thread_t *new_thread );
 * 
 * Attach/detach a thread from the scheduling policy
 * 
 * policy_thread_attach(
 *     sched_policy_object *policy,
 *     thread_t *thread );
 * 
 * policy_thread_detach(
 *     sched_policy_object *policy,
 *     thread_t *thread );
 * 
 * Set the thread's processor [set]
 * 
 * policy_thread_processor(
 *     sched_policy_object *policy,
 *     thread_t *thread,
 *     processor_t processor );
 * 
 * policy_thread_processor_set(
 *     sched_policy_object *policy,
 *     thread_t *thread,
 *     processor_set_t processor_set);
 * 
 * Scheduling Framework Interfaces
 * 
 * [en/dis]able particular run queue headers on a processor [set],
 * 
 * Lock the run queues, update the mask, unlock the run queues.  If
 * enabling, check preemption.
 * 
 * sched_queue_enable(
 *     run_queue_t		runq,
 *     sched_priority_mask *mask );
 * 
 * sched_queue_disable(
 *     run_queue_t		runq,
 *     sched_priority_mask *mask );
 * 
 * Lock the run queues, insert the thread at the head, unlock the
 * run queues and preempt (if possible).
 * 
 * sched_queue_preempt(
 *     integer_t		priority,
 *     thread_t			thread,
 *     run_queue_t		run_queues );
 * 
 * Lock the run queues, add the thread to the tail, unlock the run queues
 * and preempt if appropriate.
 * 
 * sched_queue_add_preempt(
 *     integer_t		priority,
 *     thread_t			thread,
 *     run_queue_t		run_queues );
 * 
 * Lock the run queues, add the thread to the tail, unlock the queues
 * but don't check for preemption.
 * 
 * sched_queue_add_only(
 *     integer_t		priority,
 *     thread_t			thread,
 *     run_queue_t		run_queues );
 * 
 * Lock the run queues, remove the entry the thread, unlock the run queues.
 * 
 * sched_queue_remove(
 *     thread_t			thread );
 */

#include <kern/kern_types.h>
#include <kern/sched.h>
#include <mach/thread_switch.h>
#include <mach/mach_types.h>

/*
 * Type definitions and constants for MK Scheduling Framework
 */
typedef int	sf_return_t;

/* successful completion */
#define SF_SUCCESS					0

/* error codes */
#define SF_FAILURE					1
#define SF_KERN_RESOURCE_SHORTAGE	2

/* Scheduler Framework Object -- i.e., a scheduling policy */
typedef struct sf_policy	*sf_object_t;

/*
 * maximum number of scheduling policies that the Scheduling Framework
 * will host (picked arbitrarily)
 */
#define MAX_SCHED_POLS	10

/**********
 *
 * Scheduling Framework Interfaces
 *
 **********/

/* Initialize Framework and selected policies */
void		sf_init(void);

/**********
 *
 * Scheduling Policy Interfaces
 *
 **********/

/*
 * Operation list for scheduling policies.  (Modeled after the
 * device operations `.../mach_kernel/device/conf.h.')
 *
 * Key to some abbreviations:
 *     sp = scheduling policy
 *     sf = scheduling framework
 */
typedef struct sched_policy_ops {
    /* Allow the policy to update the meta-priority of a running thread */
    sf_return_t	(*sp_thread_update_mpri)(
		sf_object_t			policy,
		thread_t			thread);

    /* Notify the policy that a thread has become runnable */
    sf_return_t	(*sp_thread_unblock)(
		sf_object_t			policy,
		thread_t			thread);

    /* Notify the policy that the current thread is done */
    /*** ??? Should this call take a `reason' argument? ***/
    sf_return_t	(*sp_thread_done)(
		sf_object_t			policy,
		thread_t			old_thread);

    /* Notify the policy that a new thread has been selected to run */
    sf_return_t	(*sp_thread_begin)(
		sf_object_t			policy,
		thread_t			new_thread);

    /* Notify the policy that an old thread is ready to be requeued */
    sf_return_t	(*sp_thread_dispatch)(
		sf_object_t			policy,
		thread_t			old_thread);

    /* Attach/detach a thread from the scheduling policy */
    sf_return_t	(*sp_thread_attach)(
		sf_object_t			policy,
		thread_t			thread);

    sf_return_t	(*sp_thread_detach)(
		sf_object_t			policy,
		thread_t			thread);

    /* Set the thread's processor [set] */
    sf_return_t	(*sp_thread_processor)(
		sf_object_t			policy,
		thread_t			*thread,
		processor_t			processor);

    sf_return_t	(*sp_thread_processor_set)(
		sf_object_t			policy,
		thread_t			thread,
		processor_set_t		processor_set);

    sf_return_t	(*sp_thread_setup)(
		sf_object_t			policy,
		thread_t			thread);

    /***
     *** ??? Hopefully, many of the following operations are only
     *** temporary.  Consequently, they haven't been forced to take
     *** the same form as the others just yet.  That should happen
     *** for all of those that end up being permanent additions to the
     *** list of standard operations.
     ***/

    /* `swtch_pri()' routine -- attempt to give up processor */
    void (*sp_swtch_pri)(
		sf_object_t			policy,
		int					pri);

    /* `thread_switch()' routine -- context switch w/ optional hint */
    kern_return_t (*sp_thread_switch)(
		sf_object_t			policy,
		thread_act_t		hint_act,
		int					option,
		mach_msg_timeout_t	option_time);

    /* `thread_depress_abort()' routine -- prematurely abort depression */
    kern_return_t (*sp_thread_depress_abort)(
		sf_object_t			policy,
		thread_t			thread);

    /* `thread_depress_timeout()' routine -- timeout on depression */
    void	(*sp_thread_depress_timeout)(
		sf_object_t			policy,
		thread_t			thread);

    boolean_t (*sp_thread_runnable)(
		sf_object_t			policy,
		thread_t			thread);

} sp_ops_t;

/**********
 *
 * Scheduling Policy
 *
 **********/

typedef struct sf_policy {
	int					policy_id;		/* policy number */
	sp_ops_t			sp_ops;
} sched_policy_t;

#define SCHED_POLICY_NULL	((sched_policy_t *) 0)

#define policy_id_to_sched_policy(policy_id)		\
	(((policy_id) != POLICY_NULL)?					\
			&sched_policy[(policy_id)] : SCHED_POLICY_NULL)

extern sched_policy_t	sched_policy[MAX_SCHED_POLS];

#endif	/* _KERN_SF_H_ */
