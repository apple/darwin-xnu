/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_FREE_COPYRIGHT@
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
 *      File:   thread_act.h
 *
 *      thread activation definitions
 */
#ifndef	_KERN_THREAD_ACT_H_
#define _KERN_THREAD_ACT_H_

#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/thread_info.h>
#include <mach/exception_types.h>

#include <sys/appleapiopts.h>

#ifdef	__APPLE_API_PRIVATE

#ifdef	MACH_KERNEL_PRIVATE

#include <mach_assert.h>
#include <thread_swapper.h>
#include <cputypes.h>

#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/etap_macros.h>
#include <kern/exception.h>
#include <kern/thread.h>
#include <ipc/ipc_port.h>
#include <machine/thread_act.h>

/*
 * Here is a description of the states an thread_activation may be in.
 *
 * An activation always has a valid task pointer, and it is always constant.
 * The activation is only linked onto the task's activation list until
 * the activation is terminated.
 *
 * The thread holds a reference on the activation while using it.
 *
 * An activation is active until thread_terminate is called on it;
 * then it is inactive, waiting for all references to be dropped.
 * Future control operations on the terminated activation will fail,
 * with the exception that act_yank still works if the activation is
 * still on an RPC chain.  A terminated activation always has a null
 * thread pointer.
 *
 * An activation is suspended when suspend_count > 0.
 *
 * Locking note:  access to data relevant to scheduling state (user_stop_count,
 * suspend_count, handlers, special_handler) is controlled by the combination
 * of locks acquired by act_lock_thread().  That is, not only must act_lock()
 * be held, but migration through the activation must be frozen (so that the
 * thread pointer doesn't change).  If a shuttle is associated with the
 * activation, then its thread_lock() must also be acquired to change these
 * data.  Regardless of whether a shuttle is present, the data must be
 * altered at splsched().
 */

typedef struct ReturnHandler {
	struct ReturnHandler *next;
	void (*handler)(struct ReturnHandler *rh,
				struct thread_activation *thr_act);
} ReturnHandler;

typedef struct thread_activation {

	/*** task linkage ***/

	/* Links for task's circular list of activations.  The activation
	 * is only on the task's activation list while active.  Must be
	 * first.
	 */
	queue_chain_t	thr_acts;

	/* Indicators for whether this activation is in the midst of
	 * resuming or has already been resumed in a kernel-loaded
	 * task -- these flags are basically for quick access to
	 * this information.
	 */
	boolean_t	kernel_loaded;	/* running in kernel-loaded task */
	boolean_t	kernel_loading;	/* about to run kernel-loaded */

	boolean_t	inited;

	/*** Machine-dependent state ***/
	struct MachineThrAct	mact;

	/*** Consistency ***/
	decl_mutex_data(,lock)
	decl_simple_lock_data(,sched_lock)
	int		ref_count;

	/* Reference to the task this activation is in.
	 * Constant for the life of the activation
	 */
	struct task	*task;
	vm_map_t	map;		/* cached current map */

	/*** Thread linkage ***/
	/* Shuttle using this activation, zero if not in use.  The shuttle
	 * holds a reference on the activation while this is nonzero.
	 */
	struct thread_shuttle	*thread;

	/* The rest in this section is only valid when thread is nonzero.  */

	/* Next higher and next lower activation on the thread's activation
	 * stack.  For a topmost activation or the null_act, higher is
	 * undefined.  The bottommost activation is always the null_act.
	 */
	struct thread_activation *higher, *lower;

	/* Alert bits pending at this activation; some of them may have
	 * propagated from lower activations.
	 */
	unsigned	alerts;

	/* Mask of alert bits to be allowed to pass through from lower levels.
	 */
	unsigned	alert_mask;

	/*** Control information ***/

	/* Number of outstanding suspensions on this activation.  */
	int		suspend_count;

	/* User-visible scheduling state */
	int		user_stop_count;	/* outstanding stops */

	/* ast is needed - see ast.h */
	ast_t	ast;

	/* This is normally true, but is set to false when the
	 * activation is terminated.
	 */
	int		active;

	/* Chain of return handlers to be called before the thread is
	 * allowed to return to this invocation
	 */
	ReturnHandler	*handlers;

	/* A special ReturnHandler attached to the above chain to
	 * handle suspension and such
	 */
	ReturnHandler	special_handler;

	/* Special ports attached to this activation */
	struct ipc_port *ith_self;	/* not a right, doesn't hold ref */
	struct ipc_port *ith_sself;	/* a send right */
	struct exception_action exc_actions[EXC_TYPES_COUNT];

	/* A list of ulocks (a lock set element) currently held by the thread
	 */
	queue_head_t	held_ulocks;

#if	MACH_PROF
	/* Profiling data structures */
	boolean_t	act_profiled;	/* is activation being profiled? */
	boolean_t	act_profiled_own;
					/* is activation being profiled 
					 * on its own ? */
	struct prof_data *profil_buffer;/* prof struct if either is so */
#endif	/* MACH_PROF */

#ifdef  MACH_BSD
	void    *uthread;
#endif

} Thread_Activation;

/* Alert bits */
#define SERVER_TERMINATED		0x01
#define ORPHANED			0x02
#define CLIENT_TERMINATED		0x04
#define TIME_CONSTRAINT_UNSATISFIED	0x08

#define	act_lock_init(thr_act)	mutex_init(&(thr_act)->lock, ETAP_THREAD_ACT)
#define	act_lock(thr_act)	mutex_lock(&(thr_act)->lock)
#define	act_lock_try(thr_act)	mutex_try(&(thr_act)->lock)
#define	act_unlock(thr_act)	mutex_unlock(&(thr_act)->lock)

/* Sanity check the ref count.  If it is 0, we may be doubly zfreeing.
 * If it is larger than max int, it has been corrupted, probably by being
 * modified into an address (this is architecture dependent, but it's
 * safe to assume there cannot really be max int references).
 */
#define ACT_MAX_REFERENCES					\
	(unsigned)(~0 ^ (1 << (sizeof(int)*BYTE_SIZE - 1)))

#define		act_reference_fast(thr_act)			\
		MACRO_BEGIN					\
		    if (thr_act) {				\
			act_lock(thr_act);			\
			assert((thr_act)->ref_count < ACT_MAX_REFERENCES); \
			(thr_act)->ref_count++;			\
			act_unlock(thr_act);			\
		    }						\
		MACRO_END

#define		act_reference(thr_act) act_reference_fast(thr_act)

#define		act_locked_act_reference(thr_act)		\
		MACRO_BEGIN					\
		    if (thr_act) {				\
			assert((thr_act)->ref_count < ACT_MAX_REFERENCES); \
			(thr_act)->ref_count++;			\
		    }						\
		MACRO_END

#define		act_deallocate_fast(thr_act)			\
		MACRO_BEGIN					\
		    if (thr_act) {				\
			int new_value;				\
			act_lock(thr_act);			\
			assert((thr_act)->ref_count > 0 &&	\
			    (thr_act)->ref_count <= ACT_MAX_REFERENCES); \
			new_value = --(thr_act)->ref_count;	\
			act_unlock(thr_act);			\
			if (new_value == 0) 			\
			    act_free(thr_act); 			\
		    }						\
		MACRO_END

#define		act_deallocate(thr_act) act_deallocate_fast(thr_act)

#define		act_locked_act_deallocate(thr_act)		\
		MACRO_BEGIN					\
		    if (thr_act) {				\
			int new_value;				\
			assert((thr_act)->ref_count > 0 &&	\
			    (thr_act)->ref_count <= ACT_MAX_REFERENCES); \
			new_value = --(thr_act)->ref_count;	\
			if (new_value == 0) { 			\
			    panic("a_l_act_deallocate: would free act"); \
			}					\
		    }						\
		MACRO_END

extern	struct thread_activation	pageout_act;

extern void		act_init(void);
extern void		thread_release(thread_act_t);
extern kern_return_t	thread_dowait(thread_act_t, boolean_t);
extern void		thread_hold(thread_act_t);

extern kern_return_t	thread_get_special_port(thread_act_t, int,
					ipc_port_t *);
extern kern_return_t	thread_set_special_port(thread_act_t, int,
					ipc_port_t);
extern thread_t		act_lock_thread(thread_act_t);
extern void		act_unlock_thread(thread_act_t);
extern void		install_special_handler(thread_act_t);
extern thread_act_t	thread_lock_act(thread_t);
extern void		thread_unlock_act(thread_t);
extern void		act_attach(thread_act_t, thread_t, unsigned);
extern void		act_execute_returnhandlers(void);
extern void		act_detach(thread_act_t);
extern void		act_free(thread_act_t);

/* machine-dependent functions */
extern void		act_machine_return(kern_return_t);
extern void		act_machine_init(void);
extern kern_return_t	act_machine_create(struct task *, thread_act_t);
extern void		act_machine_destroy(thread_act_t);
extern kern_return_t	act_machine_set_state(thread_act_t,
					thread_flavor_t, thread_state_t,
					mach_msg_type_number_t );
extern kern_return_t	act_machine_get_state(thread_act_t,
					thread_flavor_t, thread_state_t,
					mach_msg_type_number_t *);
extern void		act_machine_switch_pcb(thread_act_t);
extern void		act_virtual_machine_destroy(thread_act_t);

extern kern_return_t	act_create(task_t, thread_act_t *);
extern kern_return_t	act_get_state(thread_act_t, int, thread_state_t,
				mach_msg_type_number_t *);
extern kern_return_t	act_set_state(thread_act_t, int, thread_state_t,
				mach_msg_type_number_t);

extern int		dump_act(thread_act_t);	/* debugging */

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

#else	/* MACH_KERNEL_PRIVATE */

extern void		act_reference(thread_act_t);
extern void		act_deallocate(thread_act_t);

#endif	/* MACH_KERNEL_PRIVATE */

extern kern_return_t	act_alert(thread_act_t, unsigned);
extern kern_return_t	act_alert_mask(thread_act_t, unsigned );
extern kern_return_t	post_alert(thread_act_t, unsigned);

typedef void	(thread_apc_handler_t)(thread_act_t);

extern kern_return_t	thread_apc_set(thread_act_t, thread_apc_handler_t);
extern kern_return_t	thread_apc_clear(thread_act_t, thread_apc_handler_t);

extern vm_map_t			swap_act_map(thread_act_t, vm_map_t);

extern void		*get_bsdthread_info(thread_act_t);
extern void		set_bsdthread_info(thread_act_t, void *);
extern task_t	get_threadtask(thread_act_t);

#endif	/* __APPLE_API_PRIVATE */

#ifdef	__APPLE_API_UNSTABLE

#if		!defined(MACH_KERNEL_PRIVATE)

extern thread_act_t	current_act(void);

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* __APPLE_API_UNSTABLE */

extern kern_return_t	thread_abort(thread_act_t);
extern kern_return_t	thread_abort_safely(thread_act_t);
extern kern_return_t	thread_resume(thread_act_t);
extern kern_return_t	thread_suspend(thread_act_t);
extern kern_return_t	thread_terminate(thread_act_t);

#endif /* _KERN_THREAD_ACT_H_ */
