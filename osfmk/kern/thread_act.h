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
#include <mach/rpc.h>
#include <mach/vm_param.h>
#include <mach/thread_info.h>
#include <mach/exception_types.h>


#ifdef MACH_KERNEL_PRIVATE
#include <mach_assert.h>
#include <thread_swapper.h>
#include <cputypes.h>

#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/etap_macros.h>
#include <kern/exception.h>
#include <kern/thread.h>
#include <kern/thread_pool.h>
#include <ipc/ipc_port.h>
#include <machine/thread_act.h>

/* Here is a description of the states an thread_activation may be in.
 *
 * An activation always has a valid task pointer, and it is always constant.
 * The activation is only linked onto the task's activation list until
 * the activation is terminated.
 *
 * An activation is in use or not, depending on whether its thread
 * pointer is nonzero.  If it is not in use, it is just sitting idly
 * waiting to be used by a thread.  The thread holds a reference on
 * the activation while using it.
 *
 * An activation lives on an thread_pool if its pool_port pointer is nonzero.
 * When in use, it can still live on an thread_pool, but it is not actually
 * linked onto the thread_pool's list of available activations.  In this case,
 * the act will return to its thread_pool as soon as it becomes unused.
 *
 * An activation is active until thread_terminate is called on it;
 * then it is inactive, waiting for all references to be dropped.
 * Future control operations on the terminated activation will fail,
 * with the exception that act_yank still works if the activation is
 * still on an RPC chain.  A terminated activation always has null
 * thread and pool_port pointers.
 *
 * An activation is suspended when suspend_count > 0.
 * A suspended activation can live on an thread_pool, but it is not
 * actually linked onto the thread_pool while suspended.
 *
 * Locking note:  access to data relevant to scheduling state (user_stop_count,
 * suspend_count, handlers, special_handler) is controlled by the combination
 * of locks acquired by act_lock_thread().  That is, not only must act_lock()
 * be held, but RPC through the activation must be frozen (so that the
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

	/*** thread_pool-related stuff ***/
	/* Port containing the thread_pool this activation normally lives
	 * on, zero if none.  The port (really the thread_pool) holds a
	 * reference to the activation as long as this is nonzero (even when
	 * the activation isn't actually on the thread_pool's list).
	 */
	struct ipc_port	*pool_port;

	/* Link on the thread_pool's list of activations.
	 * The activation is only actually on the thread_pool's list
	 * (and hence this is valid) when not in use (thread == 0) and
	 * not suspended (suspend_count == 0).
	 */
	struct thread_activation *thread_pool_next;

	/* RPC state */
        union {
                struct {
                        rpc_subsystem_t         r_subsystem;
#if 0 /* Grenoble */
                        mach_rpc_id_t           r_routine_num;
                        mach_rpc_signature_t    r_sig_ptr;
                        mach_rpc_size_t         r_sig_size;
#else
                        rpc_id_t           r_routine_num;
                        rpc_signature_t    r_sig_ptr;      /* Stored Client Sig Ptr */
                        rpc_size_t         r_sig_size;     /* Size of Sig stored */
			struct rpc_signature r_sigbuf;     /* Static Reservation of Sig Mem */
			routine_descriptor_t    r_sigbufp;      /* For dynamic storage of Sig */
			vm_size_t		r_sigbuf_size;  /* Size of buffer allocated for sig */
#endif
                        vm_offset_t             r_new_argv;
                        vm_offset_t            *r_arg_buf;
                        vm_offset_t             r_arg_buf_data[RPC_KBUF_SIZE];
                        rpc_copy_state_t        r_state;
                        rpc_copy_state_data_t   r_state_data[RPC_DESC_COUNT];
                        unsigned int            r_port_flags;
                        ipc_port_t              r_local_port;
                        void                   *r_kkt_args;
                } regular;
                struct {
                        ipc_port_t              r_port;
                        ipc_port_t              r_exc_port;
			int			r_exc_flavor;
			mach_msg_type_number_t	r_ostate_cnt;
			exception_data_type_t	r_code[EXCEPTION_CODE_MAX];
#if                     ETAP_EVENT_MONITOR
                        exception_type_t        r_exception;
#endif
                } exception;
        } rpc_state;

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

#if 0 /* Grenoble */
	/* Saved policy and priority of shuttle if changed to migrate into
	 * higher-priority or more real-time task.  Only valid if
	 * saved_sched_stamp is nonzero and equal to the sched_change_stamp
	 * in the thread_shuttle.  (Otherwise, the policy or priority has
	 * been explicitly changed in the meantime, and the saved values
	 * are invalid.)
	 */
	policy_t	saved_policy;
	integer_t	saved_base_priority;
	unsigned int	saved_sched_change_stamp;
#endif
	/*** Control information ***/

	/* Number of outstanding suspensions on this activation.  */
	int		suspend_count;

	/* User-visible scheduling state */
	int		user_stop_count;	/* outstanding stops */

	/* ast is needed - see ast.h */
	int		ast;

#if	THREAD_SWAPPER
	/* task swapper */
      	int		swap_state;	/* swap state (or unswappable flag)*/
	queue_chain_t	swap_queue;	/* links on swap queues */
#if	MACH_ASSERT
	boolean_t	kernel_stack_swapped_in;
					/* debug for thread swapping */
#endif	/* MACH_ASSERT */
#endif	/* THREAD_SWAPPER */

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

/* RPC state fields */
#define r_subsystem     rpc_state.regular.r_subsystem
#define r_routine_num   rpc_state.regular.r_routine_num
#define r_sig_ptr       rpc_state.regular.r_sig_ptr
#define r_sig_size      rpc_state.regular.r_sig_size
#define r_sigbuf	rpc_state.regular.r_sigbuf
#define r_sigbufp	rpc_state.regular.r_sigbufp
#define r_sigbuf_size   rpc_state.regular.r_sigbuf_size
#define r_new_argv      rpc_state.regular.r_new_argv
#define r_arg_buf       rpc_state.regular.r_arg_buf
#define r_arg_buf_data  rpc_state.regular.r_arg_buf_data
#define r_state         rpc_state.regular.r_state
#define r_state_data    rpc_state.regular.r_state_data
#define r_port_flags    rpc_state.regular.r_port_flags
#define r_local_port    rpc_state.regular.r_local_port
#define r_kkt_args      rpc_state.regular.r_kkt_args
#define r_port          rpc_state.exception.r_port
#define r_exc_port      rpc_state.exception.r_exc_port
#define r_exc_flavor	rpc_state.exception.r_exc_flavor
#define r_ostate_cnt	rpc_state.exception.r_ostate_cnt
#define r_code          rpc_state.exception.r_code
#define r_exception     rpc_state.exception.r_exception

/* Alert bits */
#define SERVER_TERMINATED		0x01
#define ORPHANED			0x02
#define CLIENT_TERMINATED		0x04
#define TIME_CONSTRAINT_UNSATISFIED	0x08

#if THREAD_SWAPPER
/*
 * Encapsulate the actions needed to ensure that next lower act on
 * RPC chain is swapped in.  Used at base spl; assumes rpc_lock()
 * of thread is held; if port is non-null, assumes its ip_lock()
 * is also held.
 */
#define act_switch_swapcheck(thread, port)			\
MACRO_BEGIN							\
	thread_act_t __act__ = thread->top_act;			\
								\
	while (__act__->lower) {				\
		thread_act_t __l__ = __act__->lower;		\
								\
		if (__l__->swap_state == TH_SW_IN ||		\
			__l__->swap_state == TH_SW_UNSWAPPABLE)	\
			break;					\
		/*						\
		 * XXX - Do we need to reference __l__?  	\
		 */						\
		if (port)					\
			ip_unlock(port);			\
		if (!thread_swapin_blocking(__l__))		\
			panic("act_switch_swapcheck: !active");	\
		if (port)					\
			ip_lock(port);				\
		if (__act__->lower == __l__)			\
			break;					\
	}							\
MACRO_END

#else	/* !THREAD_SWAPPER */

#define act_switch_swapcheck(thread, port)

#endif	/* !THREAD_SWAPPER */

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

#define 	sigbuf_dealloc(thr_act)		   			\
		if ((thr_act->r_sigbufp) && (thr_act->r_sigbuf_size >  	\
                                        sizeof(thr_act->r_sigbuf))) 	\
                {                                                 	\
                    kfree((vm_offset_t)thr_act->r_sigbufp,        	\
                            thr_act->r_sigbuf_size);               	\
                    thr_act->r_sigbuf_size = 0;                   	\
                }						

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


extern void		act_init(void);
extern kern_return_t	act_disable_task_locked(thread_act_t);
extern void		thread_release(thread_act_t);
extern kern_return_t	thread_dowait(thread_act_t, boolean_t);
extern void		thread_hold(thread_act_t);
extern void		nudge(thread_act_t);

extern kern_return_t	act_set_thread_pool(thread_act_t, ipc_port_t);
extern kern_return_t	act_locked_act_set_thread_pool(thread_act_t, ipc_port_t);
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

#define current_act_fast()	(current_thread()->top_act)
#define current_act_slow()	((current_thread()) ?		\
				 current_act_fast() :		\
				 THR_ACT_NULL)

#define current_act() current_act_slow()    /* JMM - til we find the culprit */

#else /* !MACH_KERNEL_PRIVATE */

extern thread_act_t	current_act(void);
extern void		act_reference(thread_act_t);
extern void		act_deallocate(thread_act_t);

#endif /* !MACH_KERNEL_PRIVATE */

/* Exported to world */
extern kern_return_t	act_alert(thread_act_t, unsigned);
extern kern_return_t	act_alert_mask(thread_act_t, unsigned );
extern kern_return_t	post_alert(thread_act_t, unsigned);

extern kern_return_t	thread_abort(thread_act_t);
extern kern_return_t	thread_abort_safely(thread_act_t);
extern kern_return_t	thread_resume(thread_act_t);
extern kern_return_t	thread_suspend(thread_act_t);
extern kern_return_t	thread_terminate(thread_act_t);

typedef void (thread_apc_handler_t)(thread_act_t);

extern kern_return_t	thread_apc_set(thread_act_t, thread_apc_handler_t);
extern kern_return_t	thread_apc_clear(thread_act_t, thread_apc_handler_t);

extern vm_map_t		swap_act_map(thread_act_t, vm_map_t);

extern void		*get_bsdthread_info(thread_act_t);
extern void		set_bsdthread_info(thread_act_t, void *);
extern task_t		get_threadtask(thread_act_t);

#endif /* _KERN_THREAD_ACT_H_ */
