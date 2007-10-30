/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/assert.h>
#include <kern/clock.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <mach/machine/thread_status.h>
#include <mach/thread_act.h>
#include <ppc/savearea.h>

#include <sys/kernel.h>
#include <sys/vm.h>
#include <sys/proc_internal.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/kdebug.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/kauth.h>

#include <bsm/audit_kernel.h>

#if CONFIG_DTRACE
extern int32_t dtrace_systrace_syscall(struct proc *, void *, int *);
extern void dtrace_systrace_syscall_return(unsigned short, int, int *);
#endif

extern void
unix_syscall(struct savearea *regs);

extern struct savearea * 
find_user_regs(
	thread_t act);

extern lck_spin_t * tz_slock;
extern void throttle_lowpri_io(int *lowpri_window, mount_t v_mount);

/*
 * Function:	unix_syscall
 *
 * Inputs:	regs	- pointer to Process Control Block
 *
 * Outputs:	none
 */
void
unix_syscall(struct savearea	*regs)
{
	thread_t			thread_act;
	struct uthread		*uthread;
	struct proc			*proc;
	struct sysent		*callp;
	int					error;
	unsigned int		code;
	boolean_t			flavor;

	flavor = (((unsigned int)regs->save_r0) == 0)? 1: 0;

	if (flavor)
		code = regs->save_r3;
	else
		code = regs->save_r0;

	if (kdebug_enable && (code != 180)) {
		if (flavor)
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
				regs->save_r4, regs->save_r5, regs->save_r6, regs->save_r7, 0);
		else
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
				regs->save_r3, regs->save_r4, regs->save_r5, regs->save_r6, 0);
	}
	thread_act = current_thread();
	uthread = get_bsdthread_info(thread_act);

	if (!(uthread->uu_flag & UT_VFORK))
		proc = (struct proc *)get_bsdtask_info(current_task());
	else
		proc = current_proc();

	/* Make sure there is a process associated with this task */
	if (proc == NULL) {
		regs->save_r3 = (long long)EPERM;
		/* set the "pc" to execute cerror routine */
		regs->save_srr0 -= 4;
		task_terminate_internal(current_task());
		thread_exception_return();
		/* NOTREACHED */
	}

	/*
	 * Delayed binding of thread credential to process credential, if we
	 * are not running with an explicitly set thread credential.
	 */
	kauth_cred_uthread_update(uthread, proc);

	callp = (code >= NUM_SYSENT) ? &sysent[63] : &sysent[code];

	if (callp->sy_narg != 0) {
		void 		*regsp;
		sy_munge_t 	*mungerp;
		
		if (IS_64BIT_PROCESS(proc)) {
			/* XXX Turn 64 bit unsafe calls into nosys() */
			if (callp->sy_flags & UNSAFE_64BIT) {
				callp = &sysent[63];
				goto unsafe;
			}
			mungerp = callp->sy_arg_munge64;
		}
		else {
			mungerp = callp->sy_arg_munge32;
		}
		if ( !flavor) {
			regsp = (void *) &regs->save_r3;
		} else {
			/* indirect system call consumes an argument so only 7 are supported */
			if (callp->sy_narg > 7) {
				callp = &sysent[63];
				goto unsafe;
			}
			regsp = (void *) &regs->save_r4;
		}
		/* call syscall argument munger to copy in arguments (see xnu/bsd/dev/ppc/munge.s) */
		(*mungerp)(regsp, (void *) &uthread->uu_arg[0]);
	}

unsafe:
	
	uthread->uu_flag |= UT_NOTCANCELPT;

	uthread->uu_rval[0] = 0;

	/*
	 * r4 is volatile, if we set it to regs->save_r4 here the child
	 * will have parents r4 after execve
	 */
	uthread->uu_rval[1] = 0;

	error = 0;

	/*
	 * PPC runtime calls cerror after every unix system call, so
	 * assume no error and adjust the "pc" to skip this call.
	 * It will be set back to the cerror call if an error is detected.
	 */
	regs->save_srr0 += 4;

#ifdef JOE_DEBUG
	uthread->uu_iocount = 0;
	uthread->uu_vpindex = 0;
#endif
	AUDIT_SYSCALL_ENTER(code, proc, uthread);
	error = (*(callp->sy_call))(proc, (void *)uthread->uu_arg, &(uthread->uu_rval[0]));
	AUDIT_SYSCALL_EXIT(code, proc, uthread, error);
#if CONFIG_MACF
	mac_thread_userret(code, error, thread_act);
#endif


#ifdef JOE_DEBUG
	if (uthread->uu_iocount)
	        joe_debug("system call returned with uu_iocount != 0");
#endif
#if CONFIG_DTRACE
	uthread->t_dtrace_errno = error;
#endif /* CONFIG_DTRACE */

	regs = find_user_regs(thread_act);

	if (error == ERESTART) {
		regs->save_srr0 -= 8;
	} else if (error != EJUSTRETURN) {
		if (error) {
			regs->save_r3 = (long long)error;
			/* set the "pc" to execute cerror routine */
			regs->save_srr0 -= 4;
		} else { /* (not error) */
			switch (callp->sy_return_type) {
			case _SYSCALL_RET_INT_T:
				regs->save_r3 = uthread->uu_rval[0];
				regs->save_r4 = uthread->uu_rval[1];
				break;
			case _SYSCALL_RET_UINT_T:
				regs->save_r3 = ((u_int)uthread->uu_rval[0]);
				regs->save_r4 = ((u_int)uthread->uu_rval[1]);
				break;
			case _SYSCALL_RET_OFF_T:
				/* off_t returns 64 bits split across two registers for 32 bit */
				/* process and in one register for 64 bit process */
				if (IS_64BIT_PROCESS(proc)) {
					u_int64_t 	*retp = (u_int64_t *)&uthread->uu_rval[0];
					regs->save_r3 = *retp;
					regs->save_r4 = 0;
				}
				else {
					regs->save_r3 = uthread->uu_rval[0];
					regs->save_r4 = uthread->uu_rval[1];
				}
				break;
			case _SYSCALL_RET_ADDR_T:
			case _SYSCALL_RET_SIZE_T:
			case _SYSCALL_RET_SSIZE_T:
				/* the variable length return types (user_addr_t, user_ssize_t, 
				 * and user_size_t) are always the largest possible size in the 
				 * kernel (we use uu_rval[0] and [1] as one 64 bit value).
				 */
				{
					user_addr_t *retp = (user_addr_t *)&uthread->uu_rval[0];
					regs->save_r3 = *retp;
					regs->save_r4 = 0;
				}
				break;
			case _SYSCALL_RET_NONE:
				break;
			default:
				panic("unix_syscall: unknown return type");
				break;
			}
		} 
	}
	/* else  (error == EJUSTRETURN) { nothing } */


	uthread->uu_flag &= ~UT_NOTCANCELPT;

	/* panic if funnel is held */
	syscall_exit_funnelcheck();

	if (uthread->uu_lowpri_window && uthread->v_mount) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this system call
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		throttle_lowpri_io(&uthread->uu_lowpri_window,uthread->v_mount);
	}
	if (kdebug_enable && (code != 180)) {

	        if (callp->sy_return_type == _SYSCALL_RET_SSIZE_T)
		        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
					      error, uthread->uu_rval[1], 0, 0, 0);
		else
		        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
					      error, uthread->uu_rval[0], uthread->uu_rval[1], 0, 0);
	}

	thread_exception_return();
	/* NOTREACHED */
}

void
unix_syscall_return(int error)
{
	thread_t					thread_act;
	struct uthread				*uthread;
	struct proc					*proc;
	struct savearea				*regs;
	unsigned int				code;
	struct sysent				*callp;

	thread_act = current_thread();
	proc = current_proc();
	uthread = get_bsdthread_info(thread_act);

	regs = find_user_regs(thread_act);

	if (regs->save_r0 != 0)
		code = regs->save_r0;
	else
		code = regs->save_r3;

	callp = (code >= NUM_SYSENT) ? &sysent[63] : &sysent[code];

#if CONFIG_DTRACE
        if (callp->sy_call == dtrace_systrace_syscall)
                dtrace_systrace_syscall_return( code, error, uthread->uu_rval );
#endif /* CONFIG_DTRACE */

	/*
	 * Get index into sysent table
	 */   
	if (error == ERESTART) {
		regs->save_srr0 -= 8;
	} else if (error != EJUSTRETURN) {
		if (error) {
			regs->save_r3 = (long long)error;
			/* set the "pc" to execute cerror routine */
			regs->save_srr0 -= 4;
		} else { /* (not error) */
			switch (callp->sy_return_type) {
			case _SYSCALL_RET_INT_T:
				regs->save_r3 = uthread->uu_rval[0];
				regs->save_r4 = uthread->uu_rval[1];
				break;
			case _SYSCALL_RET_UINT_T:
				regs->save_r3 = ((u_int)uthread->uu_rval[0]);
				regs->save_r4 = ((u_int)uthread->uu_rval[1]);
				break;
			case _SYSCALL_RET_OFF_T:
				/* off_t returns 64 bits split across two registers for 32 bit */
				/* process and in one register for 64 bit process */
				if (IS_64BIT_PROCESS(proc)) {
					u_int64_t 	*retp = (u_int64_t *)&uthread->uu_rval[0];
					regs->save_r3 = *retp;
				}
				else {
					regs->save_r3 = uthread->uu_rval[0];
					regs->save_r4 = uthread->uu_rval[1];
				}
				break;
			case _SYSCALL_RET_ADDR_T:
			case _SYSCALL_RET_SIZE_T:
			case _SYSCALL_RET_SSIZE_T:
				/* the variable length return types (user_addr_t, user_ssize_t, 
				 * and user_size_t) are always the largest possible size in the 
				 * kernel (we use uu_rval[0] and [1] as one 64 bit value).
				 */
				{
					u_int64_t 	*retp = (u_int64_t *)&uthread->uu_rval[0];
					regs->save_r3 = *retp;
				}
				break;
			case _SYSCALL_RET_NONE:
				break;
			default:
				panic("unix_syscall: unknown return type");
				break;
			}
		} 
	}
	/* else  (error == EJUSTRETURN) { nothing } */


	uthread->uu_flag &= ~UT_NOTCANCELPT;

	/* panic if funnel is held */
	syscall_exit_funnelcheck();

	if (uthread->uu_lowpri_window && uthread->v_mount) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this system call
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		throttle_lowpri_io(&uthread->uu_lowpri_window,uthread->v_mount);
	}
	if (kdebug_enable && (code != 180)) {
	        if (callp->sy_return_type == _SYSCALL_RET_SSIZE_T)
		        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
					      error, uthread->uu_rval[1], 0, 0, 0);
		else
		        KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
					      error, uthread->uu_rval[0], uthread->uu_rval[1], 0, 0);
	}

	thread_exception_return();
	/* NOTREACHED */
}

#ifdef JOE_DEBUG
joe_debug(char *p) {

        printf("%s\n", p);
}
#endif
