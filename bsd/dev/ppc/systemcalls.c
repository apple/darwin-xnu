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

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/assert.h>
#include <kern/clock.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <mach/machine/thread_status.h>
#include <ppc/savearea.h>

#include <sys/kernel.h>
#include <sys/vm.h>
#include <sys/proc_internal.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/ktrace.h>
#include <sys/kdebug.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>
#include <sys/kauth.h>

#include <bsm/audit_kernel.h>

extern void
unix_syscall(struct savearea *regs);
void
unix_syscall_return(int error);

extern struct savearea * 
find_user_regs(
	thread_t act);

extern void enter_funnel_section(funnel_t *funnel_lock);
extern void exit_funnel_section(void);

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
	int funnel_type;
	unsigned int cancel_enable;

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
	if (uthread->uu_ucred != proc->p_ucred &&
	    (uthread->uu_flag & UT_SETUID) == 0) {
		kauth_cred_t old = uthread->uu_ucred;
		proc_lock(proc);
		uthread->uu_ucred = proc->p_ucred;
		kauth_cred_ref(uthread->uu_ucred);
		proc_unlock(proc);
		if (old != NOCRED)
			kauth_cred_rele(old);
	}

	uthread->uu_ar0 = (int *)regs;

	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

	if (callp->sy_narg != 0) {
		void 		*regsp;
		sy_munge_t 	*mungerp;
		
		if (IS_64BIT_PROCESS(proc)) {
			/* XXX Turn 64 bit unsafe calls into nosys() */
			if (callp->sy_funnel & UNSAFE_64BIT) {
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
	cancel_enable = callp->sy_cancel;
	
	if (cancel_enable == _SYSCALL_CANCEL_NONE) {
			uthread->uu_flag |= UT_NOTCANCELPT;
	} else {
		if((uthread->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
			if (cancel_enable == _SYSCALL_CANCEL_PRE) {
					/* system call cancelled; return to handle cancellation */
					regs->save_r3 = (long long)EINTR;
					thread_exception_return();
					/* NOTREACHED */
 			} else {
                        thread_abort_safely(thread_act);
			}
		}
	}

	funnel_type = (int)(callp->sy_funnel & FUNNEL_MASK);
	if (funnel_type == KERNEL_FUNNEL) 
		 enter_funnel_section(kernel_flock);
	
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

	if (KTRPOINT(proc, KTR_SYSCALL))
		ktrsyscall(proc, code, callp->sy_narg, uthread->uu_arg);

#ifdef JOE_DEBUG
	uthread->uu_iocount = 0;
	uthread->uu_vpindex = 0;
#endif
	AUDIT_SYSCALL_ENTER(code, proc, uthread);
	error = (*(callp->sy_call))(proc, (void *)uthread->uu_arg, &(uthread->uu_rval[0]));
	AUDIT_SYSCALL_EXIT(error, proc, uthread);

#ifdef JOE_DEBUG
	if (uthread->uu_iocount)
	        joe_debug("system call returned with uu_iocount != 0");
#endif
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


	if (KTRPOINT(proc, KTR_SYSRET)) {
		switch(callp->sy_return_type) {
		case _SYSCALL_RET_ADDR_T:
		case _SYSCALL_RET_SIZE_T:
		case _SYSCALL_RET_SSIZE_T:
			/*
			 * Trace the value of the least significant bits,
			 * until we can revise the ktrace API safely.
			 */
			ktrsysret(proc, code, error, uthread->uu_rval[1]);
			break;
		default:
			ktrsysret(proc, code, error, uthread->uu_rval[0]);
			break;
		}
	}

	if (cancel_enable == _SYSCALL_CANCEL_NONE)
                uthread->uu_flag &= ~UT_NOTCANCELPT;

	exit_funnel_section();

	if (uthread->uu_lowpri_delay) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this system call
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		IOSleep(uthread->uu_lowpri_delay);
	        uthread->uu_lowpri_delay = 0;
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
	int funnel_type;
	unsigned int cancel_enable;

	thread_act = current_thread();
	proc = current_proc();
	uthread = get_bsdthread_info(thread_act);

	regs = find_user_regs(thread_act);

	if (regs->save_r0 != 0)
		code = regs->save_r0;
	else
		code = regs->save_r3;

	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

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

	if (KTRPOINT(proc, KTR_SYSRET)) {
		switch(callp->sy_return_type) {
		case _SYSCALL_RET_ADDR_T:
		case _SYSCALL_RET_SIZE_T:
		case _SYSCALL_RET_SSIZE_T:
			/*
			 * Trace the value of the least significant bits,
			 * until we can revise the ktrace API safely.
			 */
			ktrsysret(proc, code, error, uthread->uu_rval[1]);
			break;
		default:
			ktrsysret(proc, code, error, uthread->uu_rval[0]);
			break;
		}
	}

	cancel_enable = callp->sy_cancel;

	if (cancel_enable == _SYSCALL_CANCEL_NONE)
                uthread->uu_flag &= ~UT_NOTCANCELPT;

	exit_funnel_section();

	if (uthread->uu_lowpri_delay) {
	        /*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in this system call
		 * collided with normal I/O operations... we'll
		 * delay in order to mitigate the impact of this
		 * task on the normal operation of the system
		 */
		IOSleep(uthread->uu_lowpri_delay);
	        uthread->uu_lowpri_delay = 0;
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

/* 
 * Time of day and interval timer support.
 *
 * These routines provide the kernel entry points to get and set
 * the time-of-day and per-process interval timers.  Subroutines
 * here provide support for adding and subtracting timeval structures
 * and decrementing interval timers, optionally reloading the interval
 * timers when they expire.
 */
/*  NOTE THIS implementation is for  ppc architectures only.
 *  It is infrequently called, since the commpage intercepts
 *  most calls in user mode.
 *
 * XXX Y2038 bug because of assumed return of 32 bit seconds value, and
 * XXX first parameter to clock_gettimeofday()
 */
int
ppc_gettimeofday(__unused struct proc *p, 
				 register struct ppc_gettimeofday_args *uap, 
				 register_t *retval)
{
	int error = 0;
	extern lck_spin_t * tz_slock;

	if (uap->tp)
		clock_gettimeofday(&retval[0], &retval[1]);
	
	if (uap->tzp) {
		struct timezone ltz;

		lck_spin_lock(tz_slock);
		ltz = tz;
		lck_spin_unlock(tz_slock);
		error = copyout((caddr_t)&ltz, uap->tzp, sizeof (tz));
	}

	return (error);
}

#ifdef JOE_DEBUG
joe_debug(char *p) {

        printf("%s\n", p);
}
#endif


/* 
 * WARNING - this is a temporary workaround for binary compatibility issues
 * with anti-piracy software that relies on patching ptrace (3928003).
 * This KPI will be removed in the system release after Tiger.
 */
uintptr_t temp_patch_ptrace(uintptr_t new_ptrace)
{
	struct sysent *		callp;
	sy_call_t *			old_ptrace;

	if (new_ptrace == 0)
		return(0);
		
	enter_funnel_section(kernel_flock);
	callp = &sysent[26];
	old_ptrace = callp->sy_call;
	
	/* only allow one patcher of ptrace */
	if (old_ptrace == (sy_call_t *) ptrace) {
		callp->sy_call = (sy_call_t *) new_ptrace;
	}
	else {
		old_ptrace = NULL;
	}
	exit_funnel_section( );
	
	return((uintptr_t)old_ptrace);
}

void temp_unpatch_ptrace(void)
{
	struct sysent *		callp;
		
	enter_funnel_section(kernel_flock);
	callp = &sysent[26];
	callp->sy_call = (sy_call_t *) ptrace;
	exit_funnel_section( );
	
	return;
}
