/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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

#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/assert.h>
#include <mach/machine/thread_status.h>
#include <ppc/savearea.h>

#include <sys/kernel.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/ktrace.h>
#include <sys/kdebug.h>

extern void
unix_syscall(
	struct savearea *regs
);

extern struct savearea * 
find_user_regs(
	thread_act_t act);

extern enter_funnel_section(funnel_t *funnel_lock);
extern exit_funnel_section(funnel_t *funnel_lock);

/*
 * Function:	unix_syscall
 *
 * Inputs:	regs	- pointer to Process Control Block
 *
 * Outputs:	none
 */
void
unix_syscall(
	struct savearea	*regs
)
{
	thread_act_t		thread_act;
	struct uthread		*uthread;
	struct proc			*proc;
	struct sysent		*callp;
	int					error;
	unsigned short		code;
	boolean_t			flavor;
	int funnel_type;

	thread_act = current_act();
	uthread = get_bsdthread_info(thread_act);

	if (!(uthread->uu_flag & P_VFORK))
		proc = (struct proc *)get_bsdtask_info(current_task());
	else
		proc = current_proc();

	flavor = (regs->save_r0 == NULL)? 1: 0;

	uthread->uu_ar0 = (int *)regs;

	if (flavor)
		code = regs->save_r3;
	else
		code = regs->save_r0;

	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

#ifdef	DEBUG
	if (callp->sy_narg > 8)
		panic("unix_syscall: max arg count exceeded");
#endif

	if (callp->sy_narg != 0) {
		if ( !flavor) {
			uthread->uu_arg[0] = regs->save_r3;
			uthread->uu_arg[1] = regs->save_r4;
			uthread->uu_arg[2] = regs->save_r5;
			uthread->uu_arg[3] = regs->save_r6;
			uthread->uu_arg[4] = regs->save_r7;
			uthread->uu_arg[5] = regs->save_r8;
			uthread->uu_arg[6] = regs->save_r9;
			uthread->uu_arg[7] = regs->save_r10;
		} else {
			uthread->uu_arg[0] = regs->save_r4;
			uthread->uu_arg[1] = regs->save_r5;
			uthread->uu_arg[2] = regs->save_r6;
			uthread->uu_arg[3] = regs->save_r7;
			uthread->uu_arg[4] = regs->save_r8;
			uthread->uu_arg[5] = regs->save_r9;
			uthread->uu_arg[7] = regs->save_r10;
		}
	}

	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

	if (kdebug_enable && (code != 180)) {
		if (flavor)
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
				regs->save_r4, regs->save_r5, regs->save_r6, regs->save_r7, 0);
		else
			KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_START,
				regs->save_r3, regs->save_r4, regs->save_r5, regs->save_r6, 0);
	}

	funnel_type = (int)callp->sy_funnel;
	if(funnel_type == KERNEL_FUNNEL) 
		 enter_funnel_section(kernel_flock);
	else if (funnel_type == NETWORK_FUNNEL)
		 enter_funnel_section(network_flock);
	

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
		ktrsyscall(proc, code, callp->sy_narg, uthread->uu_arg, funnel_type);

	error = (*(callp->sy_call))(proc, (void *)uthread->uu_arg, &(uthread->uu_rval[0]));

	regs = find_user_regs(thread_act);

	if (error == ERESTART) {
		regs->save_srr0 -= 8;
	} else if (error != EJUSTRETURN) {
		if (error) {
			regs->save_r3 = error;
			/* set the "pc" to execute cerror routine */
			regs->save_srr0 -= 4;
		} else { /* (not error) */
			regs->save_r3 = uthread->uu_rval[0];
			regs->save_r4 = uthread->uu_rval[1];
		} 
	}
	/* else  (error == EJUSTRETURN) { nothing } */

	if (KTRPOINT(proc, KTR_SYSRET))
		ktrsysret(proc, code, error, uthread->uu_rval[0], funnel_type);

	if(funnel_type == KERNEL_FUNNEL) 
		 exit_funnel_section(kernel_flock);
	else if (funnel_type == NETWORK_FUNNEL)
		 exit_funnel_section(network_flock);

	if (kdebug_enable && (code != 180)) {
		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_EXCP_SC, code) | DBG_FUNC_END,
			error, uthread->uu_rval[0], uthread->uu_rval[1], 0, 0);
	}

	thread_exception_return();
	/* NOTREACHED */
}

unix_syscall_return(error)
{
	thread_act_t				thread_act;
	struct uthread				*uthread;
	struct proc					*proc;
	struct savearea				*regs;
	unsigned short				code;
	struct sysent				*callp;
	int funnel_type;

	thread_act = current_act();
	proc = current_proc();
	uthread = get_bsdthread_info(thread_act);

	regs = find_user_regs(thread_act);

	/*
	 * Get index into sysent table
	 */   
	if (error == ERESTART) {
		regs->save_srr0 -= 8;
	} else if (error != EJUSTRETURN) {
		if (error) {
			regs->save_r3 = error;
			/* set the "pc" to execute cerror routine */
			regs->save_srr0 -= 4;
		} else { /* (not error) */
			regs->save_r3 = uthread->uu_rval[0];
			regs->save_r4 = uthread->uu_rval[1];
		} 
	}
	/* else  (error == EJUSTRETURN) { nothing } */

	if (regs->save_r0 != NULL)
		code = regs->save_r0;
	else
		code = regs->save_r3;

	callp = (code >= nsysent) ? &sysent[63] : &sysent[code];

	funnel_type = (int)callp->sy_funnel;

	if (KTRPOINT(proc, KTR_SYSRET))
		ktrsysret(proc, code, error, uthread->uu_rval[0], funnel_type);

	if(funnel_type == KERNEL_FUNNEL) 
		 exit_funnel_section(kernel_flock);
	else if (funnel_type == NETWORK_FUNNEL)
		 exit_funnel_section(network_flock);

	if (kdebug_enable && (code != 180)) {
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
struct gettimeofday_args{
	struct timeval *tp;
	struct timezone *tzp;
};
/*  NOTE THIS implementation is for  ppc architectures only */
int
ppc_gettimeofday(p, uap, retval)
	struct proc *p;
	register struct gettimeofday_args *uap;
	register_t *retval;
{
	struct timeval atv;
	int error = 0;
	struct timezone ltz;
	//struct savearea *child_state;
	extern simple_lock_data_t tz_slock;

	if (uap->tp) {
		microtime(&atv);
		retval[0] = atv.tv_sec;
		retval[1] = atv.tv_usec;
	}
	
	if (uap->tzp) {
		usimple_lock(&tz_slock);
		ltz = tz;
		usimple_unlock(&tz_slock);
		error = copyout((caddr_t)&ltz, (caddr_t)uap->tzp,
		    sizeof (tz));
	}

	return(error);
}

