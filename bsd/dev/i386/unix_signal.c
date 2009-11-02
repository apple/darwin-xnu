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
 * Copyright (c) 1992 NeXT, Inc.
 *
 * HISTORY
 * 13 May 1992 ? at NeXT
 *	Created.
 */

#include <mach/mach_types.h>
#include <mach/exception.h>

#include <kern/thread.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <mach/thread_act.h>	/* for thread_abort_safely */

#include <i386/psl.h>
#include <i386/seg.h>

#include <mach/i386/thread_status.h>

extern struct i386_saved_state *get_user_regs(thread_t);

extern boolean_t valid_user_segment_selectors(uint16_t cs,
					      uint16_t ss,
					      uint16_t ds,
					      uint16_t es,
					      uint16_t fs,
					      uint16_t gs);

/* Forward: */
extern boolean_t machine_exception(int, int, int, int *, int *);

/* Signal handler flavors supported */
/* These defns should match the Libc implmn */
#define UC_TRAD			1

/*
 * Send an interrupt to process.
 *
 * Stack is set up to allow sigcode stored
 * in u. to call routine, followed by chmk
 * to sigreturn routine below.  After sigreturn
 * resets the signal mask, the stack, the frame 
 * pointer, and the argument pointer, it returns
 * to the user specified pc, psl.
 */
void
sendsig(p, catcher, sig, mask, code)
 	struct proc *p;
	user_addr_t catcher;	/* sig_t */
	int sig, mask;
	u_long code;
{
	struct sigframe {
		int			retaddr;
		sig_t			catcher;
		int			sigstyle;
		int			sig;
		int			code;
		struct sigcontext *	scp;
	} frame, *fp;
	struct sigcontext		context, *scp;
	struct sigacts *ps = p->p_sigacts;
	int oonstack;
	thread_t thread = current_thread();
	struct uthread * ut;
	struct i386_saved_state * saved_state = get_user_regs(thread);
	sig_t trampact;
    
	ut = get_bsdthread_info(thread);
	oonstack = ps->ps_sigstk.ss_flags & SA_ONSTACK;
	if ((ps->ps_flags & SAS_ALTSTACK) && !oonstack &&
		(ps->ps_sigonstack & sigmask(sig))) {
			scp = ((struct sigcontext *)ps->ps_sigstk.ss_sp) - 1;
			ps->ps_sigstk.ss_flags |= SA_ONSTACK;
	} else
		scp = ((struct sigcontext *)saved_state->uesp) - 1;
	fp = ((struct sigframe *)scp) - 1;

	/* 
	 * Build the argument list for the signal handler.
	 */

	trampact = (sig_t)ps->ps_trampact[sig];
	/* Handler should call sigreturn to get out of it */
	frame.retaddr = 0xffffffff;	
	frame.catcher = CAST_DOWN(sig_t,catcher);	/* XXX LP64 */
	frame.sigstyle = UC_TRAD;
	frame.sig = sig;

	if (sig == SIGILL || sig == SIGFPE) {
		frame.code = code;
	} else
		frame.code = 0;
	frame.scp = scp;
	if (copyout((caddr_t)&frame, (user_addr_t)fp, sizeof (frame))) 
		goto bad;

	/*
	 * Build the signal context to be used by sigreturn.
	 */
	context.sc_onstack = oonstack;
	context.sc_mask = mask;
	context.sc_eax = saved_state->eax;
	context.sc_ebx = saved_state->ebx;
	context.sc_ecx = saved_state->ecx;
	context.sc_edx = saved_state->edx;
	context.sc_edi = saved_state->edi;
	context.sc_esi = saved_state->esi;
	context.sc_ebp = saved_state->ebp;
	context.sc_esp = saved_state->uesp;
	context.sc_ss = saved_state->ss;
	context.sc_eflags = saved_state->efl;
	context.sc_eip = saved_state->eip;
	context.sc_cs = saved_state->cs;
	if (saved_state->efl & EFL_VM) {
		context.sc_ds = saved_state->v86_segs.v86_ds;
		context.sc_es = saved_state->v86_segs.v86_es;
		context.sc_fs = saved_state->v86_segs.v86_fs;
		context.sc_gs = saved_state->v86_segs.v86_gs;

		saved_state->efl &= ~EFL_VM;
	} else {
		context.sc_ds = saved_state->ds;
		context.sc_es = saved_state->es;
		context.sc_fs = saved_state->fs;
		context.sc_gs = saved_state->gs;
	}
	if (copyout((caddr_t)&context, (user_addr_t)scp, sizeof (context))) 
		goto bad;

	saved_state->eip = (unsigned int)trampact;
	saved_state->cs = USER_CS;

	saved_state->uesp = (unsigned int)fp;
	saved_state->ss = USER_DS;

	saved_state->ds = USER_DS;
	saved_state->es = USER_DS;
	saved_state->fs = NULL_SEG;
	saved_state->gs = USER_CTHREAD;
	return;

bad:
	SIGACTION(p, SIGILL) = SIG_DFL;
	sig = sigmask(SIGILL);
	p->p_sigignore &= ~sig;
	p->p_sigcatch &= ~sig;
	ut->uu_sigmask &= ~sig;
	/* sendsig is called with signal lock held */
	psignal_lock(p, SIGILL, 0);
	return;
}

/*
 * System call to cleanup state after a signal
 * has been taken.  Reset signal mask and
 * stack state from context left by sendsig (above).
 * Return to previous pc and psl as specified by
 * context left by sendsig. Check carefully to
 * make sure that the user has not modified the
 * psl to gain improper priviledges or to cause
 * a machine fault.
 */
/* ARGSUSED */
int
sigreturn(
	struct proc *p,
	struct sigreturn_args *uap,
	__unused int *retval)
{
    struct sigcontext		context;
    thread_t			thread = current_thread();
	int error;
    struct i386_saved_state*	saved_state = (struct i386_saved_state*)
							get_user_regs(thread);	
	struct uthread * ut;


    
	if (saved_state == NULL) 
		return EINVAL;

    if ((error = copyin(CAST_USER_ADDR_T(uap->sigcntxp), (void *)&context, 
				sizeof (context)))) 
		return(error);

	/*
	 * Validate segment selectors.
	 * Bad values would result in kernel exception at context switch
	 * back to user mode. If other state is invalid an exception will
	 * occur in user context.
	 */
	if (!valid_user_segment_selectors(context.sc_cs,
					  context.sc_ss,
					  context.sc_ds,
					  context.sc_es,
					  context.sc_fs,
					  context.sc_gs)) {
		return EINVAL;
	}

	ut = (struct uthread *)get_bsdthread_info(thread);

	if (context.sc_onstack & 01)
		p->p_sigacts->ps_sigstk.ss_flags |= SA_ONSTACK;
	else
		p->p_sigacts->ps_sigstk.ss_flags &= ~SA_ONSTACK;

	ut->uu_sigmask = context.sc_mask &~ sigcantmask;
	if(ut->uu_siglist & ~ut->uu_sigmask)
		signal_setast(thread);

	saved_state->eax = context.sc_eax;
	saved_state->ebx = context.sc_ebx;
	saved_state->ecx = context.sc_ecx;
	saved_state->edx = context.sc_edx;
	saved_state->edi = context.sc_edi;
	saved_state->esi = context.sc_esi;
	saved_state->ebp = context.sc_ebp;
	saved_state->uesp = context.sc_esp;
	saved_state->ss = context.sc_ss;
	saved_state->efl = context.sc_eflags;
	saved_state->efl &= ~EFL_USERCLR;
	saved_state->efl |= EFL_USERSET;
	saved_state->eip = context.sc_eip;
	saved_state->cs = context.sc_cs;

	if (context.sc_eflags & EFL_VM) {
		saved_state->ds = NULL_SEG;
    		saved_state->es = NULL_SEG;
    		saved_state->fs = NULL_SEG;
    		saved_state->gs = NULL_SEG;
		saved_state->v86_segs.v86_ds = context.sc_ds;
		saved_state->v86_segs.v86_es = context.sc_es;
		saved_state->v86_segs.v86_fs = context.sc_fs;
		saved_state->v86_segs.v86_gs = context.sc_gs;

		saved_state->efl |= EFL_VM;
	}
	else {
		saved_state->ds = context.sc_ds;
		saved_state->es = context.sc_es;
		saved_state->fs = context.sc_fs;
		saved_state->gs = context.sc_gs;
	}

	return (EJUSTRETURN);
}

/*
 * machine_exception() performs MD translation
 * of a mach exception to a unix signal and code.
 */

boolean_t
machine_exception(
    int			exception,
    int			code,
    __unused int	subcode,
    int			*unix_signal,
    int			*unix_code
)
{

    switch(exception) {

    case EXC_BAD_INSTRUCTION:
	*unix_signal = SIGILL;
	*unix_code = code;
	break;

    case EXC_ARITHMETIC:
	*unix_signal = SIGFPE;
	*unix_code = code;
	break;

    default:
	return(FALSE);
    }
   
    return(TRUE);
}

#include <sys/systm.h>
#include <sys/sysent.h>

int __pthread_cset(struct sysent *);
void __pthread_creset(struct sysent *);

int
__pthread_cset(struct sysent *callp)
{
	unsigned int cancel_enable;
	thread_t thread;
	struct uthread * uthread; 

	thread = current_thread();
	uthread = get_bsdthread_info(thread);

	cancel_enable = callp->sy_cancel;
	if (cancel_enable == _SYSCALL_CANCEL_NONE) {
		uthread->uu_flag |= UT_NOTCANCELPT;
	} else {
		if((uthread->uu_flag & (UT_CANCELDISABLE | UT_CANCEL | UT_CANCELED)) == UT_CANCEL) {
			if (cancel_enable == _SYSCALL_CANCEL_PRE)
				return(EINTR);
			else
				thread_abort_safely(thread);
		}
	}   
	return(0);
}


void
__pthread_creset(struct sysent *callp)
{

	unsigned int cancel_enable;
	thread_t thread;
	struct uthread * uthread; 

	thread = current_thread();
	uthread = get_bsdthread_info(thread);
	
	cancel_enable = callp->sy_cancel;
	if (!cancel_enable) 
		uthread->uu_flag &= ~UT_NOTCANCELPT;

}

