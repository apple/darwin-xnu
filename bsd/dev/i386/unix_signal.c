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
#include <kern/thread_act.h>

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/user.h>

#include <i386/psl.h>

#include <mach/i386/thread_status.h>
#include <dev/i386/sel_inline.h>


/*
 * FIXME.. should be included from mach_kernel/i386/seg.h
 */

#define	USER_CS	0x17
#define	USER_DS	0x1f
#define USER_CTHREAD 0x27

#define	UDATA_SEL	USER_DS
#define	UCODE_SEL	USER_CS
#define UCTHREAD_SEL    USER_CTHREAD

#define	valid_user_code_selector(x)	(TRUE)
#define	valid_user_data_selector(x)	(TRUE)
#define	valid_user_stack_selector(x)	(TRUE)


#define	NULL_SEG	0

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
	sig_t catcher;
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
	thread_act_t th_act = current_act();
	struct uthread * ut;
	struct i386_saved_state * saved_state = (struct i386_saved_state *)
							get_user_regs(th_act);
	sig_t trampact;
    
	ut = get_bsdthread_info(th_act);
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

	trampact = ps->ps_trampact[sig];
	/* Handler should call sigreturn to get out of it */
	frame.retaddr = 0xffffffff;	
	frame.catcher = catcher;
	frame.sigstyle = UC_TRAD;
	frame.sig = sig;

	if (sig == SIGILL || sig == SIGFPE) {
		frame.code = code;
	} else
		frame.code = 0;
	frame.scp = scp;
	if (copyout((caddr_t)&frame, (caddr_t)fp, sizeof (frame))) 
		goto bad;

#if	PC_SUPPORT
	{
	PCcontext_t	context = threadPCContext(thread);
	
	if (context && context->running) {
		oonstack |= 02;
		context->running = FALSE;
	}
	}
#endif
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
	if (copyout((caddr_t)&context, (caddr_t)scp, sizeof (context))) 
		goto bad;

	saved_state->eip = (unsigned int)trampact;
	saved_state->cs = UCODE_SEL;

	saved_state->uesp = (unsigned int)fp;
	saved_state->ss = UDATA_SEL;

	saved_state->ds = UDATA_SEL;
	saved_state->es = UDATA_SEL;
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
struct sigreturn_args {
	struct sigcontext *sigcntxp;
};
/* ARGSUSED */
int
sigreturn(p, uap, retval)
	struct proc *p;
	struct sigreturn_args *uap;
	int *retval;
{
    struct sigcontext		context;
    thread_t			thread = current_thread();
    thread_act_t		th_act = current_act();
	int error;
    struct i386_saved_state*	saved_state = (struct i386_saved_state*)
							get_user_regs(th_act);	
	struct uthread * ut;


    
    if (saved_state == NULL) 
	return EINVAL;

    if (error = copyin((caddr_t)uap->sigcntxp, (caddr_t)&context, 
						sizeof (context))) 
					return(error);
	ut = (struct uthread *)get_bsdthread_info(th_act);

    if (context.sc_onstack & 01)
			p->p_sigacts->ps_sigstk.ss_flags |= SA_ONSTACK;
	else
		p->p_sigacts->ps_sigstk.ss_flags &= ~SA_ONSTACK;
	ut->uu_sigmask = context.sc_mask &~ sigcantmask;
	if(ut->uu_siglist & ~ut->uu_sigmask)
		signal_setast(current_act());
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

#if	PC_SUPPORT
    if (context.sc_onstack & 02) {
	PCcontext_t	context = threadPCContext(thread);
	
	if (context)
	    context->running = TRUE;
    }
#endif

	return (EJUSTRETURN);
}

/*
 * machine_exception() performs MD translation
 * of a mach exception to a unix signal and code.
 */

boolean_t
machine_exception(
    int		exception,
    int		code,
    int		subcode,
    int		*unix_signal,
    int		*unix_code
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
