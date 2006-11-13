/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <mach/thread_act.h>	/* for thread_abort_safely */
#include <mach/thread_status.h>	
#include <i386/machine_routines.h>

#include <i386/eflags.h>
#include <i386/psl.h>
#include <i386/seg.h>

#include <sys/kdebug.h>

/* Forward: */
extern boolean_t machine_exception(int, int, int, int *, int *);
extern kern_return_t thread_getstatus(register thread_t act, int flavor,
			thread_state_t tstate, mach_msg_type_number_t *count);
extern kern_return_t thread_setstatus(thread_t thread, int flavor,
			thread_state_t tstate, mach_msg_type_number_t count);

/* Signal handler flavors supported */
/* These defns should match the Libc implmn */
#define UC_TRAD			1
#define UC_FLAVOR		30

#define	C_32_STK_ALIGN		16
#define	C_64_STK_ALIGN		16
#define	C_64_REDZONE_LEN	128
#define TRUNC_DOWN32(a,c)	((((uint32_t)a)-(c)) & ((uint32_t)(-(c))))
#define TRUNC_DOWN64(a,c)	((((uint64_t)a)-(c)) & ((uint64_t)(-(c))))

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
struct sigframe32 {
        int		  retaddr;
	sig_t		  catcher;
	int		  sigstyle;
	int		  sig;
	siginfo_t	* sinfo;
	struct ucontext * uctx;
};



void
sendsig(struct proc *p, user_addr_t ua_catcher, int sig, int mask, __unused u_long code)
{
        union {
	    struct mcontext32	mctx32;
	    struct mcontext64	mctx64;
	} mctx;
	user_addr_t	ua_sp;
	user_addr_t	ua_fp;
	user_addr_t	ua_cr2;
	user_addr_t	ua_sip;
	user_addr_t 	ua_uctxp;
	user_addr_t	ua_mctxp;
	user_siginfo_t	sinfo64;

	struct sigacts *ps = p->p_sigacts;
	int oonstack, flavor; 
	void * state;
	mach_msg_type_number_t state_count;
	int uthsigaltstack = 0;
	int altstack = 0;

	thread_t thread = current_thread();
	struct uthread * ut;
	int stack_size = 0;
	int infostyle = UC_TRAD;
    
	if (p->p_sigacts->ps_siginfo & sigmask(sig))
		infostyle = UC_FLAVOR;

	ut = get_bsdthread_info(thread);

	uthsigaltstack = p->p_lflag & P_LTHSIGSTACK;

	if (uthsigaltstack != 0 )  {
		oonstack = ut->uu_sigstk.ss_flags & SA_ONSTACK;
		altstack = ut->uu_flag & UT_ALTSTACK;
	} else {
		oonstack = ps->ps_sigstk.ss_flags & SA_ONSTACK;
		altstack = ps->ps_flags & SAS_ALTSTACK;
	}
	/*
	 * init siginfo
	 */
	bzero((caddr_t)&sinfo64, sizeof(user_siginfo_t));
	sinfo64.si_signo = sig;
		
	if (proc_is64bit(p)) {
	        x86_thread_state64_t	*tstate64;
	        struct user_ucontext64 	uctx64;

	        flavor = x86_THREAD_STATE64;
		state_count = x86_THREAD_STATE64_COUNT;
		state = (void *)&mctx.mctx64.ss;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS)
		        goto bad;

		flavor = x86_FLOAT_STATE64;
		state_count = x86_FLOAT_STATE64_COUNT;
		state = (void *)&mctx.mctx64.fs;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS)
		        goto bad;

		flavor = x86_EXCEPTION_STATE64;
		state_count = x86_EXCEPTION_STATE64_COUNT;
		state = (void *)&mctx.mctx64.es;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS)
		        goto bad;

		tstate64 = &mctx.mctx64.ss;

		if (altstack && !oonstack && (ps->ps_sigonstack & sigmask(sig))) {
		        if (uthsigaltstack != 0) {
			        ua_sp = ut->uu_sigstk.ss_sp;
				stack_size = ut->uu_sigstk.ss_size;
				ua_sp += stack_size;
				ut->uu_sigstk.ss_flags |= SA_ONSTACK;
			} else {
			        ua_sp = ps->ps_sigstk.ss_sp;
				stack_size = ps->ps_sigstk.ss_size;
				ua_sp += stack_size;
				ps->ps_sigstk.ss_flags |= SA_ONSTACK;
			}
		} else
		        ua_sp = tstate64->rsp;
		ua_cr2 = mctx.mctx64.es.faultvaddr;

		/* The x86_64 ABI defines a 128-byte red zone. */
		ua_sp -= C_64_REDZONE_LEN;

		ua_sp -= sizeof (struct user_ucontext64);
		ua_uctxp = ua_sp;			 // someone tramples the first word!

		ua_sp -= sizeof (user_siginfo_t);
		ua_sip = ua_sp;

	        ua_sp -= sizeof (struct mcontext64);
		ua_mctxp = ua_sp;

		/*
		 * Align the frame and stack pointers to 16 bytes for SSE.
		 * (Note that we use 'ua_fp' as the base of the stack going forward)
		 */
		ua_fp = TRUNC_DOWN64(ua_sp, C_64_STK_ALIGN);

		/*
		 * But we need to account for the return address so the alignment is
		 * truly "correct" at _sigtramp
		 */
		ua_fp -= sizeof(user_addr_t);

		/*
		 * Build the signal context to be used by sigreturn.
		 */
		bzero(&uctx64, sizeof(uctx64));

		uctx64.uc_onstack = oonstack;
		uctx64.uc_sigmask = mask;
		uctx64.uc_stack.ss_sp = ua_fp;
		uctx64.uc_stack.ss_size = stack_size;

		if (oonstack)
		        uctx64.uc_stack.ss_flags |= SS_ONSTACK;	
		uctx64.uc_link = 0;

		uctx64.uc_mcsize = sizeof(struct mcontext64);
		uctx64.uc_mcontext64 = ua_mctxp;
		
		if (copyout((caddr_t)&uctx64, ua_uctxp, sizeof (uctx64))) 
		        goto bad;

	        if (copyout((caddr_t)&mctx.mctx64, ua_mctxp, sizeof (struct mcontext64))) 
		        goto bad;

		sinfo64.pad[0]  = tstate64->rsp;
		sinfo64.si_addr = tstate64->rip;

		tstate64->rip = ps->ps_trampact[sig];
		tstate64->rsp = ua_fp;
		tstate64->rflags = get_eflags_exportmask();
		/*
		 * JOE - might not need to set these
		 */
		tstate64->cs = USER64_CS;
		tstate64->fs = NULL_SEG;
		tstate64->gs = USER_CTHREAD;

		/* 
		 * Build the argument list for the signal handler.
		 * Handler should call sigreturn to get out of it
		 */
		tstate64->rdi = ua_catcher;
		tstate64->rsi = infostyle;
		tstate64->rdx = sig;
		tstate64->rcx = ua_sip;
		tstate64->r8  = ua_uctxp;

	} else {
	        x86_thread_state32_t	*tstate32;
	        struct ucontext 	uctx32;
		struct sigframe32	frame32;

	        flavor = x86_THREAD_STATE32;
		state_count = x86_THREAD_STATE32_COUNT;
		state = (void *)&mctx.mctx32.ss;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS)
		        goto bad;

		flavor = x86_FLOAT_STATE32;
		state_count = x86_FLOAT_STATE32_COUNT;
		state = (void *)&mctx.mctx32.fs;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS)
		        goto bad;

		flavor = x86_EXCEPTION_STATE32;
		state_count = x86_EXCEPTION_STATE32_COUNT;
		state = (void *)&mctx.mctx32.es;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS)
		        goto bad;

		tstate32 = &mctx.mctx32.ss;

		if (altstack && !oonstack && (ps->ps_sigonstack & sigmask(sig))) {
		        if (uthsigaltstack != 0) {
			        ua_sp = ut->uu_sigstk.ss_sp;
				stack_size = ut->uu_sigstk.ss_size;
				ua_sp += stack_size;
				ut->uu_sigstk.ss_flags |= SA_ONSTACK;
			} else {
			        ua_sp = ps->ps_sigstk.ss_sp;
				stack_size = ps->ps_sigstk.ss_size;
				ua_sp += stack_size;
				ps->ps_sigstk.ss_flags |= SA_ONSTACK;
			}
		} else
		        ua_sp = tstate32->esp;
		ua_cr2 = mctx.mctx32.es.faultvaddr;

		ua_sp -= sizeof (struct ucontext);
		ua_uctxp = ua_sp;			 // someone tramples the first word!

		ua_sp -= sizeof (siginfo_t);
		ua_sip = ua_sp;

	        ua_sp -= sizeof (struct mcontext32);
		ua_mctxp = ua_sp;

		ua_sp -= sizeof (struct sigframe32);
		ua_fp = ua_sp;

		/*
		 * Align the frame and stack pointers to 16 bytes for SSE.
		 * (Note that we use 'fp' as the base of the stack going forward)
		 */
		ua_fp = TRUNC_DOWN32(ua_fp, C_32_STK_ALIGN);

		/*
		 * But we need to account for the return address so the alignment is
		 * truly "correct" at _sigtramp
		 */
		ua_fp -= sizeof(frame32.retaddr);

		/* 
		 * Build the argument list for the signal handler.
		 * Handler should call sigreturn to get out of it
		 */
		frame32.retaddr = -1;	
		frame32.sigstyle = infostyle;
		frame32.sig = sig;
		frame32.catcher = CAST_DOWN(sig_t, ua_catcher);
		frame32.sinfo = CAST_DOWN(siginfo_t *, ua_sip);
		frame32.uctx = CAST_DOWN(struct ucontext *, ua_uctxp);

		if (copyout((caddr_t)&frame32, ua_fp, sizeof (frame32))) 
		        goto bad;

		/*
		 * Build the signal context to be used by sigreturn.
		 */
		bzero(&uctx32, sizeof(uctx32));

		uctx32.uc_onstack = oonstack;
		uctx32.uc_sigmask = mask;
		uctx32.uc_stack.ss_sp = CAST_DOWN(char *, ua_fp);
		uctx32.uc_stack.ss_size = stack_size;

		if (oonstack)
		        uctx32.uc_stack.ss_flags |= SS_ONSTACK;	
		uctx32.uc_link = 0;

		uctx32.uc_mcsize = sizeof(struct mcontext32);

		uctx32.uc_mcontext = CAST_DOWN(struct mcontext *, ua_mctxp);
		
		if (copyout((caddr_t)&uctx32, ua_uctxp, sizeof (uctx32))) 
		        goto bad;

		if (copyout((caddr_t)&mctx.mctx32, ua_mctxp, sizeof (struct mcontext32))) 
		        goto bad;

		sinfo64.pad[0]  = tstate32->esp;
		sinfo64.si_addr = tstate32->eip;
	}

	switch (sig) {
		case SIGCHLD:
			sinfo64.si_pid = p->si_pid;
			p->si_pid =0;
			sinfo64.si_status = p->si_status;
			p->si_status = 0;
			sinfo64.si_uid = p->si_uid;
			p->si_uid =0;
			sinfo64.si_code = p->si_code;
			p->si_code = 0;
			if (sinfo64.si_code == CLD_EXITED) {
				if (WIFEXITED(sinfo64.si_status)) 
					sinfo64.si_code = CLD_EXITED;
				else if (WIFSIGNALED(sinfo64.si_status)) {
					if (WCOREDUMP(sinfo64.si_status))
						sinfo64.si_code = CLD_DUMPED;
					else	
						sinfo64.si_code = CLD_KILLED;
				}
			}
			break;
		case SIGILL:
			switch (ut->uu_code) {
				case EXC_I386_INVOP:
					sinfo64.si_code = ILL_ILLOPC;
					break;
				case EXC_I386_GPFLT:
					sinfo64.si_code = ILL_PRVOPC;
					break;
				default:
					printf("unknown SIGILL code %d\n", ut->uu_code);
					sinfo64.si_code = ILL_NOOP;
			}
			break;
		case SIGFPE:
#define FP_IE 0 /* Invalid operation */
#define FP_DE 1 /* Denormalized operand */
#define FP_ZE 2 /* Zero divide */
#define FP_OE 3 /* overflow */
#define FP_UE 4 /* underflow */
#define FP_PE 5 /* precision */
			if (ut->uu_subcode & (1 << FP_ZE)) {
				sinfo64.si_code = FPE_FLTDIV;
			} else if (ut->uu_subcode & (1 << FP_OE)) {
				sinfo64.si_code = FPE_FLTOVF;
			} else if (ut->uu_subcode & (1 << FP_UE)) {
				sinfo64.si_code = FPE_FLTUND;
			} else if (ut->uu_subcode & (1 << FP_PE)) {
				sinfo64.si_code = FPE_FLTRES;
			} else if (ut->uu_subcode & (1 << FP_IE)) {
				sinfo64.si_code = FPE_FLTINV;
			} else {
				printf("unknown SIGFPE code %d, subcode %x\n",
				       ut->uu_code, ut->uu_subcode);
				sinfo64.si_code = FPE_NOOP;
			}
			break;
		case SIGBUS:
			sinfo64.si_code = BUS_ADRERR;
			sinfo64.si_addr = ua_cr2;
			break;
		case SIGTRAP:
			sinfo64.si_code = TRAP_BRKPT;
			break;
		case SIGSEGV:
		        sinfo64.si_addr = ua_cr2;

			switch (ut->uu_code) {
				case KERN_PROTECTION_FAILURE:
					sinfo64.si_code = SEGV_ACCERR;
					break;
				case KERN_INVALID_ADDRESS:
					sinfo64.si_code = SEGV_MAPERR;
					break;
				default:
					printf("unknown SIGSEGV code %d\n", ut->uu_code);
					sinfo64.si_code = FPE_NOOP;
			}
				break;
		default:
			break;
	}
	if (proc_is64bit(p)) {
	        if (copyout((caddr_t)&sinfo64, ua_sip, sizeof (sinfo64))) 
		        goto bad;

		flavor = x86_THREAD_STATE64;
		state_count = x86_THREAD_STATE64_COUNT;
		state = (void *)&mctx.mctx64.ss;
	} else {
	        x86_thread_state32_t	*tstate32;
		siginfo_t		sinfo32;

		bzero((caddr_t)&sinfo32, sizeof(siginfo_t));

		sinfo32.si_signo  = sinfo64.si_signo;
		sinfo32.si_code   = sinfo64.si_code;
		sinfo32.si_pid    = sinfo64.si_pid;
		sinfo32.si_uid    = sinfo64.si_uid;
		sinfo32.si_status = sinfo64.si_status;
		sinfo32.si_addr   = CAST_DOWN(void *, sinfo64.si_addr);
		sinfo32.pad[0]    = sinfo64.pad[0];

	        if (copyout((caddr_t)&sinfo32, ua_sip, sizeof (sinfo32))) 
		        goto bad;
	
		tstate32 = &mctx.mctx32.ss;
		tstate32->eip = CAST_DOWN(unsigned int, ps->ps_trampact[sig]);
		tstate32->esp = CAST_DOWN(unsigned int, ua_fp);
		
		tstate32->eflags = get_eflags_exportmask();

		tstate32->cs = USER_CS;
		tstate32->ss = USER_DS;
		tstate32->ds = USER_DS;
		tstate32->es = USER_DS;
		tstate32->fs = NULL_SEG;
		tstate32->gs = USER_CTHREAD;

		flavor = x86_THREAD_STATE32;
		state_count = x86_THREAD_STATE32_COUNT;
		state = (void *)tstate32;
	}
	if (thread_setstatus(thread, flavor, (thread_state_t)state, state_count) != KERN_SUCCESS)
	        goto bad;
	ml_fp_setvalid(FALSE);

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

int
sigreturn(
	struct proc *p,
	struct sigreturn_args *uap,
	__unused int *retval)
{
        union {
	    struct mcontext32	mctx32;
	    struct mcontext64	mctx64;
	} mctx;
	thread_t thread = current_thread();
	struct uthread * ut;
	int	error;
	int	uthsigaltstack = 0;
	int	onstack = 0;

	mach_msg_type_number_t ts_count;
	unsigned int           ts_flavor;
	void		    *  ts;
	mach_msg_type_number_t fs_count;
	unsigned int           fs_flavor;
	void		    *  fs;

	ut = (struct uthread *)get_bsdthread_info(thread);
	uthsigaltstack = p->p_lflag & P_LTHSIGSTACK;

	if (proc_is64bit(p)) {
	        struct user_ucontext64	uctx64;

	        if ((error = copyin(uap->uctx, (void *)&uctx64, sizeof (uctx64))))
		        return(error);

		if ((error = copyin(uctx64.uc_mcontext64, (void *)&mctx.mctx64, sizeof (struct mcontext64))))
		        return(error);

		onstack = uctx64.uc_onstack & 01;
		ut->uu_sigmask = uctx64.uc_sigmask & ~sigcantmask;

	        ts_flavor = x86_THREAD_STATE64;
		ts_count  = x86_THREAD_STATE64_COUNT;
		ts = (void *)&mctx.mctx64.ss;

		fs_flavor = x86_FLOAT_STATE64;
		fs_count  = x86_FLOAT_STATE64_COUNT;
		fs = (void *)&mctx.mctx64.fs;

      } else {
	        struct ucontext		uctx32;

	        if ((error = copyin(uap->uctx, (void *)&uctx32, sizeof (uctx32)))) 
		        return(error);

		if ((error = copyin(CAST_USER_ADDR_T(uctx32.uc_mcontext), (void *)&mctx.mctx32, sizeof (struct mcontext32)))) 
		        return(error);

		onstack = uctx32.uc_onstack & 01;
		ut->uu_sigmask = uctx32.uc_sigmask & ~sigcantmask;

	        ts_flavor = x86_THREAD_STATE32;
		ts_count  = x86_THREAD_STATE32_COUNT;
		ts = (void *)&mctx.mctx32.ss;

		fs_flavor = x86_FLOAT_STATE32;
		fs_count  = x86_FLOAT_STATE32_COUNT;
		fs = (void *)&mctx.mctx32.fs;
	}
	if (onstack) {
		if (uthsigaltstack != 0)
			ut->uu_sigstk.ss_flags |= SA_ONSTACK;
		else
			p->p_sigacts->ps_sigstk.ss_flags |= SA_ONSTACK;
	} else {
		if (uthsigaltstack != 0)
			ut->uu_sigstk.ss_flags &= ~SA_ONSTACK;
		else
			p->p_sigacts->ps_sigstk.ss_flags &= ~SA_ONSTACK;
	}
	if (ut->uu_siglist & ~ut->uu_sigmask)
		signal_setast(thread);

	/*
	 * thread_set_state() does all the needed checks for the passed in content
	 */
	if (thread_setstatus(thread, ts_flavor, ts, ts_count) != KERN_SUCCESS)
	        return(EINVAL);

	ml_fp_setvalid(TRUE);

	if (thread_setstatus(thread, fs_flavor, fs, fs_count)  != KERN_SUCCESS)
	        return(EINVAL);

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

