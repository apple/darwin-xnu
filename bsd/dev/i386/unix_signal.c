/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1992 NeXT, Inc.
 *
 * HISTORY
 * 13 May 1992 ? at NeXT
 *	Created.
 */

#include <mach/mach_types.h>
#include <mach/exception.h>

#include <kern/thread.h>
#include <kern/ast.h>

#include <sys/systm.h>
#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/ucontext.h>
#include <sys/wait.h>

#include <sys/ux_exception.h>

#include <mach/thread_act.h>    /* for thread_abort_safely */
#include <mach/thread_status.h>

#include <i386/eflags.h>
#include <i386/psl.h>
#include <i386/machine_routines.h>
#include <i386/seg.h>
#include <i386/fpu.h>

#include <machine/pal_routines.h>

#include <sys/kdebug.h>
#include <sys/sdt.h>


/* Forward: */
extern kern_return_t thread_getstatus(thread_t act, int flavor,
    thread_state_t tstate, mach_msg_type_number_t *count);
extern kern_return_t thread_setstatus(thread_t thread, int flavor,
    thread_state_t tstate, mach_msg_type_number_t count);

/* Signal handler flavors supported */
/* These defns should match the Libc implmn */
#define UC_TRAD                 1
#define UC_FLAVOR               30
#define UC_SET_ALT_STACK        0x40000000
#define UC_RESET_ALT_STACK      0x80000000

#define C_32_STK_ALIGN          16
#define C_64_STK_ALIGN          16
#define C_64_REDZONE_LEN        128
#define TRUNC_DOWN32(a, c)       ((((uint32_t)a)-(c)) & ((uint32_t)(-(c))))
#define TRUNC_DOWN64(a, c)       ((((uint64_t)a)-(c)) & ((uint64_t)(-(c))))

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
	int             retaddr;
	user32_addr_t   catcher; /* sig_t */
	int             sigstyle;
	int             sig;
	user32_addr_t   sinfo;  /* siginfo32_t* */
	user32_addr_t   uctx;   /* struct ucontext32 */
	user32_addr_t   token;
};

/*
 * Declare table of structure flavors and sizes for 64-bit and 32-bit processes
 * for the cases of extended states (plain FP, or AVX):
 */
typedef struct {
	int flavor; natural_t state_count; size_t  mcontext_size;
} xstate_info_t;
static const xstate_info_t thread_state64[] = {
	[FP]          = { x86_FLOAT_STATE64, x86_FLOAT_STATE64_COUNT, sizeof(struct mcontext64) },
	[FP_FULL]     = { x86_FLOAT_STATE64, x86_FLOAT_STATE64_COUNT, sizeof(struct mcontext64_full) },
	[AVX]         = { x86_AVX_STATE64, x86_AVX_STATE64_COUNT, sizeof(struct mcontext_avx64) },
	[AVX_FULL]    = { x86_AVX_STATE64, x86_AVX_STATE64_COUNT, sizeof(struct mcontext_avx64_full) },
	[AVX512]      = { x86_AVX512_STATE64, x86_AVX512_STATE64_COUNT, sizeof(struct mcontext_avx512_64) },
	[AVX512_FULL] = { x86_AVX512_STATE64, x86_AVX512_STATE64_COUNT, sizeof(struct mcontext_avx512_64_full) }
};
static const xstate_info_t thread_state32[] = {
	[FP]     = { x86_FLOAT_STATE32, x86_FLOAT_STATE32_COUNT, sizeof(struct mcontext32) },
	[AVX]    = { x86_AVX_STATE32, x86_AVX_STATE32_COUNT, sizeof(struct mcontext_avx32) },
	[AVX512] = { x86_AVX512_STATE32, x86_AVX512_STATE32_COUNT, sizeof(struct mcontext_avx512_32) }
};

/*
 * NOTE: Source and target may *NOT* overlap!
 * XXX: Unify with bsd/kern/kern_exit.c
 */
static void
siginfo_user_to_user32_x86(user_siginfo_t *in, user32_siginfo_t *out)
{
	out->si_signo   = in->si_signo;
	out->si_errno   = in->si_errno;
	out->si_code    = in->si_code;
	out->si_pid     = in->si_pid;
	out->si_uid     = in->si_uid;
	out->si_status  = in->si_status;
	out->si_addr    = CAST_DOWN_EXPLICIT(user32_addr_t, in->si_addr);
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr = CAST_DOWN_EXPLICIT(user32_addr_t, in->si_value.sival_ptr);
	out->si_band    = in->si_band;                  /* range reduction */
	out->__pad[0]   = in->pad[0];                   /* mcontext.ss.r1 */
}

static void
siginfo_user_to_user64_x86(user_siginfo_t *in, user64_siginfo_t *out)
{
	out->si_signo   = in->si_signo;
	out->si_errno   = in->si_errno;
	out->si_code    = in->si_code;
	out->si_pid     = in->si_pid;
	out->si_uid     = in->si_uid;
	out->si_status  = in->si_status;
	out->si_addr    = in->si_addr;
	out->si_value.sival_ptr = in->si_value.sival_ptr;
	out->si_band    = in->si_band;                  /* range reduction */
	out->__pad[0]   = in->pad[0];                   /* mcontext.ss.r1 */
}

void
sendsig(struct proc *p, user_addr_t ua_catcher, int sig, int mask, __unused uint32_t code, sigset_t siginfo)
{
	union {
		struct mcontext_avx32           mctx_avx32;
		struct mcontext_avx64           mctx_avx64;
		struct mcontext_avx64_full      mctx_avx64_full;
		struct mcontext_avx512_32       mctx_avx512_32;
		struct mcontext_avx512_64       mctx_avx512_64;
		struct mcontext_avx512_64_full  mctx_avx512_64_full;
	} mctx_store, *mctxp = &mctx_store;

	user_addr_t     ua_sp;
	user_addr_t     ua_fp;
	user_addr_t     ua_cr2;
	user_addr_t     ua_sip;
	user_addr_t     ua_uctxp;
	user_addr_t     ua_mctxp;
	user_siginfo_t  sinfo64;

	struct sigacts *ps = p->p_sigacts;
	int oonstack, flavor;
	user_addr_t trampact;
	int sigonstack;
	void * state, *fpstate;
	mach_msg_type_number_t state_count;

	thread_t thread;
	struct uthread * ut;
	int stack_size = 0;
	int infostyle = UC_TRAD;
	xstate_t        sig_xstate;
	user_addr_t     token_uctx;
	kern_return_t   kr;
	boolean_t       reset_ss = TRUE;

	thread = current_thread();
	ut = get_bsdthread_info(thread);

	if (siginfo & sigmask(sig)) {
		infostyle = UC_FLAVOR;
	}

	oonstack = ut->uu_sigstk.ss_flags & SA_ONSTACK;
	trampact = ps->ps_trampact[sig];
	sigonstack = (ps->ps_sigonstack & sigmask(sig));

	/*
	 * init siginfo
	 */
	proc_unlock(p);

	bzero((caddr_t)&sinfo64, sizeof(sinfo64));
	sinfo64.si_signo = sig;

	bzero(mctxp, sizeof(*mctxp));

	sig_xstate = current_xstate();

	if (proc_is64bit(p)) {
		x86_thread_state64_t    *tstate64;
		struct user_ucontext64  uctx64;
		user64_addr_t token;
		int task_has_ldt = thread_task_has_ldt(thread);

		if (task_has_ldt) {
			flavor = x86_THREAD_FULL_STATE64;
			state_count = x86_THREAD_FULL_STATE64_COUNT;
			fpstate = (void *)&mctxp->mctx_avx64_full.fs;
			sig_xstate |= STATE64_FULL;
		} else {
			flavor = x86_THREAD_STATE64;
			state_count = x86_THREAD_STATE64_COUNT;
			fpstate = (void *)&mctxp->mctx_avx64.fs;
		}
		state = (void *)&mctxp->mctx_avx64.ss;

		/*
		 * The state copying is performed with pointers to fields in the state
		 * struct.  This works specifically because the mcontext is layed-out with the
		 * variable-sized FP-state as the last member.  However, with the requirement
		 * to support passing "full" 64-bit state to the signal handler, that layout has now
		 * changed (since the "full" state has a larger "ss" member than the non-"full"
		 * structure.  Because of this, and to retain the array-lookup method of determining
		 * structure sizes, we OR-in STATE64_FULL to sig_xstate to ensure the proper mcontext
		 * size is passed.
		 */

		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS) {
			goto bad;
		}

		if ((sig_xstate & STATE64_FULL) && mctxp->mctx_avx64.ss.cs != USER64_CS) {
			if ((ut->uu_flag & UT_ALTSTACK) && !oonstack &&
			    (sigonstack)) {
				reset_ss = TRUE;
			} else {
				reset_ss = FALSE;
			}
		} else {
			reset_ss = FALSE;
		}

		flavor      = thread_state64[sig_xstate].flavor;
		state_count = thread_state64[sig_xstate].state_count;
		if (thread_getstatus(thread, flavor, (thread_state_t)fpstate, &state_count) != KERN_SUCCESS) {
			goto bad;
		}

		flavor = x86_EXCEPTION_STATE64;
		state_count = x86_EXCEPTION_STATE64_COUNT;
		state = (void *)&mctxp->mctx_avx64.es;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS) {
			goto bad;
		}

		tstate64 = &mctxp->mctx_avx64.ss;

		/* figure out where our new stack lives */
		if ((ut->uu_flag & UT_ALTSTACK) && !oonstack &&
		    (sigonstack)) {
			ua_sp = ut->uu_sigstk.ss_sp;
			stack_size = ut->uu_sigstk.ss_size;
			ua_sp += stack_size;
			ut->uu_sigstk.ss_flags |= SA_ONSTACK;
		} else {
			if ((sig_xstate & STATE64_FULL) && tstate64->cs != USER64_CS) {
				reset_ss = FALSE;
			}
			ua_sp = tstate64->rsp;
		}
		ua_cr2 = mctxp->mctx_avx64.es.faultvaddr;

		/* The x86_64 ABI defines a 128-byte red zone. */
		ua_sp -= C_64_REDZONE_LEN;

		ua_sp -= sizeof(struct user_ucontext64);
		ua_uctxp = ua_sp;                        // someone tramples the first word!

		ua_sp -= sizeof(user64_siginfo_t);
		ua_sip = ua_sp;

		ua_sp -= thread_state64[sig_xstate].mcontext_size;
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
		 * Generate the validation token for sigreturn
		 */
		token_uctx = ua_uctxp;
		kr = machine_thread_siguctx_pointer_convert_to_user(thread, &token_uctx);
		assert(kr == KERN_SUCCESS);
		token = (user64_addr_t)token_uctx ^ (user64_addr_t)ps->ps_sigreturn_token;

		/*
		 * Build the signal context to be used by sigreturn.
		 */
		bzero(&uctx64, sizeof(uctx64));

		uctx64.uc_onstack = oonstack;
		uctx64.uc_sigmask = mask;
		uctx64.uc_stack.ss_sp = ua_fp;
		uctx64.uc_stack.ss_size = stack_size;

		if (oonstack) {
			uctx64.uc_stack.ss_flags |= SS_ONSTACK;
		}
		uctx64.uc_link = 0;

		uctx64.uc_mcsize = thread_state64[sig_xstate].mcontext_size;
		uctx64.uc_mcontext64 = ua_mctxp;

		if (copyout((caddr_t)&uctx64, ua_uctxp, sizeof(uctx64))) {
			goto bad;
		}

		if (copyout((caddr_t)&mctx_store, ua_mctxp, thread_state64[sig_xstate].mcontext_size)) {
			goto bad;
		}

		sinfo64.pad[0]  = tstate64->rsp;
		sinfo64.si_addr = tstate64->rip;

		tstate64->rip = trampact;
		tstate64->rsp = ua_fp;
		tstate64->rflags = get_eflags_exportmask();

		/*
		 * SETH - need to set these for processes with LDTs
		 */
		tstate64->cs = USER64_CS;
		tstate64->fs = NULL_SEG;
		/*
		 * Set gs to 0 here to prevent restoration of %gs on return-to-user.  If we
		 * did NOT do that here and %gs was non-zero, we'd blow away gsbase when
		 * we restore %gs in the kernel exit trampoline.
		 */
		tstate64->gs = 0;

		if (sig_xstate & STATE64_FULL) {
			/* Reset DS, ES, and possibly SS */
			if (reset_ss) {
				/*
				 * Restore %ss if (a) an altstack was used for signal delivery
				 * or (b) %cs at the time of the signal was the default
				 * (USER64_CS)
				 */
				mctxp->mctx_avx64_full.ss.ss = USER64_DS;
			}
			mctxp->mctx_avx64_full.ss.ds = USER64_DS;
			mctxp->mctx_avx64_full.ss.es = 0;
		}

		/*
		 * Build the argument list for the signal handler.
		 * Handler should call sigreturn to get out of it
		 */
		tstate64->rdi = ua_catcher;
		tstate64->rsi = infostyle;
		tstate64->rdx = sig;
		tstate64->rcx = ua_sip;
		tstate64->r8  = ua_uctxp;
		tstate64->r9  = token;
	} else {
		x86_thread_state32_t    *tstate32;
		struct user_ucontext32  uctx32;
		struct sigframe32       frame32;
		user32_addr_t token;

		flavor = x86_THREAD_STATE32;
		state_count = x86_THREAD_STATE32_COUNT;
		state = (void *)&mctxp->mctx_avx32.ss;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS) {
			goto bad;
		}

		flavor = thread_state32[sig_xstate].flavor;
		state_count = thread_state32[sig_xstate].state_count;
		state = (void *)&mctxp->mctx_avx32.fs;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS) {
			goto bad;
		}

		flavor = x86_EXCEPTION_STATE32;
		state_count = x86_EXCEPTION_STATE32_COUNT;
		state = (void *)&mctxp->mctx_avx32.es;
		if (thread_getstatus(thread, flavor, (thread_state_t)state, &state_count) != KERN_SUCCESS) {
			goto bad;
		}

		tstate32 = &mctxp->mctx_avx32.ss;

		/* figure out where our new stack lives */
		if ((ut->uu_flag & UT_ALTSTACK) && !oonstack &&
		    (sigonstack)) {
			ua_sp = ut->uu_sigstk.ss_sp;
			stack_size = ut->uu_sigstk.ss_size;
			ua_sp += stack_size;
			ut->uu_sigstk.ss_flags |= SA_ONSTACK;
		} else {
			ua_sp = tstate32->esp;
		}
		ua_cr2 = mctxp->mctx_avx32.es.faultvaddr;

		ua_sp -= sizeof(struct user_ucontext32);
		ua_uctxp = ua_sp;                        // someone tramples the first word!

		ua_sp -= sizeof(user32_siginfo_t);
		ua_sip = ua_sp;

		ua_sp -= thread_state32[sig_xstate].mcontext_size;
		ua_mctxp = ua_sp;

		ua_sp -= sizeof(struct sigframe32);
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
		 * Generate the validation token for sigreturn
		 */
		token_uctx = ua_uctxp;
		kr = machine_thread_siguctx_pointer_convert_to_user(thread, &token_uctx);
		assert(kr == KERN_SUCCESS);
		token = CAST_DOWN_EXPLICIT(user32_addr_t, token_uctx) ^
		    CAST_DOWN_EXPLICIT(user32_addr_t, ps->ps_sigreturn_token);

		/*
		 * Build the argument list for the signal handler.
		 * Handler should call sigreturn to get out of it
		 */
		frame32.retaddr = -1;
		frame32.sigstyle = infostyle;
		frame32.sig = sig;
		frame32.catcher = CAST_DOWN_EXPLICIT(user32_addr_t, ua_catcher);
		frame32.sinfo = CAST_DOWN_EXPLICIT(user32_addr_t, ua_sip);
		frame32.uctx = CAST_DOWN_EXPLICIT(user32_addr_t, ua_uctxp);
		frame32.token = token;

		if (copyout((caddr_t)&frame32, ua_fp, sizeof(frame32))) {
			goto bad;
		}

		/*
		 * Build the signal context to be used by sigreturn.
		 */
		bzero(&uctx32, sizeof(uctx32));

		uctx32.uc_onstack = oonstack;
		uctx32.uc_sigmask = mask;
		uctx32.uc_stack.ss_sp = CAST_DOWN_EXPLICIT(user32_addr_t, ua_fp);
		uctx32.uc_stack.ss_size = stack_size;

		if (oonstack) {
			uctx32.uc_stack.ss_flags |= SS_ONSTACK;
		}
		uctx32.uc_link = 0;

		uctx32.uc_mcsize = thread_state64[sig_xstate].mcontext_size;

		uctx32.uc_mcontext = CAST_DOWN_EXPLICIT(user32_addr_t, ua_mctxp);

		if (copyout((caddr_t)&uctx32, ua_uctxp, sizeof(uctx32))) {
			goto bad;
		}

		if (copyout((caddr_t)&mctx_store, ua_mctxp, thread_state32[sig_xstate].mcontext_size)) {
			goto bad;
		}

		sinfo64.pad[0]  = tstate32->esp;
		sinfo64.si_addr = tstate32->eip;
	}

	switch (sig) {
	case SIGILL:
		switch (ut->uu_code) {
		case EXC_I386_INVOP:
			sinfo64.si_code = ILL_ILLOPC;
			break;
		default:
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
		if (ut->uu_code == EXC_I386_DIV) {
			sinfo64.si_code = FPE_INTDIV;
		} else if (ut->uu_code == EXC_I386_INTO) {
			sinfo64.si_code = FPE_INTOVF;
		} else if (ut->uu_subcode & (1 << FP_ZE)) {
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
		case EXC_I386_GPFLT:
			/* CR2 is meaningless after GP fault */
			/* XXX namespace clash! */
			sinfo64.si_addr = 0ULL;
			sinfo64.si_code = 0;
			break;
		case KERN_PROTECTION_FAILURE:
			sinfo64.si_code = SEGV_ACCERR;
			break;
		case KERN_INVALID_ADDRESS:
			sinfo64.si_code = SEGV_MAPERR;
			break;
		default:
			sinfo64.si_code = FPE_NOOP;
		}
		break;
	default:
	{
		int status_and_exitcode;

		/*
		 * All other signals need to fill out a minimum set of
		 * information for the siginfo structure passed into
		 * the signal handler, if SA_SIGINFO was specified.
		 *
		 * p->si_status actually contains both the status and
		 * the exit code; we save it off in its own variable
		 * for later breakdown.
		 */
		proc_lock(p);
		sinfo64.si_pid = p->si_pid;
		p->si_pid = 0;
		status_and_exitcode = p->si_status;
		p->si_status = 0;
		sinfo64.si_uid = p->si_uid;
		p->si_uid = 0;
		sinfo64.si_code = p->si_code;
		p->si_code = 0;
		proc_unlock(p);
		if (sinfo64.si_code == CLD_EXITED) {
			if (WIFEXITED(status_and_exitcode)) {
				sinfo64.si_code = CLD_EXITED;
			} else if (WIFSIGNALED(status_and_exitcode)) {
				if (WCOREDUMP(status_and_exitcode)) {
					sinfo64.si_code = CLD_DUMPED;
					status_and_exitcode = W_EXITCODE(status_and_exitcode, status_and_exitcode);
				} else {
					sinfo64.si_code = CLD_KILLED;
					status_and_exitcode = W_EXITCODE(status_and_exitcode, status_and_exitcode);
				}
			}
		}
		/*
		 * The recorded status contains the exit code and the
		 * signal information, but the information to be passed
		 * in the siginfo to the handler is supposed to only
		 * contain the status, so we have to shift it out.
		 */
		sinfo64.si_status = (WEXITSTATUS(status_and_exitcode) & 0x00FFFFFF) | (((uint32_t)(p->p_xhighbits) << 24) & 0xFF000000);
		p->p_xhighbits = 0;
		break;
	}
	}
	if (proc_is64bit(p)) {
		user64_siginfo_t sinfo64_user64;

		bzero((caddr_t)&sinfo64_user64, sizeof(sinfo64_user64));

		siginfo_user_to_user64_x86(&sinfo64, &sinfo64_user64);

#if CONFIG_DTRACE
		bzero((caddr_t)&(ut->t_dtrace_siginfo), sizeof(ut->t_dtrace_siginfo));

		ut->t_dtrace_siginfo.si_signo = sinfo64.si_signo;
		ut->t_dtrace_siginfo.si_code = sinfo64.si_code;
		ut->t_dtrace_siginfo.si_pid = sinfo64.si_pid;
		ut->t_dtrace_siginfo.si_uid = sinfo64.si_uid;
		ut->t_dtrace_siginfo.si_status = sinfo64.si_status;
		/* XXX truncates faulting address to void * on K32  */
		ut->t_dtrace_siginfo.si_addr = CAST_DOWN(void *, sinfo64.si_addr);

		/* Fire DTrace proc:::fault probe when signal is generated by hardware. */
		switch (sig) {
		case SIGILL: case SIGBUS: case SIGSEGV: case SIGFPE: case SIGTRAP:
			DTRACE_PROC2(fault, int, (int)(ut->uu_code), siginfo_t *, &(ut->t_dtrace_siginfo));
			break;
		default:
			break;
		}

		/* XXX truncates catcher address to uintptr_t */
		DTRACE_PROC3(signal__handle, int, sig, siginfo_t *, &(ut->t_dtrace_siginfo),
		    void (*)(void), CAST_DOWN(sig_t, ua_catcher));
#endif /* CONFIG_DTRACE */

		if (copyout((caddr_t)&sinfo64_user64, ua_sip, sizeof(sinfo64_user64))) {
			goto bad;
		}

		if (sig_xstate & STATE64_FULL) {
			flavor = x86_THREAD_FULL_STATE64;
			state_count = x86_THREAD_FULL_STATE64_COUNT;
		} else {
			flavor = x86_THREAD_STATE64;
			state_count = x86_THREAD_STATE64_COUNT;
		}
		state = (void *)&mctxp->mctx_avx64.ss;
	} else {
		x86_thread_state32_t    *tstate32;
		user32_siginfo_t sinfo32;

		bzero((caddr_t)&sinfo32, sizeof(sinfo32));

		siginfo_user_to_user32_x86(&sinfo64, &sinfo32);

#if CONFIG_DTRACE
		bzero((caddr_t)&(ut->t_dtrace_siginfo), sizeof(ut->t_dtrace_siginfo));

		ut->t_dtrace_siginfo.si_signo = sinfo32.si_signo;
		ut->t_dtrace_siginfo.si_code = sinfo32.si_code;
		ut->t_dtrace_siginfo.si_pid = sinfo32.si_pid;
		ut->t_dtrace_siginfo.si_uid = sinfo32.si_uid;
		ut->t_dtrace_siginfo.si_status = sinfo32.si_status;
		ut->t_dtrace_siginfo.si_addr = CAST_DOWN(void *, sinfo32.si_addr);

		/* Fire DTrace proc:::fault probe when signal is generated by hardware. */
		switch (sig) {
		case SIGILL: case SIGBUS: case SIGSEGV: case SIGFPE: case SIGTRAP:
			DTRACE_PROC2(fault, int, (int)(ut->uu_code), siginfo_t *, &(ut->t_dtrace_siginfo));
			break;
		default:
			break;
		}

		DTRACE_PROC3(signal__handle, int, sig, siginfo_t *, &(ut->t_dtrace_siginfo),
		    void (*)(void), CAST_DOWN(sig_t, ua_catcher));
#endif /* CONFIG_DTRACE */

		if (copyout((caddr_t)&sinfo32, ua_sip, sizeof(sinfo32))) {
			goto bad;
		}

		tstate32 = &mctxp->mctx_avx32.ss;

		tstate32->eip = CAST_DOWN_EXPLICIT(user32_addr_t, trampact);
		tstate32->esp = CAST_DOWN_EXPLICIT(user32_addr_t, ua_fp);

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
	if (thread_setstatus(thread, flavor, (thread_state_t)state, state_count) != KERN_SUCCESS) {
		goto bad;
	}
	ml_fp_setvalid(FALSE);

	/* Tell the PAL layer about the signal */
	pal_set_signal_delivery( thread );

	proc_lock(p);

	return;

bad:

	proc_lock(p);
	SIGACTION(p, SIGILL) = SIG_DFL;
	sig = sigmask(SIGILL);
	p->p_sigignore &= ~sig;
	p->p_sigcatch &= ~sig;
	ut->uu_sigmask &= ~sig;
	/* sendsig is called with signal lock held */
	proc_unlock(p);
	psignal_locked(p, SIGILL);
	proc_lock(p);
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
sigreturn(struct proc *p, struct sigreturn_args *uap, __unused int *retval)
{
	union {
		struct mcontext_avx32           mctx_avx32;
		struct mcontext_avx64           mctx_avx64;
		struct mcontext_avx64_full      mctx_avx64_full;
		struct mcontext_avx512_32       mctx_avx512_32;
		struct mcontext_avx512_64       mctx_avx512_64;
		struct mcontext_avx512_64_full  mctx_avx512_64_full;
	} mctx_store, *mctxp = &mctx_store;

	thread_t thread = current_thread();
	struct uthread * ut;
	struct sigacts *ps = p->p_sigacts;
	int     error;
	int     onstack = 0;

	mach_msg_type_number_t ts_count;
	unsigned int           ts_flavor;
	void                *  ts;
	mach_msg_type_number_t fs_count;
	unsigned int           fs_flavor;
	void                *  fs;
	int                    rval = EJUSTRETURN;
	xstate_t               sig_xstate;
	uint32_t            sigreturn_validation;
	user_addr_t         token_uctx;
	kern_return_t       kr;

	ut = (struct uthread *)get_bsdthread_info(thread);

	/*
	 * If we are being asked to change the altstack flag on the thread, we
	 * just set/reset it and return (the uap->uctx is not used).
	 */
	if ((unsigned int)uap->infostyle == UC_SET_ALT_STACK) {
		ut->uu_sigstk.ss_flags |= SA_ONSTACK;
		return 0;
	} else if ((unsigned int)uap->infostyle == UC_RESET_ALT_STACK) {
		ut->uu_sigstk.ss_flags &= ~SA_ONSTACK;
		return 0;
	}

	/* see osfmk/kern/restartable.c */
	act_set_ast_reset_pcs(thread);

	bzero(mctxp, sizeof(*mctxp));

	sig_xstate = current_xstate();

	sigreturn_validation = atomic_load_explicit(
		&ps->ps_sigreturn_validation, memory_order_relaxed);
	token_uctx = uap->uctx;
	kr = machine_thread_siguctx_pointer_convert_to_user(thread, &token_uctx);
	assert(kr == KERN_SUCCESS);

	if (proc_is64bit(p)) {
		struct user_ucontext64  uctx64;
		user64_addr_t token;
		int task_has_ldt = thread_task_has_ldt(thread);

		if ((error = copyin(uap->uctx, (void *)&uctx64, sizeof(uctx64)))) {
			return error;
		}

		onstack = uctx64.uc_onstack & 01;
		ut->uu_sigmask = uctx64.uc_sigmask & ~sigcantmask;

		if (task_has_ldt) {
			ts_flavor = x86_THREAD_FULL_STATE64;
			ts_count  = x86_THREAD_FULL_STATE64_COUNT;
			fs = (void *)&mctxp->mctx_avx64_full.fs;
			sig_xstate |= STATE64_FULL;
		} else {
			ts_flavor = x86_THREAD_STATE64;
			ts_count  = x86_THREAD_STATE64_COUNT;
			fs = (void *)&mctxp->mctx_avx64.fs;
		}

		if ((error = copyin(uctx64.uc_mcontext64, (void *)mctxp, thread_state64[sig_xstate].mcontext_size))) {
			return error;
		}

		ts = (void *)&mctxp->mctx_avx64.ss;

		fs_flavor = thread_state64[sig_xstate].flavor;
		fs_count  = thread_state64[sig_xstate].state_count;

		token = (user64_addr_t)token_uctx ^ (user64_addr_t)ps->ps_sigreturn_token;
		if ((user64_addr_t)uap->token != token) {
#if DEVELOPMENT || DEBUG
			printf("process %s[%d] sigreturn token mismatch: received 0x%llx expected 0x%llx\n",
			    p->p_comm, p->p_pid, (user64_addr_t)uap->token, token);
#endif /* DEVELOPMENT || DEBUG */
			if (sigreturn_validation != PS_SIGRETURN_VALIDATION_DISABLED) {
				rval = EINVAL;
			}
		}
	} else {
		struct user_ucontext32  uctx32;
		user32_addr_t token;

		if ((error = copyin(uap->uctx, (void *)&uctx32, sizeof(uctx32)))) {
			return error;
		}

		if ((error = copyin(CAST_USER_ADDR_T(uctx32.uc_mcontext), (void *)mctxp, thread_state32[sig_xstate].mcontext_size))) {
			return error;
		}

		onstack = uctx32.uc_onstack & 01;
		ut->uu_sigmask = uctx32.uc_sigmask & ~sigcantmask;

		ts_flavor = x86_THREAD_STATE32;
		ts_count  = x86_THREAD_STATE32_COUNT;
		ts = (void *)&mctxp->mctx_avx32.ss;

		fs_flavor = thread_state32[sig_xstate].flavor;
		fs_count  = thread_state32[sig_xstate].state_count;
		fs = (void *)&mctxp->mctx_avx32.fs;

		token = CAST_DOWN_EXPLICIT(user32_addr_t, uap->uctx) ^
		    CAST_DOWN_EXPLICIT(user32_addr_t, ps->ps_sigreturn_token);
		if ((user32_addr_t)uap->token != token) {
#if DEVELOPMENT || DEBUG
			printf("process %s[%d] sigreturn token mismatch: received 0x%x expected 0x%x\n",
			    p->p_comm, p->p_pid, (user32_addr_t)uap->token, token);
#endif /* DEVELOPMENT || DEBUG */
			if (sigreturn_validation != PS_SIGRETURN_VALIDATION_DISABLED) {
				rval = EINVAL;
			}
		}
	}

	if (onstack) {
		ut->uu_sigstk.ss_flags |= SA_ONSTACK;
	} else {
		ut->uu_sigstk.ss_flags &= ~SA_ONSTACK;
	}

	if (ut->uu_siglist & ~ut->uu_sigmask) {
		signal_setast(thread);
	}

	if (rval == EINVAL) {
		goto error_ret;
	}

	/*
	 * thread_set_state() does all the needed checks for the passed in
	 * content
	 */
	if (thread_setstatus(thread, ts_flavor, ts, ts_count) != KERN_SUCCESS) {
		rval = EINVAL;
#if DEVELOPMENT || DEBUG
		printf("process %s[%d] sigreturn thread_setstatus error %d\n",
		    p->p_comm, p->p_pid, rval);
#endif /* DEVELOPMENT || DEBUG */
		goto error_ret;
	}

	ml_fp_setvalid(TRUE);

	if (thread_setstatus(thread, fs_flavor, fs, fs_count) != KERN_SUCCESS) {
		rval = EINVAL;
#if DEVELOPMENT || DEBUG
		printf("process %s[%d] sigreturn thread_setstatus error %d\n",
		    p->p_comm, p->p_pid, rval);
#endif /* DEVELOPMENT || DEBUG */
		goto error_ret;
	}
error_ret:
	return rval;
}


/*
 * machine_exception() performs machine-dependent translation
 * of a mach exception to a unix signal.
 */
int
machine_exception(int                           exception,
    mach_exception_code_t         code,
    __unused mach_exception_subcode_t      subcode)
{
	switch (exception) {
	case EXC_BAD_ACCESS:
		/* Map GP fault to SIGSEGV, otherwise defer to caller */
		if (code == EXC_I386_GPFLT) {
			return SIGSEGV;
		}
		break;

	case EXC_BAD_INSTRUCTION:
		return SIGILL;

	case EXC_ARITHMETIC:
		return SIGFPE;

	case EXC_SOFTWARE:
		if (code == EXC_I386_BOUND) {
			/*
			 * Map #BR, the Bound Range Exceeded exception, to
			 * SIGTRAP.
			 */
			return SIGTRAP;
		}
		break;
	}

	return 0;
}
