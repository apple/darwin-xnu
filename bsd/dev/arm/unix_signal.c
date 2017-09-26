/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
 */

#include <mach/mach_types.h>
#include <mach/exception_types.h>

#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/signal.h>
#include <sys/ucontext.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ux_exception.h>

#include <arm/signal.h>
#include <sys/signalvar.h>
#include <sys/kdebug.h>
#include <sys/sdt.h>
#include <sys/wait.h>
#include <kern/thread.h>
#include <mach/arm/thread_status.h>
#include <arm/proc_reg.h>

#include <kern/assert.h>
#include <pexpert/pexpert.h>

extern struct arm_saved_state *get_user_regs(thread_t);
extern user_addr_t thread_get_cthread_self(void);
extern kern_return_t thread_getstatus(thread_t act, int flavor,
		thread_state_t tstate, mach_msg_type_number_t *count);
extern kern_return_t thread_setstatus(thread_t thread, int flavor,
		thread_state_t tstate, mach_msg_type_number_t count);
/* XXX Put these someplace smarter... */
typedef struct mcontext32 mcontext32_t; 
typedef struct mcontext64 mcontext64_t;

/* Signal handler flavors supported */
/* These defns should match the Libc implmn */
#define UC_TRAD			1
#define UC_FLAVOR		30

/* The following are valid mcontext sizes */
#define UC_FLAVOR_SIZE32 ((ARM_THREAD_STATE_COUNT + ARM_EXCEPTION_STATE_COUNT + ARM_VFP_STATE_COUNT) * sizeof(int))
#define UC_FLAVOR_SIZE64 ((ARM_THREAD_STATE64_COUNT + ARM_EXCEPTION_STATE64_COUNT + ARM_NEON_STATE64_COUNT) * sizeof(int))

#if __arm64__
#define	C_64_REDZONE_LEN	128
#endif

static int
sendsig_get_state32(thread_t th_act, mcontext32_t *mcp)
{
	void *tstate;
	mach_msg_type_number_t state_count;

	assert(!proc_is64bit(current_proc()));

	tstate = (void *) &mcp->ss;
	state_count = ARM_THREAD_STATE_COUNT;
	if (thread_getstatus(th_act, ARM_THREAD_STATE, (thread_state_t) tstate, &state_count) != KERN_SUCCESS)
		return EINVAL;

	tstate = (void *) &mcp->es;
	state_count = ARM_EXCEPTION_STATE_COUNT;
	if (thread_getstatus(th_act, ARM_EXCEPTION_STATE, (thread_state_t) tstate, &state_count) != KERN_SUCCESS)
		return EINVAL;

	tstate = (void *) &mcp->fs;
	state_count = ARM_VFP_STATE_COUNT;
	if (thread_getstatus(th_act, ARM_VFP_STATE, (thread_state_t) tstate, &state_count) != KERN_SUCCESS)
		return EINVAL;

	return 0;
}

#if defined(__arm64__)
struct user_sigframe64 {
	/* We can pass the last arg in a register for ARM64 */
	user64_siginfo_t	sinfo;
	struct user_ucontext64 	uctx;
	mcontext64_t		mctx;
};

static int
sendsig_get_state64(thread_t th_act, mcontext64_t *mcp)
{
	void *tstate;
	mach_msg_type_number_t state_count;

	assert(proc_is64bit(current_proc()));

	tstate = (void *) &mcp->ss;
	state_count = ARM_THREAD_STATE64_COUNT;
	if (thread_getstatus(th_act, ARM_THREAD_STATE64, (thread_state_t) tstate, &state_count) != KERN_SUCCESS)
		return EINVAL;

	tstate = (void *) &mcp->es;
	state_count = ARM_EXCEPTION_STATE64_COUNT;
	if (thread_getstatus(th_act, ARM_EXCEPTION_STATE64, (thread_state_t) tstate, &state_count) != KERN_SUCCESS)
		return EINVAL;

	tstate = (void *) &mcp->ns;
	state_count = ARM_NEON_STATE64_COUNT;
	if (thread_getstatus(th_act, ARM_NEON_STATE64, (thread_state_t) tstate, &state_count) != KERN_SUCCESS)
		return EINVAL;

	return 0;
}

static void
sendsig_fill_uctx64(user_ucontext64_t *uctx, int oonstack, int mask, user64_addr_t sp, user64_size_t stack_size, user64_addr_t p_mctx)
{
	bzero(uctx, sizeof(*uctx));
	uctx->uc_onstack = oonstack;
	uctx->uc_sigmask = mask;
	uctx->uc_stack.ss_sp = sp; 
	uctx->uc_stack.ss_size = stack_size;
	if (oonstack)
		uctx->uc_stack.ss_flags |= SS_ONSTACK;
	uctx->uc_link = (user64_addr_t)0;
	uctx->uc_mcsize = (user64_size_t) UC_FLAVOR_SIZE64; 
	uctx->uc_mcontext64 = (user64_addr_t) p_mctx;
}

static kern_return_t
sendsig_set_thread_state64(arm_thread_state64_t *regs, 
		user64_addr_t catcher, int infostyle, int sig, user64_addr_t p_sinfo, 
		user64_addr_t p_uctx, user64_addr_t trampact, user64_addr_t sp, thread_t th_act)
{
	assert(proc_is64bit(current_proc()));

	regs->x[0] = catcher;
	regs->x[1] = infostyle;
	regs->x[2] = sig;
	regs->x[3] = p_sinfo;
	regs->x[4] = p_uctx;
	regs->pc = trampact;
	regs->cpsr = PSR64_USER64_DEFAULT;
	regs->sp = sp;

	return thread_setstatus(th_act, ARM_THREAD_STATE64, (void *)regs, ARM_THREAD_STATE64_COUNT);
}
#endif /* defined(__arm64__) */

static void
sendsig_fill_uctx32(user_ucontext32_t *uctx, int oonstack, int mask, user_addr_t sp, user_size_t stack_size, user_addr_t p_mctx)
{
	bzero(uctx, sizeof(*uctx));
	uctx->uc_onstack = oonstack;
	uctx->uc_sigmask = mask;
	uctx->uc_stack.ss_sp = (user32_addr_t) sp; 
	uctx->uc_stack.ss_size = (user32_size_t) stack_size;
	if (oonstack)
		uctx->uc_stack.ss_flags |= SS_ONSTACK;
	uctx->uc_link = (user32_addr_t)0;
	uctx->uc_mcsize = (user32_size_t) UC_FLAVOR_SIZE32; 
	uctx->uc_mcontext = (user32_addr_t) p_mctx;
}

static kern_return_t
sendsig_set_thread_state32(arm_thread_state_t *regs, 
		user32_addr_t catcher, int infostyle, int sig, user32_addr_t p_sinfo, 
		user32_addr_t trampact, user32_addr_t sp, thread_t th_act)
{

	assert(!proc_is64bit(current_proc()));

	regs->r[0] = catcher;
	regs->r[1] = infostyle;
	regs->r[2] = sig;
	regs->r[3] = p_sinfo;
	if (trampact & 1) {
		regs->pc = trampact & ~1;
#if defined(__arm64__)
		regs->cpsr = PSR64_USER32_DEFAULT | PSR64_MODE_USER32_THUMB;
#elif defined(__arm__)
		regs->cpsr = PSR_USERDFLT | PSR_TF;
#else
#error Unknown architeture.
#endif
	} else {
		regs->pc = trampact;
		regs->cpsr = PSR_USERDFLT;
	}
	regs->sp = sp;

	return thread_setstatus(th_act, ARM_THREAD_STATE, (void *)regs, ARM_THREAD_STATE_COUNT);
}

#if CONFIG_DTRACE
static void
sendsig_do_dtrace(uthread_t ut, user_siginfo_t *sinfo, int sig, user_addr_t catcher)
{
        bzero((caddr_t)&(ut->t_dtrace_siginfo), sizeof(ut->t_dtrace_siginfo));

	ut->t_dtrace_siginfo.si_signo = sinfo->si_signo;
	ut->t_dtrace_siginfo.si_code = sinfo->si_code;
	ut->t_dtrace_siginfo.si_pid = sinfo->si_pid;
	ut->t_dtrace_siginfo.si_uid = sinfo->si_uid;
	ut->t_dtrace_siginfo.si_status = sinfo->si_status;
	    /* XXX truncates faulting address to void *  */
	ut->t_dtrace_siginfo.si_addr = CAST_DOWN_EXPLICIT(void *, sinfo->si_addr);

	/* Fire DTrace proc:::fault probe when signal is generated by hardware. */
	switch (sig) {
	case SIGILL: case SIGBUS: case SIGSEGV: case SIGFPE: case SIGTRAP:
		DTRACE_PROC2(fault, int, (int)(ut->uu_code), siginfo_t *, &(ut->t_dtrace_siginfo));
		break;
	default:
		break;
	}
	
	/* XXX truncates faulting address to uintptr_t  */
	DTRACE_PROC3(signal__handle, int, sig, siginfo_t *, &(ut->t_dtrace_siginfo),
	    void (*)(void), CAST_DOWN(sig_t, catcher));
}
#endif 
	
struct user_sigframe32 {
	user32_addr_t		puctx;
	user32_siginfo_t 	sinfo;
	struct user_ucontext32 	uctx;
	mcontext32_t		mctx;
};

/*
 * Send an interrupt to process.
 *
 */
void
sendsig(
	struct proc * p,
	user_addr_t catcher,
	int sig,
	int mask,
	__unused uint32_t code
)
{
	union { 
		struct user_sigframe32 uf32;
#if defined(__arm64__)
		struct user_sigframe64 uf64;
#endif
	} user_frame;

	user_siginfo_t sinfo;
	user_addr_t 	sp = 0, trampact;
	struct sigacts *ps = p->p_sigacts;
	int             oonstack, infostyle;
	thread_t        th_act;
	struct uthread *ut;
	user_size_t	stack_size = 0;

	th_act = current_thread();
	ut = get_bsdthread_info(th_act);

	bzero(&user_frame, sizeof(user_frame));

	if (p->p_sigacts->ps_siginfo & sigmask(sig))
		infostyle = UC_FLAVOR;
	else
		infostyle = UC_TRAD;

	trampact = ps->ps_trampact[sig];
	oonstack = ps->ps_sigstk.ss_flags & SA_ONSTACK;

	/*
	 * Get sundry thread state.
	 */
	if (proc_is64bit(p)) {
#ifdef __arm64__
		if (sendsig_get_state64(th_act, &user_frame.uf64.mctx) != 0) {
			goto bad2;
		}
#else
	panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
	} else {
		if (sendsig_get_state32(th_act, &user_frame.uf32.mctx) != 0) {
			goto bad2;
		}
	}

	/*
	 * Figure out where our new stack lives.
	 */
	if ((ps->ps_flags & SAS_ALTSTACK) && !oonstack &&
	    (ps->ps_sigonstack & sigmask(sig))) {
		sp = ps->ps_sigstk.ss_sp;
		sp += ps->ps_sigstk.ss_size;
		stack_size = ps->ps_sigstk.ss_size;
		ps->ps_sigstk.ss_flags |= SA_ONSTACK;
	} else {
		/*
		 * Get stack pointer, and allocate enough space
		 * for signal handler data.
		 */
		if (proc_is64bit(p)) {
#if defined(__arm64__)
			sp = CAST_USER_ADDR_T(user_frame.uf64.mctx.ss.sp);
			sp = (sp - sizeof(user_frame.uf64) - C_64_REDZONE_LEN) & ~0xf; /* Make sure to align to 16 bytes and respect red zone */
#else
			panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
		} else {
			sp = CAST_USER_ADDR_T(user_frame.uf32.mctx.ss.sp);
			sp -= sizeof(user_frame.uf32);
#if defined(__arm__) && (__BIGGEST_ALIGNMENT__ > 4)
			sp &= ~0xf; /* Make sure to align to 16 bytes for armv7k */
#endif
		}
	}

	proc_unlock(p);

	/*
	 * Fill in ucontext (points to mcontext, i.e. thread states).
	 */
	if (proc_is64bit(p)) {
#if defined(__arm64__)
		sendsig_fill_uctx64(&user_frame.uf64.uctx, oonstack, mask, sp, (user64_size_t)stack_size,
				(user64_addr_t)&((struct user_sigframe64*)sp)->mctx);
#else
		panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
	} else {
		sendsig_fill_uctx32(&user_frame.uf32.uctx, oonstack, mask, sp, (user32_size_t)stack_size, 
				(user32_addr_t)&((struct user_sigframe32*)sp)->mctx);
	}

	/*
	 * Setup siginfo.
	 */
	bzero((caddr_t) & sinfo, sizeof(sinfo));
	sinfo.si_signo = sig;

	if (proc_is64bit(p)) {
#if defined(__arm64__)
		sinfo.si_addr = user_frame.uf64.mctx.ss.pc;
		sinfo.pad[0] = user_frame.uf64.mctx.ss.sp;
#else
		panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
	} else {
		sinfo.si_addr = user_frame.uf32.mctx.ss.pc;
		sinfo.pad[0] = user_frame.uf32.mctx.ss.sp;
	}

	switch (sig) {
	case SIGILL:
#ifdef	BER_XXX
		if (mctx.ss.srr1 & (1 << (31 - SRR1_PRG_ILL_INS_BIT)))
			sinfo.si_code = ILL_ILLOPC;
		else if (mctx.ss.srr1 & (1 << (31 - SRR1_PRG_PRV_INS_BIT)))
			sinfo.si_code = ILL_PRVOPC;
		else if (mctx.ss.srr1 & (1 << (31 - SRR1_PRG_TRAP_BIT)))
			sinfo.si_code = ILL_ILLTRP;
		else
			sinfo.si_code = ILL_NOOP;
#else
		sinfo.si_code = ILL_ILLTRP;
#endif
		break;

	case SIGFPE:
		break;

	case SIGBUS:
		if (proc_is64bit(p)) {
#if defined(__arm64__)
			sinfo.si_addr = user_frame.uf64.mctx.es.far;
#else
			panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
		} else {
			sinfo.si_addr = user_frame.uf32.mctx.es.far;
		}

		sinfo.si_code = BUS_ADRALN;
		break;

	case SIGSEGV:
		if (proc_is64bit(p)) {
#if defined(__arm64__)
			sinfo.si_addr = user_frame.uf64.mctx.es.far;
#else
			panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
		} else {
			sinfo.si_addr = user_frame.uf32.mctx.es.far;
		}

#ifdef	BER_XXX
		/* First check in srr1 and then in dsisr */
		if (mctx.ss.srr1 & (1 << (31 - DSISR_PROT_BIT)))
			sinfo.si_code = SEGV_ACCERR;
		else if (mctx.es.dsisr & (1 << (31 - DSISR_PROT_BIT)))
			sinfo.si_code = SEGV_ACCERR;
		else
			sinfo.si_code = SEGV_MAPERR;
#else
		sinfo.si_code = SEGV_ACCERR;
#endif
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
		sinfo.si_pid = p->si_pid;
		p->si_pid = 0;
		status_and_exitcode = p->si_status;
		p->si_status = 0;
		sinfo.si_uid = p->si_uid;
		p->si_uid = 0;
		sinfo.si_code = p->si_code;
		p->si_code = 0;
		proc_unlock(p);
		if (sinfo.si_code == CLD_EXITED) {
			if (WIFEXITED(status_and_exitcode))
				sinfo.si_code = CLD_EXITED;
			else if (WIFSIGNALED(status_and_exitcode)) {
				if (WCOREDUMP(status_and_exitcode)) {
					sinfo.si_code = CLD_DUMPED;
					status_and_exitcode = W_EXITCODE(status_and_exitcode,status_and_exitcode);
				} else {
					sinfo.si_code = CLD_KILLED;
					status_and_exitcode = W_EXITCODE(status_and_exitcode,status_and_exitcode);
				}
			}
		}
		/*
		 * The recorded status contains the exit code and the
		 * signal information, but the information to be passed
		 * in the siginfo to the handler is supposed to only
		 * contain the status, so we have to shift it out.
		 */
		sinfo.si_status = (WEXITSTATUS(status_and_exitcode) & 0x00FFFFFF) | (((uint32_t)(p->p_xhighbits) << 24) & 0xFF000000);
		p->p_xhighbits = 0;
		break;
	}
	}

#if CONFIG_DTRACE	
	sendsig_do_dtrace(ut, &sinfo, sig, catcher);
#endif /* CONFIG_DTRACE */

	/* 
	 * Copy signal-handling frame out to user space, set thread state.
	 */
	if (proc_is64bit(p)) {
#if defined(__arm64__)
		/*
		 * mctx filled in when we get state.  uctx filled in by 
		 * sendsig_fill_uctx64(). We fill in the sinfo now.
		 */
		siginfo_user_to_user64(&sinfo, &user_frame.uf64.sinfo);

		if (copyout(&user_frame.uf64, sp, sizeof(user_frame.uf64)) != 0) {
			goto bad; 
		} 

		if (sendsig_set_thread_state64(&user_frame.uf64.mctx.ss,
			catcher, infostyle, sig, (user64_addr_t)&((struct user_sigframe64*)sp)->sinfo,
			(user64_addr_t)&((struct user_sigframe64*)sp)->uctx, trampact, sp, th_act) != KERN_SUCCESS)
			goto bad;

#else
	panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
	} else {
		/*
		 * mctx filled in when we get state.  uctx filled in by 
		 * sendsig_fill_uctx32(). We fill in the sinfo and *pointer* 
		 * to uctx now.
		 */
		siginfo_user_to_user32(&sinfo, &user_frame.uf32.sinfo);
		user_frame.uf32.puctx = (user32_addr_t) &((struct user_sigframe32*)sp)->uctx;

		if (copyout(&user_frame.uf32, sp, sizeof(user_frame.uf32)) != 0) {
			goto bad; 
		} 

		if (sendsig_set_thread_state32(&user_frame.uf32.mctx.ss,
			CAST_DOWN_EXPLICIT(user32_addr_t, catcher), infostyle, sig, (user32_addr_t)&((struct user_sigframe32*)sp)->sinfo,
			CAST_DOWN_EXPLICIT(user32_addr_t, trampact), CAST_DOWN_EXPLICIT(user32_addr_t, sp), th_act) != KERN_SUCCESS)
			goto bad;
	}

	proc_lock(p);
	return;

bad:
	proc_lock(p);
bad2:
	SIGACTION(p, SIGILL) = SIG_DFL;
	sig = sigmask(SIGILL);
	p->p_sigignore &= ~sig;
	p->p_sigcatch &= ~sig;
	ut->uu_sigmask &= ~sig;
	/* sendsig is called with signal lock held */
	proc_unlock(p);
	psignal_locked(p, SIGILL);
	proc_lock(p);
}

/*
 * System call to cleanup state after a signal
 * has been taken.  Reset signal mask and
 * stack state from context left by sendsig (above).
 * Return to previous * context left by sendsig.
 * Check carefully to * make sure that the user has not
 * modified the * spr to gain improper priviledges.
 */

static int
sigreturn_copyin_ctx32(struct user_ucontext32 *uctx, mcontext32_t *mctx, user_addr_t uctx_addr)
{
	int error;

	assert(!proc_is64bit(current_proc()));

	error = copyin(uctx_addr, uctx, sizeof(*uctx));
	if (error) {
		return (error);
	}

	/* validate the machine context size */
	switch (uctx->uc_mcsize) {
	case UC_FLAVOR_SIZE32:
		break;
	default:
		return (EINVAL);
	}

	assert(uctx->uc_mcsize == sizeof(*mctx));
	error = copyin((user_addr_t)uctx->uc_mcontext, mctx, uctx->uc_mcsize);
	if (error) {
		return (error);
	}

	return 0;
}

static int
sigreturn_set_state32(thread_t th_act, mcontext32_t *mctx) 
{
	assert(!proc_is64bit(current_proc()));

	/* validate the thread state, set/reset appropriate mode bits in cpsr */
#if defined(__arm__)
	mctx->ss.cpsr = (mctx->ss.cpsr & ~PSR_MODE_MASK) | PSR_USERDFLT;
#elif defined(__arm64__)
	mctx->ss.cpsr = (mctx->ss.cpsr & ~PSR64_MODE_MASK) | PSR64_USER32_DEFAULT;
#else
#error Unknown architecture.
#endif

	if (thread_setstatus(th_act, ARM_THREAD_STATE, (void *)&mctx->ss, ARM_THREAD_STATE_COUNT) != KERN_SUCCESS) {
		return (EINVAL);
	}
	if (thread_setstatus(th_act, ARM_VFP_STATE, (void *)&mctx->fs, ARM_VFP_STATE_COUNT) != KERN_SUCCESS) {
		return (EINVAL);
	}

	return 0;
}

#if defined(__arm64__)
static int
sigreturn_copyin_ctx64(struct user_ucontext64 *uctx, mcontext64_t *mctx, user_addr_t uctx_addr)
{
	int error;

	assert(proc_is64bit(current_proc()));

	error = copyin(uctx_addr, uctx, sizeof(*uctx));
	if (error) {
		return (error);
	}

	/* validate the machine context size */
	switch (uctx->uc_mcsize) {
	case UC_FLAVOR_SIZE64:
		break;
	default:
		return (EINVAL);
	}

	assert(uctx->uc_mcsize == sizeof(*mctx));
	error = copyin((user_addr_t)uctx->uc_mcontext64, mctx, uctx->uc_mcsize);
	if (error) {
		return (error);
	}

	return 0;
}

static int
sigreturn_set_state64(thread_t th_act, mcontext64_t *mctx) 
{
	assert(proc_is64bit(current_proc()));

	/* validate the thread state, set/reset appropriate mode bits in cpsr */
	mctx->ss.cpsr = (mctx->ss.cpsr & ~PSR64_MODE_MASK) | PSR64_USER64_DEFAULT;

	if (thread_setstatus(th_act, ARM_THREAD_STATE64, (void *)&mctx->ss, ARM_THREAD_STATE64_COUNT) != KERN_SUCCESS) {
		return (EINVAL);
	}
	if (thread_setstatus(th_act, ARM_NEON_STATE64, (void *)&mctx->ns, ARM_NEON_STATE64_COUNT) != KERN_SUCCESS) {
		return (EINVAL);
	}

	return 0;
}
#endif /* defined(__arm64__) */

/* ARGSUSED */
int
sigreturn(
	  struct proc * p,
	  struct sigreturn_args * uap,
	  __unused int *retval)
{
	union {
		user_ucontext32_t uc32;
#if defined(__arm64__)
		user_ucontext64_t uc64;
#endif
	} uctx;

	union { 
		mcontext32_t mc32;
#if defined(__arm64__)
		mcontext64_t mc64;
#endif
	} mctx;

	int             error, sigmask = 0, onstack = 0;
	thread_t        th_act;
	struct uthread *ut;

	th_act = current_thread();
	ut = (struct uthread *) get_bsdthread_info(th_act);

	if (proc_is64bit(p)) {
#if defined(__arm64__)
		error = sigreturn_copyin_ctx64(&uctx.uc64, &mctx.mc64, uap->uctx);
		if (error != 0) {
			return error;
		}

		onstack = uctx.uc64.uc_onstack;
		sigmask = uctx.uc64.uc_sigmask;
#else
		panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
	} else {
		error = sigreturn_copyin_ctx32(&uctx.uc32, &mctx.mc32, uap->uctx);
		if (error != 0) {
			return error;
		}

		onstack = uctx.uc32.uc_onstack;
		sigmask = uctx.uc32.uc_sigmask;
	}

	if ((onstack & 01))
		p->p_sigacts->ps_sigstk.ss_flags |= SA_ONSTACK;
	else
		p->p_sigacts->ps_sigstk.ss_flags &= ~SA_ONSTACK;

	ut->uu_sigmask = sigmask & ~sigcantmask;
	if (ut->uu_siglist & ~ut->uu_sigmask)
		signal_setast(current_thread());

	if (proc_is64bit(p)) {
#if defined(__arm64__)
		error = sigreturn_set_state64(th_act, &mctx.mc64);
		if (error != 0) {
			return error;
		}
#else
		panic("Shouldn't have 64-bit thread states on a 32-bit kernel.");
#endif
	} else {
		error = sigreturn_set_state32(th_act, &mctx.mc32);
		if (error != 0) {
			return error;
		}
	}

	return (EJUSTRETURN);
}

/*
 * machine_exception() performs MD translation
 * of a mach exception to a unix signal and code.
 */

boolean_t
machine_exception(
		  int exception,
		  mach_exception_subcode_t code,
		  __unused mach_exception_subcode_t subcode,
		  int *unix_signal,
		  mach_exception_subcode_t * unix_code
)
{
	switch (exception) {
	case EXC_BAD_INSTRUCTION:
		*unix_signal = SIGILL;
		*unix_code = code;
		break;

	case EXC_ARITHMETIC:
		*unix_signal = SIGFPE;
		*unix_code = code;
		break;

	default:
		return (FALSE);
	}
	return (TRUE);
}
