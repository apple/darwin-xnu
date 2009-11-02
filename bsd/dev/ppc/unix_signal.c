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
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 */

#include <mach/mach_types.h>
#include <mach/exception_types.h>

#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/ucontext.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/ux_exception.h>

#include <ppc/signal.h>
#include <sys/signalvar.h>
#include <sys/kdebug.h>
#include <sys/wait.h>
#include <kern/thread.h>
#include <mach/ppc/thread_status.h>
#include <ppc/proc_reg.h>

// #include <machine/thread.h> XXX include path messed up for some reason...

/* XXX functions not in a Mach headers */
extern kern_return_t thread_getstatus(register thread_t act, int flavor,
			thread_state_t tstate, mach_msg_type_number_t *count);
extern int is_64signalregset(void);
extern unsigned int get_msr_exportmask(void);
extern kern_return_t thread_setstatus(thread_t thread, int flavor,
			thread_state_t tstate, mach_msg_type_number_t count);
extern void ppc_checkthreadstate(void *, int);
extern struct savearea_vec *find_user_vec_curr(void);
extern int thread_enable_fpe(thread_t act, int onoff);



#define	C_32_REDZONE_LEN	224
#define	C_32_STK_ALIGN		16
#define C_32_PARAMSAVE_LEN	64
#define	C_32_LINKAGE_LEN	48

#define	C_64_REDZONE_LEN	320
#define	C_64_STK_ALIGN		32
#define	C_64_PARAMSAVE_LEN	64
#define	C_64_LINKAGE_LEN	48

#define TRUNC_DOWN32(a,b,c)	((((uint32_t)a)-(b)) & ((uint32_t)(-(c))))
#define TRUNC_DOWN64(a,b,c)	((((uint64_t)a)-(b)) & ((uint64_t)(-(c))))

/*
 * The stack layout possibilities (info style); This needs to mach with signal trampoline code
 *
 * Traditional:			1
 * Traditional64:		20
 * Traditional64with vec:	25
 * 32bit context		30
 * 32bit context with vector	35
 * 64bit context		40
 * 64bit context with vector	45
 * Dual context			50
 * Dual context with vector	55
 *
 */
 
#define UC_TRAD			1
#define UC_TRAD_VEC		6
#define UC_TRAD64		20
#define UC_TRAD64_VEC		25
#define UC_FLAVOR		30
#define UC_FLAVOR_VEC		35
#define UC_FLAVOR64		40
#define UC_FLAVOR64_VEC		45
#define UC_DUAL			50
#define UC_DUAL_VEC		55

 /* The following are valid mcontext sizes */
#define UC_FLAVOR_SIZE ((PPC_THREAD_STATE_COUNT + PPC_EXCEPTION_STATE_COUNT + PPC_FLOAT_STATE_COUNT) * sizeof(int))

#define UC_FLAVOR_VEC_SIZE ((PPC_THREAD_STATE_COUNT + PPC_EXCEPTION_STATE_COUNT + PPC_FLOAT_STATE_COUNT + PPC_VECTOR_STATE_COUNT) * sizeof(int))

#define UC_FLAVOR64_SIZE ((PPC_THREAD_STATE64_COUNT + PPC_EXCEPTION_STATE64_COUNT + PPC_FLOAT_STATE_COUNT) * sizeof(int))

#define UC_FLAVOR64_VEC_SIZE ((PPC_THREAD_STATE64_COUNT + PPC_EXCEPTION_STATE64_COUNT + PPC_FLOAT_STATE_COUNT + PPC_VECTOR_STATE_COUNT) * sizeof(int))


/*
 * NOTE: Source and target may *NOT* overlap!
 */
static void
ucontext_32to64(struct ucontext64 *in, struct user_ucontext64 *out)
{
	out->uc_onstack		= in->uc_onstack;
	out->uc_sigmask		= in->uc_sigmask;

	/* internal "structure assign" */
	out->uc_stack.ss_sp	= CAST_USER_ADDR_T(in->uc_stack.ss_sp);
	out->uc_stack.ss_size	= in->uc_stack.ss_size;
	out->uc_stack.ss_flags	= in->uc_stack.ss_flags;

	out->uc_link		= CAST_USER_ADDR_T(in->uc_link);
	out->uc_mcsize		= in->uc_mcsize;
	out->uc_mcontext64	= CAST_USER_ADDR_T(in->uc_mcontext64);
}

/*
 * This conversion is safe, since if we are converting for a 32 bit process,
 * then it's values of uc-stack.ss_size and uc_mcsize will never exceed 4G.
 *
 * NOTE: Source and target may *NOT* overlap!
 */
static void
ucontext_64to32(struct user_ucontext64 *in, struct ucontext64 *out)
{
	out->uc_onstack		= in->uc_onstack;
	out->uc_sigmask		= in->uc_sigmask;

	/* internal "structure assign" */
	out->uc_stack.ss_sp	= CAST_DOWN(void *,in->uc_stack.ss_sp);
	out->uc_stack.ss_size	= in->uc_stack.ss_size;	/* range reduction */
	out->uc_stack.ss_flags	= in->uc_stack.ss_flags;

	out->uc_link		= CAST_DOWN(void *,in->uc_link);
	out->uc_mcsize		= in->uc_mcsize;	/* range reduction */
	out->uc_mcontext64	= CAST_DOWN(void *,in->uc_mcontext64);
}

/*
 * NOTE: Source and target may *NOT* overlap!
 */
static void
siginfo_64to32(user_siginfo_t *in, siginfo_t *out)
{
	out->si_signo	= in->si_signo;
	out->si_errno	= in->si_errno;
	out->si_code	= in->si_code;
	out->si_pid	= in->si_pid;
	out->si_uid	= in->si_uid;
	out->si_status	= in->si_status;
	out->si_addr	= CAST_DOWN(void *,in->si_addr);
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr	= CAST_DOWN(void *,in->si_value.sival_ptr);
	out->si_band	= in->si_band;			/* range reduction */
	out->pad[0]	= in->pad[0];			/* mcontext.ss.r1 */
}


/*
 * Arrange for this process to run a signal handler
 */

void
sendsig(struct proc *p, user_addr_t catcher, int sig, int mask, __unused u_long code)
{
	kern_return_t kretn;
	struct mcontext mctx;
	user_addr_t p_mctx = USER_ADDR_NULL;		/* mcontext dest. */
	struct mcontext64 mctx64;
	user_addr_t p_mctx64 = USER_ADDR_NULL;		/* mcontext dest. */
	struct user_ucontext64 uctx;
	user_addr_t p_uctx;		/* user stack addr top copy ucontext */
	user_siginfo_t sinfo;
	user_addr_t p_sinfo;		/* user stack addr top copy siginfo */
	struct sigacts *ps = p->p_sigacts;
	int oonstack;
	user_addr_t sp;
	mach_msg_type_number_t state_count;
	thread_t th_act;
	struct uthread *ut;
	int infostyle = UC_TRAD;
	int dualcontext =0;
	user_addr_t trampact;
	int vec_used = 0;
	int stack_size = 0;
	void * tstate;
	int flavor;
        int ctx32 = 1;

	th_act = current_thread();
	ut = get_bsdthread_info(th_act);

	
	if (p->p_sigacts->ps_siginfo & sigmask(sig)) {
		infostyle = UC_FLAVOR;
        }
	if(is_64signalregset() && (infostyle == UC_FLAVOR)) {
		dualcontext = 1;
		infostyle = UC_DUAL;	
	}
	if (p->p_sigacts->ps_64regset & sigmask(sig)) {
		dualcontext = 0;
                ctx32 = 0;
		infostyle = UC_FLAVOR64;
	}
	/* treat 64 bit processes as having used 64 bit registers */
        if ((IS_64BIT_PROCESS(p) || is_64signalregset()) &&
	    (infostyle == UC_TRAD)) {
                ctx32=0;
 		infostyle = UC_TRAD64;
	}
	if (IS_64BIT_PROCESS(p)) {
		ctx32=0;
		dualcontext = 0;
	}
	
	/* I need this for SIGINFO anyway */
	flavor = PPC_THREAD_STATE;
	tstate = (void *)&mctx.ss;
	state_count = PPC_THREAD_STATE_COUNT;
	if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
		goto bad;

	if ((ctx32 == 0) || dualcontext) {
		flavor = PPC_THREAD_STATE64;
		tstate = (void *)&mctx64.ss;
		state_count = PPC_THREAD_STATE64_COUNT;
                if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                    goto bad;
	}

        if ((ctx32 == 1) || dualcontext) {
                flavor = PPC_EXCEPTION_STATE;
		tstate = (void *)&mctx.es;
		state_count = PPC_EXCEPTION_STATE_COUNT;
                if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                    goto bad;
       } 
       
	if ((ctx32 == 0) || dualcontext) {
 		flavor = PPC_EXCEPTION_STATE64;
		tstate = (void *)&mctx64.es;
		state_count = PPC_EXCEPTION_STATE64_COUNT;
       
                if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                    goto bad;
                
        }
       

        if ((ctx32 == 1) || dualcontext) {
                flavor = PPC_FLOAT_STATE;
		tstate = (void *)&mctx.fs;
		state_count = PPC_FLOAT_STATE_COUNT;
                if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                    goto bad;
       } 
       
	if ((ctx32 == 0) || dualcontext) {
 		flavor = PPC_FLOAT_STATE;
		tstate = (void *)&mctx64.fs;
		state_count = PPC_FLOAT_STATE_COUNT;
                       if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                    goto bad;
                
        }


	if (find_user_vec_curr()) {
		vec_used = 1;

                if ((ctx32 == 1) || dualcontext) {
                    flavor = PPC_VECTOR_STATE;
                    tstate = (void *)&mctx.vs;
                    state_count = PPC_VECTOR_STATE_COUNT;
                    if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                    goto bad;
                    infostyle += 5;
            } 
       
            if ((ctx32 == 0) || dualcontext) {
                    flavor = PPC_VECTOR_STATE;
                    tstate = (void *)&mctx64.vs;
                    state_count = PPC_VECTOR_STATE_COUNT;
                    if (thread_getstatus(th_act, flavor, (thread_state_t)tstate, &state_count)  != KERN_SUCCESS)
                        goto bad;
                    infostyle += 5;
           }
	}  

	trampact = ps->ps_trampact[sig];
	oonstack = ps->ps_sigstk.ss_flags & SA_ONSTACK;

	/* figure out where our new stack lives */
	if ((ps->ps_flags & SAS_ALTSTACK) && !oonstack &&
		(ps->ps_sigonstack & sigmask(sig))) {
		sp = ps->ps_sigstk.ss_sp;
		sp += ps->ps_sigstk.ss_size;
		stack_size = ps->ps_sigstk.ss_size;
		ps->ps_sigstk.ss_flags |= SA_ONSTACK;
	}
	else {
		if (ctx32 == 0)
			sp = mctx64.ss.r1;
		else
			sp = CAST_USER_ADDR_T(mctx.ss.r1);
	}

	
	/* put siginfo on top */
        
	/* preserve RED ZONE area */
	if (IS_64BIT_PROCESS(p))
		sp = TRUNC_DOWN64(sp, C_64_REDZONE_LEN, C_64_STK_ALIGN);
	else
		sp = TRUNC_DOWN32(sp, C_32_REDZONE_LEN, C_32_STK_ALIGN);

        /* next are the saved registers */
        if ((ctx32 == 0) || dualcontext) {
            sp -= sizeof(struct mcontext64);
            p_mctx64 = sp;
        }
        if ((ctx32 == 1) || dualcontext) {
            sp -= sizeof(struct mcontext);
            p_mctx = sp;
        }    
        
	if (IS_64BIT_PROCESS(p)) {
		/* context goes first on stack */
		sp -= sizeof(struct user_ucontext64);
		p_uctx = sp;

		/* this is where siginfo goes on stack */
		sp -= sizeof(user_siginfo_t);
		p_sinfo = sp;
		
		sp = TRUNC_DOWN64(sp, C_64_PARAMSAVE_LEN+C_64_LINKAGE_LEN, C_64_STK_ALIGN);
	} else {
		/*
		 * struct ucontext and struct ucontext64 are identical in
		 * size and content; the only difference is the internal
		 * pointer type for the last element, which makes no
		 * difference for the copyout().
		 */

		/* context goes first on stack */
		sp -= sizeof(struct ucontext64);
		p_uctx = sp;

		/* this is where siginfo goes on stack */
		sp -= sizeof(siginfo_t);
		p_sinfo = sp;

		sp = TRUNC_DOWN32(sp, C_32_PARAMSAVE_LEN+C_32_LINKAGE_LEN, C_32_STK_ALIGN);
	}

	uctx.uc_onstack = oonstack;
	uctx.uc_sigmask = mask;
	uctx.uc_stack.ss_sp = sp;
	uctx.uc_stack.ss_size = stack_size;
	if (oonstack)
		uctx.uc_stack.ss_flags |= SS_ONSTACK;
		
	uctx.uc_link = 0;
	if (ctx32 == 0)
		uctx.uc_mcsize = (size_t)((PPC_EXCEPTION_STATE64_COUNT + PPC_THREAD_STATE64_COUNT + PPC_FLOAT_STATE_COUNT) * sizeof(int));
	else
		uctx.uc_mcsize = (size_t)((PPC_EXCEPTION_STATE_COUNT + PPC_THREAD_STATE_COUNT + PPC_FLOAT_STATE_COUNT) * sizeof(int));
	
	if (vec_used) 
		uctx.uc_mcsize += (size_t)(PPC_VECTOR_STATE_COUNT * sizeof(int));
        
	if (ctx32 == 0)
             uctx.uc_mcontext64 = p_mctx64;
       else
            uctx.uc_mcontext64 = p_mctx;

	/* setup siginfo */
	bzero((caddr_t)&sinfo, sizeof(user_siginfo_t));
	sinfo.si_signo = sig;
	if (ctx32 == 0) {
		sinfo.si_addr = mctx64.ss.srr0;
		sinfo.pad[0] = mctx64.ss.r1;
	} else {
		sinfo.si_addr = CAST_USER_ADDR_T(mctx.ss.srr0);
		sinfo.pad[0] = CAST_USER_ADDR_T(mctx.ss.r1);
	}

	switch (sig) {
		case SIGCHLD:
			sinfo.si_pid = p->si_pid;
			p->si_pid =0;
			sinfo.si_status = p->si_status;
			p->si_status = 0;
			sinfo.si_uid = p->si_uid;
			p->si_uid =0;
			sinfo.si_code = p->si_code;
			p->si_code = 0;
			if (sinfo.si_code == CLD_EXITED) {
				if (WIFEXITED(sinfo.si_status)) 
					sinfo.si_code = CLD_EXITED;
				else if (WIFSIGNALED(sinfo.si_status)) {
					if (WCOREDUMP(sinfo.si_status))
						sinfo.si_code = CLD_DUMPED;
					else	
						sinfo.si_code = CLD_KILLED;
				}
			}
			break;
		case SIGILL:
			/*
			 * If it's 64 bit and not a dual context, mctx will
			 * contain uninitialized data, so we have to use
			 * mctx64 here.
			 */
			if(ctx32 == 0) {
				if (mctx64.ss.srr1 & (1 << (31 - SRR1_PRG_ILL_INS_BIT)))
					sinfo.si_code = ILL_ILLOPC;
				else if (mctx64.ss.srr1 & (1 << (31 - SRR1_PRG_PRV_INS_BIT)))
					sinfo.si_code = ILL_PRVOPC;
				else if (mctx64.ss.srr1 & (1 << (31 - SRR1_PRG_TRAP_BIT)))
					sinfo.si_code = ILL_ILLTRP;
				else
					sinfo.si_code = ILL_NOOP;
			} else {
				if (mctx.ss.srr1 & (1 << (31 - SRR1_PRG_ILL_INS_BIT)))
					sinfo.si_code = ILL_ILLOPC;
				else if (mctx.ss.srr1 & (1 << (31 - SRR1_PRG_PRV_INS_BIT)))
					sinfo.si_code = ILL_PRVOPC;
				else if (mctx.ss.srr1 & (1 << (31 - SRR1_PRG_TRAP_BIT)))
					sinfo.si_code = ILL_ILLTRP;
				else
					sinfo.si_code = ILL_NOOP;
			}
			break;
		case SIGFPE:
#define FPSCR_VX	2
#define FPSCR_OX	3
#define FPSCR_UX	4
#define FPSCR_ZX	5
#define FPSCR_XX	6
			/*
			 * If it's 64 bit and not a dual context, mctx will
			 * contain uninitialized data, so we have to use
			 * mctx64 here.
			 */
			if(ctx32 == 0) {
				if (mctx64.fs.fpscr & (1 << (31 - FPSCR_VX)))
					sinfo.si_code = FPE_FLTINV;
				else if (mctx64.fs.fpscr & (1 << (31 - FPSCR_OX)))
					sinfo.si_code = FPE_FLTOVF;
				else if (mctx64.fs.fpscr & (1 << (31 - FPSCR_UX)))
					sinfo.si_code = FPE_FLTUND;
				else if (mctx64.fs.fpscr & (1 << (31 - FPSCR_ZX)))
					sinfo.si_code = FPE_FLTDIV;
				else if (mctx64.fs.fpscr & (1 << (31 - FPSCR_XX)))
					sinfo.si_code = FPE_FLTRES;
				else
					sinfo.si_code = FPE_NOOP;
			} else {
				if (mctx.fs.fpscr & (1 << (31 - FPSCR_VX)))
					sinfo.si_code = FPE_FLTINV;
				else if (mctx.fs.fpscr & (1 << (31 - FPSCR_OX)))
					sinfo.si_code = FPE_FLTOVF;
				else if (mctx.fs.fpscr & (1 << (31 - FPSCR_UX)))
					sinfo.si_code = FPE_FLTUND;
				else if (mctx.fs.fpscr & (1 << (31 - FPSCR_ZX)))
					sinfo.si_code = FPE_FLTDIV;
				else if (mctx.fs.fpscr & (1 << (31 - FPSCR_XX)))
					sinfo.si_code = FPE_FLTRES;
				else
					sinfo.si_code = FPE_NOOP;
			}
			break;

		case SIGBUS:
			if (ctx32 == 0) {
				sinfo.si_addr = mctx64.es.dar;
			} else {
				sinfo.si_addr = CAST_USER_ADDR_T(mctx.es.dar);
			}
			/* on ppc we generate only if EXC_PPC_UNALIGNED */
			sinfo.si_code = BUS_ADRALN;
			break;

		case SIGSEGV:
			/*
			 * If it's 64 bit and not a dual context, mctx will
			 * contain uninitialized data, so we have to use
			 * mctx64 here.
			 */
			if (ctx32 == 0) {
				sinfo.si_addr = mctx64.es.dar;
				/* First check in srr1 and then in dsisr */
				if (mctx64.ss.srr1 & (1 << (31 - DSISR_PROT_BIT)))
					sinfo.si_code = SEGV_ACCERR;
				else if (mctx64.es.dsisr & (1 << (31 - DSISR_PROT_BIT)))
					sinfo.si_code = SEGV_ACCERR;
				else
					sinfo.si_code = SEGV_MAPERR;
			} else {
				sinfo.si_addr = CAST_USER_ADDR_T(mctx.es.dar);
				/* First check in srr1 and then in dsisr */
				if (mctx.ss.srr1 & (1 << (31 - DSISR_PROT_BIT)))
					sinfo.si_code = SEGV_ACCERR;
				else if (mctx.es.dsisr & (1 << (31 - DSISR_PROT_BIT)))
					sinfo.si_code = SEGV_ACCERR;
				else
					sinfo.si_code = SEGV_MAPERR;
			}
			break;
		default:
			break;
	}


	/* copy info out to user space */
	if (IS_64BIT_PROCESS(p)) {
		if (copyout(&uctx, p_uctx, sizeof(struct user_ucontext64)))
			goto bad;
		if (copyout(&sinfo, p_sinfo, sizeof(user_siginfo_t)))
			goto bad;
	} else {
		struct ucontext64 uctx32;
		siginfo_t sinfo32;

		ucontext_64to32(&uctx, &uctx32);
		if (copyout(&uctx32, p_uctx, sizeof(struct ucontext64)))
			goto bad;

		siginfo_64to32(&sinfo,&sinfo32);
		if (copyout(&sinfo32, p_sinfo, sizeof(siginfo_t)))
			goto bad;
	}
        if ((ctx32 == 0) || dualcontext) {
	    /*
	     * NOTE: Size of mcontext is not variant between 64bit and
	     * 32bit programs usng 64bit registers.
	     */
            if (copyout(&mctx64, p_mctx64, (vec_used? UC_FLAVOR64_VEC_SIZE: UC_FLAVOR64_SIZE)))
		goto bad;
        }
        if ((ctx32 == 1) || dualcontext) {
            if (copyout(&mctx, p_mctx, uctx.uc_mcsize))
		goto bad;
        }    


	/* Place our arguments in arg registers: rtm dependent */
	if(IS_64BIT_PROCESS(p)) {
		mctx64.ss.r3 = catcher;
		mctx64.ss.r4 = CAST_USER_ADDR_T(infostyle);
		mctx64.ss.r5 = CAST_USER_ADDR_T(sig);
		mctx64.ss.r6 = p_sinfo;
		mctx64.ss.r7 = p_uctx;

		mctx64.ss.srr0 = trampact;
		/* MSR_EXPORT_MASK_SET */
		mctx64.ss.srr1 = CAST_USER_ADDR_T(get_msr_exportmask());
		mctx64.ss.r1 = sp;
		state_count = PPC_THREAD_STATE64_COUNT;
		if ((kretn = thread_setstatus(th_act, PPC_THREAD_STATE64, (void *)&mctx64.ss, state_count))  != KERN_SUCCESS) {
			panic("sendsig: thread_setstatus failed, ret = %08X\n", kretn);
		}	
	} else {
		mctx.ss.r3 = CAST_DOWN(unsigned long,catcher);
		mctx.ss.r4 = (unsigned long)infostyle;
		mctx.ss.r5 = (unsigned long)sig;
		mctx.ss.r6 = CAST_DOWN(unsigned long,p_sinfo);
		mctx.ss.r7 = CAST_DOWN(unsigned long,p_uctx);

		mctx.ss.srr0 = CAST_DOWN(unsigned long,trampact);
		/* MSR_EXPORT_MASK_SET */
		mctx.ss.srr1 = get_msr_exportmask();
		mctx.ss.r1 = CAST_DOWN(unsigned long,sp);
		state_count = PPC_THREAD_STATE_COUNT;
		if ((kretn = thread_setstatus(th_act, PPC_THREAD_STATE, (void *)&mctx.ss, state_count))  != KERN_SUCCESS) {
			panic("sendsig: thread_setstatus failed, ret = %08X\n", kretn);
		}	
	}
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
sigreturn(struct proc *p, struct sigreturn_args *uap, __unused int *retval)
{
	struct user_ucontext64 uctx;

	char mactx[sizeof(struct mcontext64)];
	struct mcontext *p_mctx;
	struct mcontext64 *p_64mctx;
	int error;
	thread_t th_act;
	struct sigacts *ps = p->p_sigacts;
	sigset_t mask;	
	user_addr_t action;
	unsigned long state_count;
	unsigned int state_flavor;
	struct uthread * ut;
	int vec_used = 0;
	void *tsptr, *fptr, *vptr;
        int infostyle = uap->infostyle;

	th_act = current_thread();

	ut = (struct uthread *)get_bsdthread_info(th_act);
	if (IS_64BIT_PROCESS(p)) {
		error = copyin(uap->uctx, &uctx, sizeof(struct user_ucontext64));
		if (error)
			return(error);
	} else {
		struct ucontext64 uctx32;

		/*
		 * struct ucontext and struct ucontext64 are identical in
		 * size and content; the only difference is the internal
		 * pointer type for the last element, which makes no
		 * difference for the copyin().
		 */
		error = copyin(uap->uctx, &uctx32, sizeof(struct ucontext));
		if (error)
			return(error);
		ucontext_32to64(&uctx32, &uctx);
	}
        

	/* validate the machine context size */
	switch (uctx.uc_mcsize) {
		case UC_FLAVOR64_VEC_SIZE:
		case UC_FLAVOR64_SIZE:
		case UC_FLAVOR_VEC_SIZE:
		case UC_FLAVOR_SIZE:
			break;
		default:
			return(EINVAL);
	}

	/*
	 * The 64 bit process mcontext is identical to the mcontext64, so
	 * there is no conversion necessary.
	 */
	error = copyin(uctx.uc_mcontext64, mactx, uctx.uc_mcsize);
	if (error)
		return(error);
	
	if ((uctx.uc_onstack & 01))
			p->p_sigacts->ps_sigstk.ss_flags |= SA_ONSTACK;
	else
		p->p_sigacts->ps_sigstk.ss_flags &= ~SA_ONSTACK;

	ut->uu_sigmask = uctx.uc_sigmask & ~sigcantmask;
	if (ut->uu_siglist & ~ut->uu_sigmask)
		signal_setast(current_thread());	

	vec_used = 0;
	switch (infostyle)  {
                case UC_FLAVOR64_VEC:
                case UC_TRAD64_VEC:
                                vec_used = 1;
                case UC_TRAD64:
		case UC_FLAVOR64:  {
                            p_64mctx = (struct mcontext64 *)mactx;	
                            tsptr = (void *)&p_64mctx->ss;
                            fptr = (void *)&p_64mctx->fs;
                            vptr = (void *)&p_64mctx->vs;
                            state_flavor = PPC_THREAD_STATE64;
                            state_count = PPC_THREAD_STATE64_COUNT;
                    } 
                    break;
		case UC_FLAVOR_VEC :
		case UC_TRAD_VEC :
                                vec_used = 1;
		case UC_FLAVOR :
		case UC_TRAD :
		default: {
			p_mctx = (struct mcontext *)mactx;	
			tsptr = (void *)&p_mctx->ss;
			fptr = (void *)&p_mctx->fs;
			vptr = (void *)&p_mctx->vs;
			state_flavor = PPC_THREAD_STATE;
			state_count = PPC_THREAD_STATE_COUNT;
		}
		break;
	} /* switch () */

	/* validate the thread state, set/reset appropriate mode bits in srr1 */
	(void)ppc_checkthreadstate(tsptr, state_flavor);

	if (thread_setstatus(th_act, state_flavor, tsptr, state_count)  != KERN_SUCCESS) {
		return(EINVAL);
	}	

	state_count = PPC_FLOAT_STATE_COUNT;
	if (thread_setstatus(th_act, PPC_FLOAT_STATE, fptr, state_count)  != KERN_SUCCESS) {
		return(EINVAL);
	}	

	mask = sigmask(SIGFPE);
	if (((ut->uu_sigmask & mask) == 0) && (p->p_sigcatch & mask) && ((p->p_sigignore & mask) == 0)) {
		action = ps->ps_sigact[SIGFPE];
		if((action != SIG_DFL) && (action != SIG_IGN)) {
			thread_enable_fpe(th_act, 1);
		}
	}

	if (vec_used) {
		state_count = PPC_VECTOR_STATE_COUNT;
		if (thread_setstatus(th_act, PPC_VECTOR_STATE, vptr, state_count)  != KERN_SUCCESS) {
			return(EINVAL);
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
    int		exception,
    int		code,
    __unused int subcode,
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

    case EXC_SOFTWARE:
	if (code == EXC_PPC_TRAP) {
		*unix_signal = SIGTRAP;
		*unix_code = code;
		break;
	} else
		return(FALSE);

    default:
	return(FALSE);
    }
   
    return(TRUE);
}

