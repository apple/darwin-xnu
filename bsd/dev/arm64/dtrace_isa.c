/*
 * Copyright (c) 2005-2018 Apple Computer, Inc. All rights reserved.
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

#include <arm/caches_internal.h>
#include <kern/thread.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif
#include <stdarg.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <machine/atomic.h>
#include <kern/cambria_layout.h>
#include <kern/simple_lock.h>
#include <kern/sched_prim.h>            /* for thread_wakeup() */
#include <kern/thread_call.h>
#include <kern/task.h>

extern struct arm_saved_state *find_kern_regs(thread_t);

extern dtrace_id_t      dtrace_probeid_error;   /* special ERROR probe */
typedef arm_saved_state_t savearea_t;

extern lck_attr_t       *dtrace_lck_attr;
extern lck_grp_t        *dtrace_lck_grp;

#if XNU_MONITOR
extern void * pmap_stacks_start;
extern void * pmap_stacks_end;
#endif

struct frame {
	struct frame *backchain;
	uintptr_t retaddr;
};

/*
 * Atomicity and synchronization
 */
inline void
dtrace_membar_producer(void)
{
	__asm__ volatile ("dmb ish" : : : "memory");
}

inline void
dtrace_membar_consumer(void)
{
	__asm__ volatile ("dmb ish" : : : "memory");
}

/*
 * Interrupt manipulation
 * XXX dtrace_getipl() can be called from probe context.
 */
int
dtrace_getipl(void)
{
	/*
	 * XXX Drat, get_interrupt_level is MACH_KERNEL_PRIVATE
	 * in osfmk/kern/cpu_data.h
	 */
	/* return get_interrupt_level(); */
	return ml_at_interrupt_context() ? 1 : 0;
}

/*
 * MP coordination
 */

decl_lck_mtx_data(static, dt_xc_lock);
static uint32_t dt_xc_sync;

typedef struct xcArg {
	processorid_t   cpu;
	dtrace_xcall_t  f;
	void           *arg;
} xcArg_t;

static void
xcRemote(void *foo)
{
	xcArg_t *pArg = (xcArg_t *) foo;

	if (pArg->cpu == CPU->cpu_id || pArg->cpu == DTRACE_CPUALL) {
		(pArg->f)(pArg->arg);
	}

	if (os_atomic_dec(&dt_xc_sync, relaxed) == 0) {
		thread_wakeup((event_t) &dt_xc_sync);
	}
}

/*
 * dtrace_xcall() is not called from probe context.
 */
void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t f, void *arg)
{
	/* Only one dtrace_xcall in flight allowed */
	lck_mtx_lock(&dt_xc_lock);

	xcArg_t xcArg;

	xcArg.cpu = cpu;
	xcArg.f = f;
	xcArg.arg = arg;

	cpu_broadcast_xcall(&dt_xc_sync, TRUE, xcRemote, (void*) &xcArg);

	lck_mtx_unlock(&dt_xc_lock);
	return;
}

/*
 * Initialization
 */
void
dtrace_isa_init(void)
{
	lck_mtx_init(&dt_xc_lock, dtrace_lck_grp, dtrace_lck_attr);
	return;
}


/**
 * Register definitions
 */
#define ARM64_FP 29
#define ARM64_LR 30
#define ARM64_SP 31
#define ARM64_PC 32
#define ARM64_CPSR 33

/*
 * Runtime and ABI
 */
uint64_t
dtrace_getreg(struct regs * savearea, uint_t reg)
{
	struct arm_saved_state *regs = (struct arm_saved_state *) savearea;

	if (regs == NULL) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}

	if (!check_saved_state_reglimit(regs, reg)) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}

	return (uint64_t)get_saved_state_reg(regs, reg);
}

uint64_t
dtrace_getvmreg(uint_t ndx)
{
#pragma unused(ndx)
	DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
	return 0;
}

#define RETURN_OFFSET64 8

static int
dtrace_getustack_common(uint64_t * pcstack, int pcstack_limit, user_addr_t pc,
    user_addr_t sp)
{
	volatile uint16_t *flags = (volatile uint16_t *) &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	int ret = 0;

	ASSERT(pcstack == NULL || pcstack_limit > 0);

	while (pc != 0) {
		ret++;
		if (pcstack != NULL) {
			*pcstack++ = (uint64_t) pc;
			pcstack_limit--;
			if (pcstack_limit <= 0) {
				break;
			}
		}

		if (sp == 0) {
			break;
		}

		pc = dtrace_fuword64((sp + RETURN_OFFSET64));
		sp = dtrace_fuword64(sp);

		/* Truncate ustack if the iterator causes fault. */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			break;
		}
	}

	return ret;
}

void
dtrace_getupcstack(uint64_t * pcstack, int pcstack_limit)
{
	thread_t thread = current_thread();
	savearea_t *regs;
	user_addr_t pc, sp, fp;
	volatile uint16_t *flags = (volatile uint16_t *) &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	int n;

	if (*flags & CPU_DTRACE_FAULT) {
		return;
	}

	if (pcstack_limit <= 0) {
		return;
	}

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (thread == NULL) {
		goto zero;
	}

	regs = (savearea_t *) find_user_regs(thread);
	if (regs == NULL) {
		goto zero;
	}

	*pcstack++ = (uint64_t)dtrace_proc_selfpid();
	pcstack_limit--;

	if (pcstack_limit <= 0) {
		return;
	}

	pc = get_saved_state_pc(regs);
	sp = get_saved_state_sp(regs);

	{
		fp = get_saved_state_fp(regs);
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t) pc;
		pcstack_limit--;
		if (pcstack_limit <= 0) {
			return;
		}

		pc = get_saved_state_lr(regs);
	}

	n = dtrace_getustack_common(pcstack, pcstack_limit, pc, fp);

	ASSERT(n >= 0);
	ASSERT(n <= pcstack_limit);

	pcstack += n;
	pcstack_limit -= n;

zero:
	while (pcstack_limit-- > 0) {
		*pcstack++ = 0ULL;
	}
}

int
dtrace_getustackdepth(void)
{
	thread_t        thread = current_thread();
	savearea_t     *regs;
	user_addr_t     pc, sp, fp;
	int             n = 0;

	if (thread == NULL) {
		return 0;
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT)) {
		return -1;
	}

	regs = (savearea_t *) find_user_regs(thread);
	if (regs == NULL) {
		return 0;
	}

	pc = get_saved_state_pc(regs);
	sp = get_saved_state_sp(regs);
	fp = get_saved_state_fp(regs);

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		n++;
		pc = get_saved_state_lr(regs);
	}

	/*
	 * Note that unlike ppc, the arm code does not use
	 * CPU_DTRACE_USTACK_FP. This is because arm always
	 * traces from the sp, even in syscall/profile/fbt
	 * providers.
	 */

	n += dtrace_getustack_common(NULL, 0, pc, fp);

	return n;
}

void
dtrace_getufpstack(uint64_t * pcstack, uint64_t * fpstack, int pcstack_limit)
{
	thread_t        thread = current_thread();
	boolean_t       is64bit = proc_is64bit_data(current_proc());
	savearea_t      *regs;
	user_addr_t     pc, sp;
	volatile        uint16_t  *flags = (volatile uint16_t *) &cpu_core[CPU->cpu_id].cpuc_dtrace_flags;


	if (*flags & CPU_DTRACE_FAULT) {
		return;
	}

	if (pcstack_limit <= 0) {
		return;
	}

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (thread == NULL) {
		goto zero;
	}

	regs = (savearea_t *) find_user_regs(thread);
	if (regs == NULL) {
		goto zero;
	}

	*pcstack++ = (uint64_t)dtrace_proc_selfpid();
	pcstack_limit--;

	if (pcstack_limit <= 0) {
		return;
	}

	pc = get_saved_state_pc(regs);
	sp = get_saved_state_lr(regs);

#if 0                           /* XXX signal stack crawl */
	oldcontext = lwp->lwp_oldcontext;

	if (p->p_model == DATAMODEL_NATIVE) {
		s1 = sizeof(struct frame) + 2 * sizeof(long);
		s2 = s1 + sizeof(siginfo_t);
	} else {
		s1 = sizeof(struct frame32) + 3 * sizeof(int);
		s2 = s1 + sizeof(siginfo32_t);
	}
#endif

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t) pc;
		*fpstack++ = 0;
		pcstack_limit--;
		if (pcstack_limit <= 0) {
			return;
		}

		if (is64bit) {
			pc = dtrace_fuword64(sp);
		} else {
			pc = dtrace_fuword32(sp);
		}
	}
	while (pc != 0 && sp != 0) {
		*pcstack++ = (uint64_t) pc;
		*fpstack++ = sp;
		pcstack_limit--;
		if (pcstack_limit <= 0) {
			break;
		}

#if 0                           /* XXX signal stack crawl */
		if (oldcontext == sp + s1 || oldcontext == sp + s2) {
			if (p->p_model == DATAMODEL_NATIVE) {
				ucontext_t     *ucp = (ucontext_t *) oldcontext;
				greg_t         *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fulword(&gregs[REG_FP]);
				pc = dtrace_fulword(&gregs[REG_PC]);

				oldcontext = dtrace_fulword(&ucp->uc_link);
			} else {
				ucontext_t     *ucp = (ucontext_t *) oldcontext;
				greg_t         *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fuword32(&gregs[EBP]);
				pc = dtrace_fuword32(&gregs[EIP]);

				oldcontext = dtrace_fuword32(&ucp->uc_link);
			}
		} else
#endif
		{
			pc = dtrace_fuword64((sp + RETURN_OFFSET64));
			sp = dtrace_fuword64(sp);
		}

		/* Truncate ustack if the iterator causes fault. */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			break;
		}
	}

zero:
	while (pcstack_limit-- > 0) {
		*pcstack++ = 0ULL;
	}
}

#if XNU_MONITOR
static inline boolean_t
dtrace_frame_in_ppl_stack(struct frame * fp)
{
	return ((void *)fp >= pmap_stacks_start) &&
	       ((void *)fp < pmap_stacks_end);
}
#endif

void
dtrace_getpcstack(pc_t * pcstack, int pcstack_limit, int aframes,
    uint32_t * intrpc)
{
	struct frame   *fp = (struct frame *) __builtin_frame_address(0);
	struct frame   *nextfp, *minfp, *stacktop;
	int             depth = 0;
	int             on_intr;
#if XNU_MONITOR
	int             on_ppl_stack;
#endif
	int             last = 0;
	uintptr_t       pc;
	uintptr_t       caller = CPU->cpu_dtrace_caller;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0) {
		stacktop = (struct frame *) dtrace_get_cpu_int_stack_top();
	}
#if XNU_MONITOR
	else if ((on_ppl_stack = dtrace_frame_in_ppl_stack(fp))) {
		stacktop = (struct frame *) pmap_stacks_end;
	}
#endif
	else {
		stacktop = (struct frame *) (dtrace_get_kernel_stack(current_thread()) + kernel_stack_size);
	}

	minfp = fp;

	aframes++;

	if (intrpc != NULL && depth < pcstack_limit) {
		pcstack[depth++] = (pc_t) intrpc;
	}

	while (depth < pcstack_limit) {
		nextfp = *(struct frame **) fp;
		pc = *(uintptr_t *) (((uintptr_t) fp) + RETURN_OFFSET64);

		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				arm_saved_state_t *arm_kern_regs = (arm_saved_state_t *) find_kern_regs(current_thread());
				if (arm_kern_regs) {
					nextfp = (struct frame *)(saved_state64(arm_kern_regs)->fp);

#if XNU_MONITOR
					on_ppl_stack = dtrace_frame_in_ppl_stack(nextfp);

					if (on_ppl_stack) {
						minfp = pmap_stacks_start;
						stacktop = pmap_stacks_end;
					} else
#endif
					{
						vm_offset_t kstack_base = dtrace_get_kernel_stack(current_thread());

						minfp = (struct frame *)kstack_base;
						stacktop = (struct frame *)(kstack_base + kernel_stack_size);
					}

					on_intr = 0;

					if (nextfp <= minfp || nextfp >= stacktop) {
						last = 1;
					}
				} else {
					/*
					 * If this thread was on the interrupt stack, but did not
					 * take an interrupt (i.e, the idle thread), there is no
					 * explicit saved state for us to use.
					 */
					last = 1;
				}
			} else {
#if XNU_MONITOR
				if ((!on_ppl_stack) && dtrace_frame_in_ppl_stack(nextfp)) {
					/*
					 * We are switching from the kernel stack
					 * to the PPL stack.
					 */
					on_ppl_stack = 1;
					minfp = pmap_stacks_start;
					stacktop = pmap_stacks_end;
				} else if (on_ppl_stack) {
					/*
					 * We could be going from the PPL stack
					 * to the kernel stack.
					 */
					vm_offset_t kstack_base = dtrace_get_kernel_stack(current_thread());

					minfp = (struct frame *)kstack_base;
					stacktop = (struct frame *)(kstack_base + kernel_stack_size);

					if (nextfp <= minfp || nextfp >= stacktop) {
						last = 1;
					}
				} else
#endif
				{
					/*
					 * This is the last frame we can process; indicate
					 * that we should return after processing this frame.
					 */
					last = 1;
				}
			}
		}
		if (aframes > 0) {
			if (--aframes == 0 && caller != (uintptr_t)NULL) {
				/*
				 * We've just run out of artificial frames,
				 * and we have a valid caller -- fill it in
				 * now.
				 */
				ASSERT(depth < pcstack_limit);
				pcstack[depth++] = (pc_t) caller;
				caller = (uintptr_t)NULL;
			}
		} else {
			if (depth < pcstack_limit) {
				pcstack[depth++] = (pc_t) pc;
			}
		}

		if (last) {
			while (depth < pcstack_limit) {
				pcstack[depth++] = (pc_t) NULL;
			}
			return;
		}
		fp = nextfp;
		minfp = fp;
	}
}

uint64_t
dtrace_getarg(int arg, int aframes, dtrace_mstate_t *mstate, dtrace_vstate_t *vstate)
{
#pragma unused(arg, aframes)
	uint64_t val = 0;
	struct frame *fp = (struct frame *)__builtin_frame_address(0);
	uintptr_t *stack;
	uintptr_t pc;
	int i;

	/*
	 * A total of 8 arguments are passed via registers; any argument with
	 * index of 7 or lower is therefore in a register.
	 */
	int inreg = 7;

	for (i = 1; i <= aframes; ++i) {
		fp = fp->backchain;
#if __has_feature(ptrauth_returns)
		pc = (uintptr_t)ptrauth_strip((void*)fp->retaddr, ptrauth_key_return_address);
#else
		pc = fp->retaddr;
#endif

		if (dtrace_invop_callsite_pre != NULL
		    && pc > (uintptr_t) dtrace_invop_callsite_pre
		    && pc <= (uintptr_t) dtrace_invop_callsite_post) {
			/* fp points to frame of dtrace_invop() activation */
			fp = fp->backchain; /* to fbt_perfCallback activation */
			fp = fp->backchain; /* to sleh_synchronous activation */
			fp = fp->backchain; /* to fleh_synchronous activation */

			arm_saved_state_t       *tagged_regs = (arm_saved_state_t*) ((void*) &fp[1]);
			arm_saved_state64_t     *saved_state = saved_state64(tagged_regs);

			if (arg <= inreg) {
				/* the argument will be found in a register */
				stack = (uintptr_t*) &saved_state->x[0];
			} else {
				/* the argument will be found in the stack */
				fp = (struct frame*) saved_state->sp;
				stack = (uintptr_t*) &fp[1];
				arg -= (inreg + 1);
			}

			goto load;
		}
	}

	/*
	 * We know that we did not come through a trap to get into
	 * dtrace_probe() --  We arrive here when the provider has
	 * called dtrace_probe() directly.
	 * The probe ID is the first argument to dtrace_probe().
	 * We must advance beyond that to get the argX.
	 */
	arg++; /* Advance past probeID */

	if (arg <= inreg) {
		/*
		 * This shouldn't happen.  If the argument is passed in a
		 * register then it should have been, well, passed in a
		 * register...
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}

	arg -= (inreg + 1);
	stack = (uintptr_t*) &fp[1]; /* Find marshalled arguments */

load:
	if (dtrace_canload((uint64_t)(stack + arg), sizeof(uint64_t),
	    mstate, vstate)) {
		/* dtrace_probe arguments arg0 ... arg4 are 64bits wide */
		val = dtrace_load64((uint64_t)(stack + arg));
	}

	return val;
}

void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int which,
    int fltoffs, int fault, uint64_t illval)
{
	/* XXX ARMTODO */
	/*
	 * For the case of the error probe firing lets
	 * stash away "illval" here, and special-case retrieving it in DIF_VARIABLE_ARG.
	 */
	state->dts_arg_error_illval = illval;
	dtrace_probe( dtrace_probeid_error, (uint64_t)(uintptr_t)state, epid, which, fltoffs, fault );
}

void
dtrace_toxic_ranges(void (*func)(uintptr_t base, uintptr_t limit))
{
	/* XXX ARMTODO check copied from ppc/x86*/
	/*
	 * "base" is the smallest toxic address in the range, "limit" is the first
	 * VALID address greater than "base".
	 */
	func(0x0, VM_MIN_KERNEL_ADDRESS);
	if (VM_MAX_KERNEL_ADDRESS < ~(uintptr_t)0) {
		func(VM_MAX_KERNEL_ADDRESS + 1, ~(uintptr_t)0);
	}
}

void
dtrace_flush_caches(void)
{
	/* TODO There were some problems with flushing just the cache line that had been modified.
	 * For now, we'll flush the entire cache, until we figure out how to flush just the patched block.
	 */
	FlushPoU_Dcache();
	InvalidatePoU_Icache();
}
