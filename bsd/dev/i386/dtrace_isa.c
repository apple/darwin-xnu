/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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

#define MACH__POSIX_C_SOURCE_PRIVATE 1 /* pulls in suitable savearea from mach/ppc/thread_status.h */
#include <kern/thread.h>
#include <mach/thread_status.h>

typedef x86_saved_state_t savearea_t;

#include <stdarg.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <libkern/OSAtomic.h>
#include <kern/thread_call.h>
#include <kern/task.h>
#include <kern/sched_prim.h>
#include <miscfs/devfs/devfs.h>
#include <mach/vm_param.h>

extern dtrace_id_t      dtrace_probeid_error;   /* special ERROR probe */

void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int which,
    int fault, int fltoffs, uint64_t illval)
{
    /*
     * For the case of the error probe firing lets
     * stash away "illval" here, and special-case retrieving it in DIF_VARIABLE_ARG.
     */
    state->dts_arg_error_illval = illval;
    dtrace_probe( dtrace_probeid_error, (uint64_t)(uintptr_t)state, epid, which, fault, fltoffs );
}

/*
 * Atomicity and synchronization
 */
void
dtrace_membar_producer(void)
{
	__asm__ volatile("sfence");
}

void
dtrace_membar_consumer(void)
{
	__asm__ volatile("lfence");
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
	return (ml_at_interrupt_context() ? 1: 0);
}

/*
 * MP coordination
 */

extern void mp_broadcast(
       void (*action_func)(void *),
       void *arg);

typedef struct xcArg {
	processorid_t cpu;
	dtrace_xcall_t f;
	void *arg;
} xcArg_t;

static void
xcRemote( void *foo )
{
	xcArg_t *pArg = (xcArg_t *)foo;
	
	if ( pArg->cpu == CPU->cpu_id || pArg->cpu == DTRACE_CPUALL ) {
		(pArg->f)(pArg->arg);
	}
}

/*
 * dtrace_xcall() is not called from probe context.
 */
void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t f, void *arg)
{
	xcArg_t xcArg;
	
	xcArg.cpu = cpu;
	xcArg.f = f;
	xcArg.arg = arg;

	mp_broadcast( xcRemote, (void *)&xcArg);
}

/*
 * Runtime and ABI
 */
extern greg_t
dtrace_getfp(void)
{
	return (greg_t)__builtin_frame_address(0);
}

uint64_t
dtrace_getreg(struct regs *savearea, uint_t reg)
{
	boolean_t is64Bit = proc_is64bit(current_proc());
	x86_saved_state_t *regs = (x86_saved_state_t *)savearea;
	
	if (is64Bit) {
		/* beyond register SS */
		if (reg > x86_SAVED_STATE64_COUNT - 1) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return (0);
		}
		return ((uint64_t *)(&(regs->ss_64.gs)))[reg];
	} else {
		/* beyond register SS */
		if (reg > x86_SAVED_STATE32_COUNT - 1) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return (0);
		}
		return (uint64_t)((unsigned int *)(&(regs->ss_32.gs)))[reg];
	}
	
}

#define RETURN_OFFSET 4
#define RETURN_OFFSET64 8

static int
dtrace_getustack_common(uint64_t *pcstack, int pcstack_limit, user_addr_t pc,
    user_addr_t sp)
{
#if 0
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	uintptr_t oldcontext = lwp->lwp_oldcontext; /* XXX signal stack crawl */
	size_t s1, s2;
#endif
	int ret = 0;
	boolean_t is64Bit = proc_is64bit(current_proc());

	ASSERT(pcstack == NULL || pcstack_limit > 0);
	
#if 0 /* XXX signal stack crawl */
	if (p->p_model == DATAMODEL_NATIVE) {
		s1 = sizeof (struct frame) + 2 * sizeof (long);
		s2 = s1 + sizeof (siginfo_t);
	} else {
		s1 = sizeof (struct frame32) + 3 * sizeof (int);
		s2 = s1 + sizeof (siginfo32_t);
	}
#endif

	while (pc != 0) {
		ret++;
		if (pcstack != NULL) {
			*pcstack++ = (uint64_t)pc;
			pcstack_limit--;
			if (pcstack_limit <= 0)
				break;
		}

		if (sp == 0)
			break;

#if 0 /* XXX signal stack crawl */
		if (oldcontext == sp + s1 || oldcontext == sp + s2) {
			if (p->p_model == DATAMODEL_NATIVE) {
				ucontext_t *ucp = (ucontext_t *)oldcontext;
				greg_t *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fulword(&gregs[REG_FP]);
				pc = dtrace_fulword(&gregs[REG_PC]);

				oldcontext = dtrace_fulword(&ucp->uc_link);
			} else {
				ucontext32_t *ucp = (ucontext32_t *)oldcontext;
				greg32_t *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fuword32(&gregs[EBP]);
				pc = dtrace_fuword32(&gregs[EIP]);

				oldcontext = dtrace_fuword32(&ucp->uc_link);
			}
		} 
		else
#endif
		{
			if (is64Bit) {
				pc = dtrace_fuword64((sp + RETURN_OFFSET64));
				sp = dtrace_fuword64(sp);
			} else {
				pc = dtrace_fuword32((sp + RETURN_OFFSET));
				sp = dtrace_fuword32(sp);
			}
		}

#if 0 /* XXX */
		/*
		 * This is totally bogus:  if we faulted, we're going to clear
		 * the fault and break.  This is to deal with the apparently
		 * broken Java stacks on x86.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			break;
		}
#endif
	}

	return (ret);
}

void
dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	thread_t thread = current_thread();
	x86_saved_state_t *regs;
	user_addr_t pc, sp, fp;
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
	int n;
	boolean_t is64Bit = proc_is64bit(current_proc());

	if (*flags & CPU_DTRACE_FAULT)
		return;

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (thread == NULL)
		goto zero;

	regs = (x86_saved_state_t *)find_user_regs(thread);
	if (regs == NULL)
		goto zero;
		
	*pcstack++ = (uint64_t)proc_selfpid();
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	if (is64Bit) {
		pc = regs->ss_64.isf.rip;
		sp = regs->ss_64.isf.rsp;
		fp = regs->ss_64.rbp;
	} else {
		pc = regs->ss_32.eip;
		sp = regs->ss_32.uesp;
		fp = regs->ss_32.ebp;
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t)pc;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;

		if (is64Bit)
			pc = dtrace_fuword64(sp);
		else
			pc = dtrace_fuword32(sp);
	}

	/*
	 * Note that unlike ppc, the x86 code does not use
	 * CPU_DTRACE_USTACK_FP. This is because x86 always
	 * traces from the fp, even in syscall/profile/fbt
	 * providers.
	 */
	n = dtrace_getustack_common(pcstack, pcstack_limit, pc, fp);
	ASSERT(n >= 0);
	ASSERT(n <= pcstack_limit);

	pcstack += n;
	pcstack_limit -= n;

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
}

int
dtrace_getustackdepth(void)
{
	thread_t thread = current_thread();
	x86_saved_state_t *regs;
	user_addr_t pc, sp, fp;
	int n = 0;
	boolean_t is64Bit = proc_is64bit(current_proc());

	if (thread == NULL)
		return 0;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (-1);

	regs = (x86_saved_state_t *)find_user_regs(thread);
	if (regs == NULL)
		return 0;

	if (is64Bit) {
		pc = regs->ss_64.isf.rip;
		sp = regs->ss_64.isf.rsp;
		fp = regs->ss_64.rbp;
	} else {
		pc = regs->ss_32.eip;
		sp = regs->ss_32.uesp;
		fp = regs->ss_32.ebp;
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		n++;

		if (is64Bit)
			pc = dtrace_fuword64(sp);
		else
			pc = dtrace_fuword32(sp);
	}

	/*
	 * Note that unlike ppc, the x86 code does not use
	 * CPU_DTRACE_USTACK_FP. This is because x86 always
	 * traces from the fp, even in syscall/profile/fbt
	 * providers.
	 */

	n += dtrace_getustack_common(NULL, 0, pc, fp);

	return (n);
}

void
dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack, int pcstack_limit)
{
	thread_t thread = current_thread();
	savearea_t *regs;
	user_addr_t pc, sp;
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;
#if 0
	uintptr_t oldcontext;
	size_t s1, s2;
#endif
	boolean_t is64Bit = proc_is64bit(current_proc());

	if (*flags & CPU_DTRACE_FAULT)
		return;

	if (pcstack_limit <= 0)
		return;

	/*
	 * If there's no user context we still need to zero the stack.
	 */
	if (thread == NULL)
		goto zero;

	regs = (savearea_t *)find_user_regs(thread);
	if (regs == NULL)
		goto zero;
		
	*pcstack++ = (uint64_t)proc_selfpid();
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	pc = regs->ss_32.eip;
	sp = regs->ss_32.ebp;
	
#if 0 /* XXX signal stack crawl */
	oldcontext = lwp->lwp_oldcontext;

	if (p->p_model == DATAMODEL_NATIVE) {
		s1 = sizeof (struct frame) + 2 * sizeof (long);
		s2 = s1 + sizeof (siginfo_t);
	} else {
		s1 = sizeof (struct frame32) + 3 * sizeof (int);
		s2 = s1 + sizeof (siginfo32_t);
	}
#endif

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t)pc;
		*fpstack++ = 0;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;

		if (is64Bit)
			pc = dtrace_fuword64(sp);
		else
			pc = dtrace_fuword32(sp);
	}

	while (pc != 0) {
		*pcstack++ = (uint64_t)pc;
		*fpstack++ = sp;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			break;

		if (sp == 0)
			break;

#if 0 /* XXX signal stack crawl */
		if (oldcontext == sp + s1 || oldcontext == sp + s2) {
			if (p->p_model == DATAMODEL_NATIVE) {
				ucontext_t *ucp = (ucontext_t *)oldcontext;
				greg_t *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fulword(&gregs[REG_FP]);
				pc = dtrace_fulword(&gregs[REG_PC]);

				oldcontext = dtrace_fulword(&ucp->uc_link);
			} else {
				ucontext_t *ucp = (ucontext_t *)oldcontext;
				greg_t *gregs = ucp->uc_mcontext.gregs;

				sp = dtrace_fuword32(&gregs[EBP]);
				pc = dtrace_fuword32(&gregs[EIP]);

				oldcontext = dtrace_fuword32(&ucp->uc_link);
			}
		} 
		else
#endif
		{
			if (is64Bit) {
				pc = dtrace_fuword64((sp + RETURN_OFFSET64));
				sp = dtrace_fuword64(sp);
			} else {
				pc = dtrace_fuword32((sp + RETURN_OFFSET));
				sp = dtrace_fuword32(sp);
			}
		}

#if 0 /* XXX */
		/*
		 * This is totally bogus:  if we faulted, we're going to clear
		 * the fault and break.  This is to deal with the apparently
		 * broken Java stacks on x86.
		 */
		if (*flags & CPU_DTRACE_FAULT) {
			*flags &= ~CPU_DTRACE_FAULT;
			break;
		}
#endif
	}

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
}

void
dtrace_getpcstack(pc_t *pcstack, int pcstack_limit, int aframes,
		  uint32_t *intrpc)
{
	struct frame *fp = (struct frame *)dtrace_getfp();
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int last = 0;
	uintptr_t pc;
	uintptr_t caller = CPU->cpu_dtrace_caller;
	int on_intr;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)dtrace_get_cpu_int_stack_top();
	else
		stacktop = (struct frame *)(dtrace_get_kernel_stack(current_thread()) + KERNEL_STACK_SIZE);

	minfp = fp;

	aframes++;

	if (intrpc != NULL && depth < pcstack_limit)
		pcstack[depth++] = (pc_t)intrpc;

	while (depth < pcstack_limit) {
		nextfp = *(struct frame **)fp;
		pc = *(uintptr_t *)(((uint32_t)fp) + RETURN_OFFSET);

		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				vm_offset_t kstack_base = dtrace_get_kernel_stack(current_thread());

				minfp = (struct frame *)kstack_base;
				stacktop = (struct frame *)(kstack_base + KERNEL_STACK_SIZE);

				on_intr = 0;
				continue;
			}
			/*
			 * This is the last frame we can process; indicate
			 * that we should return after processing this frame.
			 */
			last = 1;
		}

		if (aframes > 0) {
			if (--aframes == 0 && caller != 0) {
				/*
				 * We've just run out of artificial frames,
				 * and we have a valid caller -- fill it in
				 * now.
				 */
				ASSERT(depth < pcstack_limit);
				pcstack[depth++] = (pc_t)caller;
				caller = 0;
			}
		} else {
			if (depth < pcstack_limit)
				pcstack[depth++] = (pc_t)pc;
		}

		if (last) {
			while (depth < pcstack_limit)
				pcstack[depth++] = 0;
			return;
		}

		fp = nextfp;
		minfp = fp;
	}
}

struct frame {
	struct frame *backchain;
	uintptr_t retaddr;
};

uint64_t
dtrace_getarg(int arg, int aframes)
{
	uint64_t val;
	struct frame *fp = (struct frame *)dtrace_getfp();
	uintptr_t *stack;
	uintptr_t pc;
	int i;

	for (i = 1; i <= aframes; i++) {
		fp = fp->backchain;
		pc = fp->retaddr;

		if (pc  == (uintptr_t)dtrace_invop_callsite) {
			/*
			 * If we pass through the invalid op handler, we will
			 * use the pointer that it passed to the stack as the
			 * second argument to dtrace_invop() as the pointer to
			 * the frame we're hunting for.
			 */

			stack = (uintptr_t *)&fp[1]; /* Find marshalled arguments */
			fp = (struct frame *)stack[1]; /* Grab *second* argument */
			stack = (uintptr_t *)&fp[1]; /* Find marshalled arguments */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			val = (uint64_t)(stack[arg]);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
			return val;
		}
	}

	/*
	 * Arrive here when provider has called dtrace_probe directly.
	 */
	stack = (uintptr_t *)&fp[1]; /* Find marshalled arguments */
	stack++; /* Advance past probeID */

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	val = *(((uint64_t *)stack) + arg); /* dtrace_probe arguments arg0 .. arg4 are 64bits wide */
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return (val);
}

/*
 * Load/Store Safety
 */
void
dtrace_toxic_ranges(void (*func)(uintptr_t base, uintptr_t limit))
{
	/*
	 * "base" is the smallest toxic address in the range, "limit" is the first
	 * VALID address greater than "base".
	 */
	func(0x0, VM_MIN_KERNEL_ADDRESS);
	func(VM_MAX_KERNEL_ADDRESS + 1, ~(uintptr_t)0);
}

extern boolean_t pmap_valid_page(ppnum_t pn);

boolean_t
dtxnu_is_RAM_page(ppnum_t pn)
{
	return pmap_valid_page(pn);
}

