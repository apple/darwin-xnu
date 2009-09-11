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
#include <machine/cpu_capabilities.h>

extern dtrace_id_t      dtrace_probeid_error;   /* special ERROR probe */

void
dtrace_probe_error(dtrace_state_t *state, dtrace_epid_t epid, int which,
    int fltoffs, int fault, uint64_t illval)
{
	/*
	 * dtrace_getarg() is a lost cause on PPC. For the case of the error probe firing lets
	 * stash away "illval" here, and special-case retrieving it in DIF_VARIABLE_ARG.
	 */
	state->dts_arg_error_illval = illval;
	dtrace_probe( dtrace_probeid_error, (uint64_t)(uintptr_t)state, epid, which, fltoffs, fault );
}

/*
 * Atomicity and synchronization
 */
void
dtrace_membar_producer(void)
{
	__asm__ volatile("sync");
}

void
dtrace_membar_consumer(void)
{
	__asm__ volatile("isync");
}

/*
 * Interrupt manipulation
 * XXX dtrace_getipl() can be called from probe context.
 */
int
dtrace_getipl(void)
{
	return (ml_at_interrupt_context() ? 1: 0);
}

/*
 * MP coordination
 */
typedef void (*broadcastFunc) (uint32_t);

int32_t cpu_broadcast(uint32_t *, broadcastFunc, uint32_t); /* osfmk/ppc/machine_cpu.h */

typedef struct xcArg {
	processorid_t cpu;
	dtrace_xcall_t f;
	void *arg;
	uint32_t waitVar;
} xcArg_t;

static void
xcRemote( uint32_t foo )
{
	xcArg_t *pArg = (xcArg_t *)foo;
	
	if ( pArg->cpu == CPU->cpu_id || pArg->cpu == DTRACE_CPUALL ) {
		(pArg->f)(pArg->arg);
	}
	
    if(!hw_atomic_sub(&(pArg->waitVar), 1)) {      /* Drop the wait count */
        thread_wakeup((event_t)&(pArg->waitVar));  /* If we were the last, wake up the signaller */
    }
}

/*
 * dtrace_xcall() is not called from probe context.
 */
void
dtrace_xcall(processorid_t cpu, dtrace_xcall_t f, void *arg)
{
	xcArg_t xcArg;
	
	/* Talking to ourselves, are we? */
	if ( cpu == CPU->cpu_id ) {
		(*f)(arg);
		return;
	}
	
	if ( cpu == DTRACE_CPUALL ) {
		(*f)(arg);
	}
	
	xcArg.cpu = cpu;
	xcArg.f = f;
	xcArg.arg = arg;
    xcArg.waitVar = 0;

	(void)cpu_broadcast(&(xcArg.waitVar), xcRemote, (uint32_t)&xcArg);
}

/*
 * Runtime and ABI
 */
uint64_t
dtrace_getreg(struct regs *savearea, uint_t reg)
{
	ppc_saved_state_t *regs = (ppc_saved_state_t *)savearea;
    uint64_t mask = (_cpu_capabilities & k64Bit) ? 0xffffffffffffffffULL : 0x00000000ffffffffULL;
	
	/* See osfmk/ppc/savearea.h */
	if (reg > 68) { /* beyond mmcr2 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}
	
	switch (reg) {
		/* First 38 registers are saved to 64 bits r0-r31, srr0, srr1, xer, lr, ctr, dar. */
		default:
			return (((uint64_t *)(&(regs->save_r0)))[reg]) & mask;

		/* Handle the 32-bit registers */
		case 38: case 39: case 40: case 41: /* cr, dsisr, exception, vrsave */
		case 42: case 43: case 44: case 45: /* vscr[4] */
		case 46: case 47: case 48: case 49:     /* fpscrpad, fpscr, save_1d8[2] */
		case 50: case 51: case 52: case 53: /* save_1E0[8] */
		case 54: case 55: case 56: case 57: 
		case 58: case 59: case 60: case 61: /* save_pmc[8] */
		case 62: case 63: case 64: case 65: 
			return (uint64_t)(((unsigned int *)(&(regs->save_cr)))[reg - 38]);
			
		case 66:
			return regs->save_mmcr0 & mask;
		case 67:
			return regs->save_mmcr1 & mask;
		case 68:
			return regs->save_mmcr2 & mask;
	}
}

#define RETURN_OFFSET 8
#define RETURN_OFFSET64 16
#define REGPC save_srr0
#define REGSP save_r1

/*
 * XXX dtrace_getustack_common() can be called from probe context.
 */
static int
dtrace_getustack_common(uint64_t *pcstack, int pcstack_limit, user_addr_t pc,
    user_addr_t sp)
{
#if 0
	volatile uint16_t *flags =
	    (volatile uint16_t *)&cpu_core[CPU->cpu_id].cpuc_dtrace_flags;

	uintptr_t oldcontext = lwp->lwp_oldcontext; /* XXX signal stack crawl*/
	size_t s1, s2;
#endif
	int ret = 0;
	boolean_t is64Bit = proc_is64bit(current_proc());

	ASSERT(pcstack == NULL || pcstack_limit > 0);
	
#if 0 /* XXX signal stack crawl*/
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

#if 0 /* XXX signal stack crawl*/
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
	}

	return (ret);
}

void
dtrace_getupcstack(uint64_t *pcstack, int pcstack_limit)
{
	thread_t thread = current_thread();
	ppc_saved_state_t *regs;
	user_addr_t pc, sp;
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

	regs = (ppc_saved_state_t *)find_user_regs(thread);
	if (regs == NULL)
		goto zero;
		
	*pcstack++ = (uint64_t)proc_selfpid();
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	pc = regs->REGPC;
	sp = regs->REGSP;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		*pcstack++ = (uint64_t)pc;
		pcstack_limit--;
		if (pcstack_limit <= 0)
			return;

		pc = regs->save_lr;
	}
	
	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_USTACK_FP)) {
		/*
		 * If the ustack fp flag is set, the stack frame from sp to
		 * fp contains no valid call information. Start with the fp.
		 */
		if (is64Bit)
			sp = dtrace_fuword64(sp);
		else
			sp = (user_addr_t)dtrace_fuword32(sp);
	}

	n = dtrace_getustack_common(pcstack, pcstack_limit, pc, sp);
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
	ppc_saved_state_t *regs;
	user_addr_t pc, sp;
	int n = 0;
	boolean_t is64Bit = proc_is64bit(current_proc());

	if (thread == NULL)
		return 0;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return (-1);

	regs = (ppc_saved_state_t *)find_user_regs(thread);
	if (regs == NULL)
		return 0;

	pc = regs->REGPC;
	sp = regs->REGSP;

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_ENTRY)) {
		n++;
		pc = regs->save_lr;
	}
	
	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_USTACK_FP)) {
		/*
		 * If the ustack fp flag is set, the stack frame from sp to
		 * fp contains no valid call information. Start with the fp.
		 */
		if (is64Bit)
			sp = dtrace_fuword64(sp);
		else
			sp = (user_addr_t)dtrace_fuword32(sp);
	}

	n += dtrace_getustack_common(NULL, 0, pc, sp);

	return (n);
}

void
dtrace_getufpstack(uint64_t *pcstack, uint64_t *fpstack, int pcstack_limit)
{
	thread_t thread = current_thread();
	ppc_saved_state_t *regs;
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

	regs = (ppc_saved_state_t *)find_user_regs(thread);
	if (regs == NULL)
		goto zero;
		
	*pcstack++ = (uint64_t)proc_selfpid();
	pcstack_limit--;

	if (pcstack_limit <= 0)
		return;

	pc = regs->REGPC;
	sp = regs->REGSP;
	
#if 0 /* XXX signal stack crawl*/
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

		/*
		 * XXX This is wrong, but we do not yet support stack helpers.
		 */
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

#if 0 /* XXX signal stack crawl*/
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
	}

zero:
	while (pcstack_limit-- > 0)
		*pcstack++ = 0;
}

void
dtrace_getpcstack(pc_t *pcstack, int pcstack_limit, int aframes,
    uint32_t *intrpc)
{
	struct frame *fp = (struct frame *)__builtin_frame_address(0);
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int last = 0;
	uintptr_t pc;
	uintptr_t caller = CPU->cpu_dtrace_caller;
	int on_intr;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)dtrace_get_cpu_int_stack_top();
	else
		stacktop = (struct frame *)(dtrace_get_kernel_stack(current_thread()) + kernel_stack_size);

	minfp = fp;

	aframes++;

	if (intrpc != NULL && depth < pcstack_limit)
		pcstack[depth++] = (pc_t)intrpc;

	while (depth < pcstack_limit) {
		nextfp = *(struct frame **)fp;
		pc = *(uintptr_t *)(((uintptr_t)fp) + RETURN_OFFSET);

		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				vm_offset_t kstack_base = dtrace_get_kernel_stack(current_thread());

				minfp = (struct frame *)kstack_base;
				stacktop = (struct frame *)(kstack_base + kernel_stack_size);

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

uint64_t
dtrace_getarg(int arg, int aframes)
{
#pragma unused(arg,aframes)
	return 0xfeedfacedeafbeadLL; /* XXX Only called for arg >= 5 */
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
	if (VM_MAX_KERNEL_ADDRESS < ~(uintptr_t)0)
			func(VM_MAX_KERNEL_ADDRESS + 1, ~(uintptr_t)0);
}

extern void *mapping_phys_lookup(ppnum_t, unsigned int *);

