/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)sdt.c	1.9	08/07/01 SMI" */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#define MACH__POSIX_C_SOURCE_PRIVATE 1 /* pulls in suitable savearea from mach/ppc/thread_status.h */
#include <kern/cpu_data.h>
#include <kern/thread.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>

#include <sys/dtrace_glue.h>

#include <sys/sdt_impl.h>

extern sdt_probe_t      **sdt_probetab;

/*ARGSUSED*/
int
sdt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t eax)
{
#pragma unused(eax)
	sdt_probe_t *sdt = sdt_probetab[SDT_ADDR2NDX(addr)];

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t)sdt->sdp_patchpoint == addr) {
			x86_saved_state64_t *regs = (x86_saved_state64_t *)stack;

			dtrace_probe(sdt->sdp_id, regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8);

			return (DTRACE_INVOP_NOP);
		}
	}

	return (0);
}


struct frame {
    struct frame *backchain;
    uintptr_t retaddr;
};

/*ARGSUSED*/
uint64_t
sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg, id, parg)    
	uint64_t val;
	struct frame *fp = (struct frame *)__builtin_frame_address(0);
	uintptr_t *stack;
	uintptr_t pc;
	int i;

    /*
     * A total of 6 arguments are passed via registers; any argument with
     * index of 5 or lower is therefore in a register.
     */
    int inreg = 5;

	for (i = 1; i <= aframes; i++) {
		fp = fp->backchain;
		pc = fp->retaddr;

		if (dtrace_invop_callsite_pre != NULL
			&& pc  >  (uintptr_t)dtrace_invop_callsite_pre
			&& pc  <= (uintptr_t)dtrace_invop_callsite_post) {
			/*
			 * In the case of x86_64, we will use the pointer to the
			 * save area structure that was pushed when we took the
			 * trap.  To get this structure, we must increment
			 * beyond the frame structure. If the
			 * argument that we're seeking is passed on the stack,
			 * we'll pull the true stack pointer out of the saved
			 * registers and decrement our argument by the number
			 * of arguments passed in registers; if the argument
			 * we're seeking is passed in regsiters, we can just
			 * load it directly.
			 */

			/* fp points to frame of dtrace_invop() activation. */
			fp = fp->backchain; /* to fbt_perfcallback() activation. */
			fp = fp->backchain; /* to kernel_trap() activation. */
			fp = fp->backchain; /* to trap_from_kernel() activation. */
			
			x86_saved_state_t   *tagged_regs = (x86_saved_state_t *)&fp[1];
			x86_saved_state64_t *saved_state = saved_state64(tagged_regs);

			if (argno <= inreg) {
				stack = (uintptr_t *)(void*)&saved_state->rdi;
			} else {
				fp = (struct frame *)(saved_state->isf.rsp);
				stack = (uintptr_t *)&fp[0]; /* Find marshalled
								arguments */
				argno -= (inreg +1);
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
	argno++; /* Advance past probeID */

	if (argno <= inreg) {
		/*
		 * This shouldn't happen.  If the argument is passed in a
		 * register then it should have been, well, passed in a
		 * register...
		 */
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return (0);
	}

	argno -= (inreg + 1);
	stack = (uintptr_t *)&fp[1]; /* Find marshalled arguments */

load:
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	/* dtrace_probe arguments arg0 ... arg4 are 64bits wide */
	val = (uint64_t)(*(((uintptr_t *)stack) + argno));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return (val);
}
    
