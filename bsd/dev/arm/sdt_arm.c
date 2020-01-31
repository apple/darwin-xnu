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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)sdt.c	1.6	06/03/24 SMI" */

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

int
sdt_invop(__unused uintptr_t addr, __unused uintptr_t *stack, __unused uintptr_t eax)
{
#pragma unused(eax)
	sdt_probe_t *sdt = sdt_probetab[SDT_ADDR2NDX(addr)];

	for (; sdt != NULL; sdt = sdt->sdp_hashnext) {
		if ((uintptr_t) sdt->sdp_patchpoint == addr) {
			struct arm_saved_state* regs = (struct arm_saved_state*) stack;
			uintptr_t stack4 = *((uintptr_t*) regs->sp);

			dtrace_probe(sdt->sdp_id, regs->r[0], regs->r[1], regs->r[2], regs->r[3], stack4);

			return DTRACE_INVOP_NOP;
		}
	}

	return 0;
}

struct frame {
	struct frame *backchain;
	uintptr_t retaddr;
};

/*ARGSUSED*/
uint64_t
sdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg,id,parg)     /* __APPLE__ */
	uint64_t val = 0;
	struct frame *fp = (struct frame *)__builtin_frame_address(0);
	uintptr_t *stack;
	uintptr_t pc;
	int i;

	/*
	 * On ARM, up to four args are passed via registers; r0,r1,r2,r3
	 * So coming into this function, arg >= 4 should be on the stack.
	 * e.g. arg==5 refers to the 6th arg passed to the probed function.
	 */
	int inreg = 4;

	for (i = 1; i <= aframes; i++) {
		fp = fp->backchain;
		pc = fp->retaddr;

		if (dtrace_invop_callsite_pre != NULL
		    && pc > (uintptr_t)dtrace_invop_callsite_pre
		    && pc <= (uintptr_t)dtrace_invop_callsite_post) {
			/*
			 * When we pass through the invalid op handler,
			 * we expect to find the save area structure,
			 * pushed on the stack where we took the trap.
			 * If the argument we seek is passed in a register, then
			 * we can load it directly from this saved area.
			 * If the argument we seek is passed on the stack, then
			 * we increment the frame pointer further, to find the
			 * pushed args
			 */

			/* fp points to the dtrace_invop activation */
			fp = fp->backchain; /* to the fbt_perfCallback activation */
			fp = fp->backchain; /* to the sleh_undef activation */

#if __BIGGEST_ALIGNMENT__ > 4
			/**
			 * rdar://problem/24228656: On armv7k, the stack is realigned in sleh_undef2 to
			 * be 16-bytes aligned and the old value is pushed to
			 * the stack, so we retrieve it from here
			 */
			arm_saved_state_t *saved_state = (arm_saved_state_t *)(uintptr_t*)*((uintptr_t *)&fp[1]);
#else
			arm_saved_state_t *saved_state = (arm_saved_state_t *)((uintptr_t *)&fp[1]);
#endif
			if (argno <= inreg) {
				/* For clarity only... should not get here */
				stack = (uintptr_t *)&saved_state->r[0];
			} else {
				fp = (struct frame *)(saved_state->sp);
				stack = (uintptr_t *)&fp[0]; /* Find marshalled arguments */
				argno -= inreg;
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
		return 0;
	}

	argno -= (inreg + 1);
	stack = (uintptr_t *)&fp[1]; /* Find marshalled arguments */

load:
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	/* dtrace_probe arguments arg0 .. arg4 are 64bits wide */
	val = (uint64_t)(*(((uintptr_t *)stack) + argno));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
	return val;
}
