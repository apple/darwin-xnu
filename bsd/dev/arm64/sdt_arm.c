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

#include <kern/cpu_data.h>
#include <kern/debug.h>
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

			dtrace_probe(sdt->sdp_id, get_saved_state_reg(regs, 0), get_saved_state_reg(regs, 1),
			    get_saved_state_reg(regs, 2), get_saved_state_reg(regs, 3), get_saved_state_reg(regs, 4));

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
	 * A total of eight arguments are passed via registers;  any argument
	 * with an index of 7 or lower is therefore in a register.
	 */

	int inreg = 7;

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
			fp = fp->backchain; /* fbt_perfCallback  */
			fp = fp->backchain; /* sleh_synchronous */
			fp = fp->backchain; /* fleh_synchronous */

			arm_saved_state_t *tagged_regs = (arm_saved_state_t *)((uintptr_t *)&fp[1]);
			arm_saved_state64_t *saved_state = saved_state64(tagged_regs);

			if (argno <= inreg) {
				/* The argument will be in a register */
				stack = (uintptr_t *)&saved_state->x[0];
			} else {
				/* The argument will be found on the stack */
				fp = (struct frame *)(saved_state->sp);
				stack = (uintptr_t *)&fp[0]; /* Find marshalled arguments */
				argno -= (inreg + 1);
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
