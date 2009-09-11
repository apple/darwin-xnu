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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * #pragma ident	"@(#)dtrace_subr.c	1.16	07/09/18 SMI"
 */

#include <sys/dtrace.h>
#include <sys/dtrace_glue.h>
#include <sys/dtrace_impl.h>
#include <sys/fasttrap.h>
#include <sys/vm.h>
#include <sys/user.h>
#include <sys/kauth.h>
#include <kern/debug.h>

int (*dtrace_pid_probe_ptr)(x86_saved_state_t *);
int (*dtrace_return_probe_ptr)(x86_saved_state_t *);

/*
 * HACK! There doesn't seem to be an easy way to include trap.h from
 * here. FIXME!
 */
#define	T_INT3			3		/* int 3 instruction */
#define T_DTRACE_RET		0x7f		/* DTrace pid return */

kern_return_t
dtrace_user_probe(x86_saved_state_t *);

kern_return_t
dtrace_user_probe(x86_saved_state_t *regs)
{
	x86_saved_state64_t *regs64;
	x86_saved_state32_t *regs32;
        int trapno;

	/*
	 * FIXME!
	 *
	 * The only call path into this method is always a user trap.
	 * We don't need to test for user trap, but should assert it.
	 */
	boolean_t user_mode = TRUE;

        if (is_saved_state64(regs) == TRUE) {
                regs64 = saved_state64(regs);
		regs32 = NULL;
                trapno = regs64->isf.trapno;
                user_mode = TRUE; // By default, because xnu is 32 bit only
        } else {
		regs64 = NULL;
                regs32 = saved_state32(regs);
                if (regs32->cs & 0x03) user_mode = TRUE;
                trapno = regs32->trapno;
        }

	lck_rw_t *rwp;
	struct proc *p = current_proc();

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
	if (user_mode /*|| (rp->r_ps & PS_VM)*/) {
		/*
		 * DTrace accesses t_cred in probe context.  t_cred
		 * must always be either NULL, or point to a valid,
		 * allocated cred structure.
		 */
		kauth_cred_uthread_update(uthread, p);
	}

	if (trapno == T_DTRACE_RET) {
		uint8_t step = uthread->t_dtrace_step;
		uint8_t ret = uthread->t_dtrace_ret;
		user_addr_t npc = uthread->t_dtrace_npc;

		if (uthread->t_dtrace_ast) {
			printf("dtrace_user_probe() should be calling aston()\n");
			// aston(uthread);
			// uthread->t_sig_check = 1;
		}

		/*
		 * Clear all user tracing flags.
		 */
		uthread->t_dtrace_ft = 0;

		/*
		 * If we weren't expecting to take a return probe trap, kill
		 * the process as though it had just executed an unassigned
		 * trap instruction.
		 */
		if (step == 0) {
			/*
			 * APPLE NOTE: We're returning KERN_FAILURE, which causes 
			 * the generic signal handling code to take over, which will effectively
			 * deliver a EXC_BAD_INSTRUCTION to the user process.
			 */
	 		return KERN_FAILURE;
		}

		/*
		 * If we hit this trap unrelated to a return probe, we're
		 * just here to reset the AST flag since we deferred a signal
		 * until after we logically single-stepped the instruction we
		 * copied out.
		 */
		if (ret == 0) {
			if (regs64) {
				regs64->isf.rip = npc;
			} else {
				regs32->eip = npc;
			}
			return KERN_SUCCESS;
		}

		/*
		 * We need to wait until after we've called the
		 * dtrace_return_probe_ptr function pointer to set %pc.
		 */
		rwp = &CPU->cpu_ft_lock;
		lck_rw_lock_shared(rwp);

		if (dtrace_return_probe_ptr != NULL)
			(void) (*dtrace_return_probe_ptr)(regs);
		lck_rw_unlock_shared(rwp);

		if (regs64) {
			regs64->isf.rip = npc;
		} else {
			regs32->eip = npc;
		}

		return KERN_SUCCESS;
	} else if (trapno == T_INT3) {
		uint8_t instr, instr2;
		rwp = &CPU->cpu_ft_lock;

		/*
		 * The DTrace fasttrap provider uses the breakpoint trap
		 * (int 3). We let DTrace take the first crack at handling
		 * this trap; if it's not a probe that DTrace knowns about,
		 * we call into the trap() routine to handle it like a
		 * breakpoint placed by a conventional debugger.
		 */

		/*
		 * APPLE NOTE: I believe the purpose of the reader/writers lock
		 * is thus: There are times which dtrace needs to prevent calling
		 * dtrace_pid_probe_ptr(). Sun's original impl grabbed a plain
		 * mutex here. However, that serialized all probe calls, and
		 * destroyed MP behavior. So now they use a RW lock, with probes
		 * as readers, and the top level synchronization as a writer.
		 */
		lck_rw_lock_shared(rwp);
		if (dtrace_pid_probe_ptr != NULL && 
		    (*dtrace_pid_probe_ptr)(regs) == 0) {
			lck_rw_unlock_shared(rwp);
			return KERN_SUCCESS;
		}
		lck_rw_unlock_shared(rwp);


		/*
		 * If the instruction that caused the breakpoint trap doesn't
		 * look like an int 3 anymore, it may be that this tracepoint
		 * was removed just after the user thread executed it. In
		 * that case, return to user land to retry the instuction.
		 */
		user_addr_t pc = (regs64) ? regs64->isf.rip : (user_addr_t)regs32->eip;
		if (fuword8(pc - 1, &instr) == 0 && instr != FASTTRAP_INSTR && // neither single-byte INT3 (0xCC)
			!(instr == 3 && fuword8(pc - 2, &instr2) == 0 && instr2 == 0xCD)) { // nor two-byte INT 3 (0xCD03)
			if (regs64) {
				regs64->isf.rip--;
			} else {
				regs32->eip--;
			}
			return KERN_SUCCESS;
		}

	}

	return KERN_FAILURE;
}

void
dtrace_safe_synchronous_signal(void)
{
#if 0
	kthread_t *t = curthread;
	struct regs *rp = lwptoregs(ttolwp(t));
	size_t isz = t->t_dtrace_npc - t->t_dtrace_pc;

	ASSERT(t->t_dtrace_on);

	/*
	 * If we're not in the range of scratch addresses, we're not actually
	 * tracing user instructions so turn off the flags. If the instruction
	 * we copied out caused a synchonous trap, reset the pc back to its
	 * original value and turn off the flags.
	 */
	if (rp->r_pc < t->t_dtrace_scrpc ||
			rp->r_pc > t->t_dtrace_astpc + isz) {
		t->t_dtrace_ft = 0;
	} else if (rp->r_pc == t->t_dtrace_scrpc ||
			rp->r_pc == t->t_dtrace_astpc) {
		rp->r_pc = t->t_dtrace_pc;
		t->t_dtrace_ft = 0;
	}
#endif /* 0 */
}

int
dtrace_safe_defer_signal(void)
{
#if 0
	kthread_t *t = curthread;
	struct regs *rp = lwptoregs(ttolwp(t));
	size_t isz = t->t_dtrace_npc - t->t_dtrace_pc;

	ASSERT(t->t_dtrace_on);

	/*
	 * If we're not in the range of scratch addresses, we're not actually
	 * tracing user instructions so turn off the flags.
	 */
	if (rp->r_pc < t->t_dtrace_scrpc ||
			rp->r_pc > t->t_dtrace_astpc + isz) {
		t->t_dtrace_ft = 0;
		return (0);
	}

	/*
	 * If we've executed the original instruction, but haven't performed
	 * the jmp back to t->t_dtrace_npc or the clean up of any registers
	 * used to emulate %rip-relative instructions in 64-bit mode, do that
	 * here and take the signal right away. We detect this condition by
	 * seeing if the program counter is the range [scrpc + isz, astpc).
	 */
	if (t->t_dtrace_astpc - rp->r_pc <
			t->t_dtrace_astpc - t->t_dtrace_scrpc - isz) {
#ifdef __sol64
		/*
		 * If there is a scratch register and we're on the
		 * instruction immediately after the modified instruction,
		 * restore the value of that scratch register.
		 */
		if (t->t_dtrace_reg != 0 &&
				rp->r_pc == t->t_dtrace_scrpc + isz) {
			switch (t->t_dtrace_reg) {
				case REG_RAX:
					rp->r_rax = t->t_dtrace_regv;
					break;
				case REG_RCX:
					rp->r_rcx = t->t_dtrace_regv;
					break;
				case REG_R8:
					rp->r_r8 = t->t_dtrace_regv;
					break;
				case REG_R9:
					rp->r_r9 = t->t_dtrace_regv;
					break;
			}
		}
#endif
		rp->r_pc = t->t_dtrace_npc;
		t->t_dtrace_ft = 0;
		return (0);
	}

	/*
	 * Otherwise, make sure we'll return to the kernel after executing
	 * the copied out instruction and defer the signal.
	 */
	if (!t->t_dtrace_step) {
		ASSERT(rp->r_pc < t->t_dtrace_astpc);
		rp->r_pc += t->t_dtrace_astpc - t->t_dtrace_scrpc;
		t->t_dtrace_step = 1;
	}

	t->t_dtrace_ast = 1;

	return (1);

#endif /* 0 */

	return 0;
}
