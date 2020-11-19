/*
 * Copyright (c) 2007-2018 Apple Inc. All rights reserved.
 */
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <kern/task.h>
#include <arm/thread.h>

#include <sys/dtrace_ptss.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

extern dtrace_id_t dtrace_probeid_error;

/* Solaris proc_t is the struct. Darwin's proc_t is a pointer to it. */
#define proc_t struct proc /* Steer clear of the Darwin typedef for proc_t */

extern uint8_t dtrace_decode_arm64(uint32_t instr);

#define IS_ARM64_NOP(x) ((x) == 0xD503201F)
/* Marker for is-enabled probes */
#define IS_ARM64_IS_ENABLED(x) ((x) == 0xD2800000)

int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp,
    user_addr_t pc, fasttrap_probe_type_t type)
{
#pragma unused(type)
	uint32_t instr = 0;

	/*
	 * Read the instruction at the given address out of the process's
	 * address space. We don't have to worry about a debugger
	 * changing this instruction before we overwrite it with our trap
	 * instruction since P_PR_LOCK is set. Since instructions can span
	 * pages, we potentially read the instruction in two parts. If the
	 * second part fails, we just zero out that part of the instruction.
	 */
	/*
	 * APPLE NOTE: Of course, we do not have a P_PR_LOCK, so this is racey...
	 */

	if (uread(p, &instr, 4, pc) != 0) {
		return -1;
	}

	tp->ftt_instr = instr;

	if (tp->ftt_fntype != FASTTRAP_FN_DONE_INIT) {
		switch (tp->ftt_fntype) {
		case FASTTRAP_FN_UNKNOWN:
		case FASTTRAP_FN_ARM64:
		case FASTTRAP_FN_ARM64_32:
			/*
			 * On arm64 there is no distinction between
			 * arm vs. thumb mode instruction types.
			 */
			tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;
			break;

		case FASTTRAP_FN_USDT:
			if (IS_ARM64_NOP(instr) || IS_ARM64_IS_ENABLED(instr)) {
				tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;
			} else {
				/*
				 * Shouldn't reach here - this means we don't
				 * recognize the instruction at one of the
				 * USDT probe locations
				 */
				return -1;
			}

			break;

		case FASTTRAP_FN_ARM:
		case FASTTRAP_FN_THUMB:
		default:
			/*
			 * If we get an arm or thumb mode type
			 * then we are clearly in the wrong path.
			 */
			return -1;
		}
	}

	tp->ftt_type = dtrace_decode_arm64(instr);

	if (tp->ftt_type == FASTTRAP_T_ARM64_EXCLUSIVE_MEM) {
		kprintf("Detected attempt to place DTrace probe on exclusive memory instruction (pc = 0x%llx); refusing to trace (or exclusive operation could never succeed).\n", pc);
		tp->ftt_type = FASTTRAP_T_INV;
		return -1;
	}

	if (tp->ftt_type == FASTTRAP_T_INV) {
		/* This is an instruction we either don't recognize or can't instrument */
		printf("dtrace: fasttrap init64: Unrecognized instruction: %08x at %08llx\n", instr, pc);
		return -1;
	}

	return 0;
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;
	int size;

	if (proc_is64bit_data(p)) {
		size = 4;
		instr = FASTTRAP_ARM64_INSTR;
	} else {
		return -1;
	}

	if (uwrite(p, &instr, size, tp->ftt_pc) != 0) {
		return -1;
	}

	tp->ftt_installed = 1;

	return 0;
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;
	int size = 4;

	if (proc_is64bit_data(p)) {
		/*
		 * Distinguish between read or write failures and a changed
		 * instruction.
		 */
		if (uread(p, &instr, size, tp->ftt_pc) != 0) {
			goto end;
		}

		if (instr != FASTTRAP_ARM64_INSTR) {
			goto end;
		}
	} else {
		return -1;
	}

	if (uwrite(p, &tp->ftt_instr, size, tp->ftt_pc) != 0) {
		return -1;
	}

end:
	tp->ftt_installed = 0;

	return 0;
}

static void
fasttrap_return_common(proc_t *p, arm_saved_state_t *regs, user_addr_t pc, user_addr_t new_pc)
{
	pid_t pid = p->p_pid;
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;
	lck_mtx_t *pid_mtx;
	int retire_tp = 1;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0) {
			break;
		}
	}

	/*
	 * Don't sweat it if we can't find the tracepoint again; unlike
	 * when we're in fasttrap_pid_probe(), finding the tracepoint here
	 * is not essential to the correct execution of the process.
	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return;
	}

	for (id = tp->ftt_retids; id != NULL; id = id->fti_next) {
		fasttrap_probe_t *probe = id->fti_probe;
		/* ARM64_TODO  - check for FASTTRAP_T_RET */
		if ((tp->ftt_type != FASTTRAP_T_ARM64_RET || tp->ftt_type != FASTTRAP_T_ARM64_RETAB) &&
		    new_pc - probe->ftp_faddr < probe->ftp_fsize) {
			continue;
		}
		if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
			if (os_atomic_xchg(&probe->ftp_triggered, 1, relaxed)) {
				/* already triggered */
				continue;
			}
		}
		/*
		 * If we have at least one probe associated that
		 * is not a oneshot probe, don't remove the
		 * tracepoint
		 */
		else {
			retire_tp = 0;
		}

#if defined(XNU_TARGET_OS_OSX)
		if (ISSET(current_proc()->p_lflag, P_LNOATTACH)) {
			dtrace_probe(dtrace_probeid_error, 0 /* state */, id->fti_probe->ftp_id,
			    1 /* ndx */, -1 /* offset */, DTRACEFLT_UPRIV);
#else
		if (FALSE) {
#endif /* defined(XNU_TARGET_OS_OSX) */
		} else {
			dtrace_probe(probe->ftp_id,
			    pc - id->fti_probe->ftp_faddr,
			    saved_state64(regs)->x[0], 0, 0, 0);
		}
	}
	if (retire_tp) {
		fasttrap_tracepoint_retire(p, tp);
	}

	lck_mtx_unlock(pid_mtx);
}

#if DEBUG
__dead2
#endif
static void
fasttrap_sigsegv(proc_t *p, uthread_t t, user_addr_t addr, arm_saved_state_t *regs)
{
	/* TODO: This function isn't implemented yet. In debug mode, panic the system to
	 * find out why we're hitting this point. In other modes, kill the process.
	 */
#if DEBUG
#pragma unused(p,t,addr,arm_saved_state)
	panic("fasttrap: sigsegv not yet implemented");
#else
#pragma unused(p,t,addr)
	/* Kill the process */
	set_saved_state_pc(regs, 0);
#endif

#if 0
	proc_lock(p);

	/* Set fault address and mark signal */
	t->uu_code = addr;
	t->uu_siglist |= sigmask(SIGSEGV);

	/*
	 * XXX These two line may be redundant; if not, then we need
	 * XXX to potentially set the data address in the machine
	 * XXX specific thread state structure to indicate the address.
	 */
	t->uu_exception = KERN_INVALID_ADDRESS;         /* SIGSEGV */
	t->uu_subcode = 0;      /* XXX pad */

	proc_unlock(p);

	/* raise signal */
	signal_setast(t->uu_context.vc_thread);
#endif
}

static void
fasttrap_usdt_args64(fasttrap_probe_t *probe, arm_saved_state64_t *regs64, int argc,
    uint64_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		/* Up to 8 args are passed in registers on arm64 */
		if (x < 8) {
			argv[i] = regs64->x[x];
		} else {
			fasttrap_fuword64_noerr(regs64->sp + (x - 8) * sizeof(uint64_t), &argv[i]);
		}
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}
}

static int
condition_true(int cond, int cpsr)
{
	int taken = 0;
	int zf = (cpsr & PSR_ZF) ? 1 : 0,
	    nf = (cpsr & PSR_NF) ? 1 : 0,
	    cf = (cpsr & PSR_CF) ? 1 : 0,
	    vf = (cpsr & PSR_VF) ? 1 : 0;

	switch (cond) {
	case 0: taken = zf; break;
	case 1: taken = !zf; break;
	case 2: taken = cf; break;
	case 3: taken = !cf; break;
	case 4: taken = nf; break;
	case 5: taken = !nf; break;
	case 6: taken = vf; break;
	case 7: taken = !vf; break;
	case 8: taken = (cf && !zf); break;
	case 9: taken = (!cf || zf); break;
	case 10: taken = (nf == vf); break;
	case 11: taken = (nf != vf); break;
	case 12: taken = (!zf && (nf == vf)); break;
	case 13: taken = (zf || (nf != vf)); break;
	case 14: taken = 1; break;
	case 15: taken = 1; break;         /* always "true" for ARM, unpredictable for THUMB. */
	}

	return taken;
}

/*
 * Copy out an instruction for execution in userland.
 * Trap back to kernel to handle return to original flow of execution, because
 * direct branches don't have sufficient range (+/- 128MB) and we
 * cannot clobber a GPR.  Note that we have to specially handle PC-rel loads/stores
 * as well, which have range +/- 1MB (convert to an indirect load).  Instruction buffer
 * layout:
 *
 *    [ Thunked instruction sequence ]
 *    [ Trap for return to original code and return probe handling ]
 *
 * This *does* make it impossible for an ldxr/stxr pair to succeed if we trace on or between
 * them... may need to get fancy at some point.
 */
static void
fasttrap_pid_probe_thunk_instr64(arm_saved_state_t *state, fasttrap_tracepoint_t *tp, proc_t *p, uthread_t uthread,
    const uint32_t *instructions, uint32_t num_instrs, user_addr_t *pc_out)
{
	uint32_t local_scratch[8];
	user_addr_t pc = get_saved_state_pc(state);
	user_addr_t user_scratch_area;

	assert(num_instrs < 8);

	bcopy(instructions, local_scratch, num_instrs * sizeof(uint32_t));
	local_scratch[num_instrs] = FASTTRAP_ARM64_RET_INSTR;

	uthread->t_dtrace_astpc = uthread->t_dtrace_scrpc = uthread->t_dtrace_scratch->addr;
	user_scratch_area = uthread->t_dtrace_scratch->write_addr;

	if (user_scratch_area == (user_addr_t)0) {
		fasttrap_sigtrap(p, uthread, pc); // Should be killing target proc
		*pc_out = pc;
		return;
	}

	if (uwrite(p, local_scratch, (num_instrs + 1) * sizeof(uint32_t), user_scratch_area) != KERN_SUCCESS) {
		fasttrap_sigtrap(p, uthread, pc);
		*pc_out = pc;
		return;
	}

	/* We're stepping (come back to kernel to adjust PC for return to regular code). */
	uthread->t_dtrace_step = 1;

	/* We may or may not be about to run a return probe (but we wouldn't thunk ret lr)*/
	uthread->t_dtrace_ret = (tp->ftt_retids != NULL);
	assert(tp->ftt_type != FASTTRAP_T_ARM64_RET);
	assert(tp->ftt_type != FASTTRAP_T_ARM64_RETAB);

	/* Set address of instruction we've patched */
	uthread->t_dtrace_pc = pc;

	/* Any branch would be emulated, next instruction should be one ahead */
	uthread->t_dtrace_npc = pc + 4;

	/* We are certainly handling a probe */
	uthread->t_dtrace_on = 1;

	/* Let's jump to the scratch area */
	*pc_out = uthread->t_dtrace_scratch->addr;
}

/*
 * Sign-extend bit "sign_bit_index" out to bit 64.
 */
static int64_t
sign_extend(int64_t input, uint32_t sign_bit_index)
{
	assert(sign_bit_index < 63);
	if (input & (1ULL << sign_bit_index)) {
		/* All 1's & ~[1's from 0 to sign bit] */
		input |= ((~0ULL) & ~((1ULL << (sign_bit_index + 1)) - 1ULL));
	}

	return input;
}

/*
 * Handle xzr vs. sp, fp, lr, etc.  Will *not* read the SP.
 */
static uint64_t
get_saved_state64_regno(arm_saved_state64_t *regs64, uint32_t regno, int use_xzr)
{
	/* Set PC to register value */
	switch (regno) {
	case 29:
		return regs64->fp;
	case 30:
		return regs64->lr;
	case 31:
		/* xzr */
		if (use_xzr) {
			return 0;
		} else {
			return regs64->sp;
		}
	default:
		return regs64->x[regno];
	}
}

static void
set_saved_state64_regno(arm_saved_state64_t *regs64, uint32_t regno, int use_xzr, register_t value)
{
	/* Set PC to register value */
	switch (regno) {
	case 29:
		regs64->fp = value;
		break;
	case 30:
		regs64->lr = value;
		break;
	case 31:
		if (!use_xzr) {
			regs64->sp = value;
		}
		break;
	default:
		regs64->x[regno] = value;
		break;
	}
}

/*
 * Common operation: extract sign-extended PC offset from instruction
 * Left-shifts result by two bits.
 */
static uint64_t
extract_address_literal_sign_extended(uint32_t instr, uint32_t base, uint32_t numbits)
{
	uint64_t offset;

	offset = (instr >> base) & ((1 << numbits) - 1);
	offset = sign_extend(offset, numbits - 1);
	offset = offset << 2;

	return offset;
}

static void
do_cbz_cnbz(arm_saved_state64_t *regs64, uint32_t regwidth, uint32_t instr, int is_cbz, user_addr_t *pc_out)
{
	uint32_t regno;
	uint64_t regval;
	uint64_t offset;

	/* Extract register */
	regno = (instr & 0x1f);
	assert(regno <= 31);
	regval = get_saved_state64_regno(regs64, regno, 1);

	/* Control for size */
	if (regwidth == 32) {
		regval &= 0xFFFFFFFFULL;
	}

	/* Extract offset */
	offset = extract_address_literal_sign_extended(instr, 5, 19);

	/* Do test */
	if ((is_cbz && regval == 0) || ((!is_cbz) && regval != 0)) {
		/* Set PC from label */
		*pc_out = regs64->pc + offset;
	} else {
		/* Advance PC */
		*pc_out = regs64->pc + 4;
	}
}

static void
do_tbz_tbnz(arm_saved_state64_t *regs64, uint32_t instr, int is_tbz, user_addr_t *pc_out)
{
	uint64_t offset, regval;
	uint32_t bit_index, b5, b40, regno, bit_set;

	/* Compute offset */
	offset = extract_address_literal_sign_extended(instr, 5, 14);

	/* Extract bit index */
	b5 = (instr >> 31);
	b40 = ((instr >> 19) & 0x1f);
	bit_index = (b5 << 5) | b40;
	assert(bit_index <= 63);

	/* Extract register */
	regno = (instr & 0x1f);
	assert(regno <= 31);
	regval = get_saved_state64_regno(regs64, regno, 1);

	/* Test bit */
	bit_set = ((regval & (1 << bit_index)) != 0);

	if ((is_tbz && (!bit_set)) || ((!is_tbz) && bit_set)) {
		/* Branch: unsigned addition so overflow defined */
		*pc_out = regs64->pc + offset;
	} else {
		/* Advance PC */
		*pc_out = regs64->pc + 4;
	}
}


static void
fasttrap_pid_probe_handle_patched_instr64(arm_saved_state_t *state, fasttrap_tracepoint_t *tp __unused, uthread_t uthread,
    proc_t *p, uint_t is_enabled, int *was_simulated)
{
	int res1, res2;
	arm_saved_state64_t *regs64 = saved_state64(state);
	uint32_t instr = tp->ftt_instr;
	user_addr_t new_pc = 0;

	/* Neon state should be threaded throw, but hack it until we have better arm/arm64 integration */
	arm_neon_saved_state64_t *ns64 = &(get_user_neon_regs(uthread->uu_thread)->ns_64);

	/* is-enabled probe: set x0 to 1 and step forwards */
	if (is_enabled) {
		regs64->x[0] = 1;
		set_saved_state_pc(state, regs64->pc + 4);
		return;
	}

	/* For USDT probes, bypass all the emulation logic for the nop instruction */
	if (IS_ARM64_NOP(tp->ftt_instr)) {
		set_saved_state_pc(state, regs64->pc + 4);
		return;
	}


	/* Only one of many cases in the switch doesn't simulate */
	switch (tp->ftt_type) {
	/*
	 * Function entry: emulate for speed.
	 * stp fp, lr, [sp, #-16]!
	 */
	case FASTTRAP_T_ARM64_STANDARD_FUNCTION_ENTRY:
	{
		/* Store values to stack */
		res1 = fasttrap_suword64(regs64->sp - 16, regs64->fp);
		res2 = fasttrap_suword64(regs64->sp - 8, regs64->lr);
		if (res1 != 0 || res2 != 0) {
			fasttrap_sigsegv(p, uthread, regs64->sp - (res1 ? 16 : 8), state);
#ifndef DEBUG
			new_pc = regs64->pc;         /* Bit of a hack */
			break;
#endif
		}

		/* Move stack pointer */
		regs64->sp -= 16;

		/* Move PC forward */
		new_pc = regs64->pc + 4;
		*was_simulated = 1;
		break;
	}

	/*
	 * PC-relative loads/stores: emulate for correctness.
	 * All loads are 32bits or greater (no need to handle byte or halfword accesses).
	 *	LDR Wt, addr
	 *	LDR Xt, addr
	 *	LDRSW Xt, addr
	 *
	 *      LDR St, addr
	 *      LDR Dt, addr
	 *      LDR Qt, addr
	 *      PRFM label -> becomes a NOP
	 */
	case FASTTRAP_T_ARM64_LDR_S_PC_REL:
	case FASTTRAP_T_ARM64_LDR_W_PC_REL:
	case FASTTRAP_T_ARM64_LDR_D_PC_REL:
	case FASTTRAP_T_ARM64_LDR_X_PC_REL:
	case FASTTRAP_T_ARM64_LDR_Q_PC_REL:
	case FASTTRAP_T_ARM64_LDRSW_PC_REL:
	{
		uint64_t offset;
		uint32_t valsize, regno;
		user_addr_t address;
		union {
			uint32_t val32;
			uint64_t val64;
			uint128_t val128;
		} value;

		/* Extract 19-bit offset, add to pc */
		offset = extract_address_literal_sign_extended(instr, 5, 19);
		address = regs64->pc + offset;

		/* Extract destination register */
		regno = (instr & 0x1f);
		assert(regno <= 31);

		/* Read value of desired size from memory */
		switch (tp->ftt_type) {
		case FASTTRAP_T_ARM64_LDR_S_PC_REL:
		case FASTTRAP_T_ARM64_LDR_W_PC_REL:
		case FASTTRAP_T_ARM64_LDRSW_PC_REL:
			valsize = 4;
			break;
		case FASTTRAP_T_ARM64_LDR_D_PC_REL:
		case FASTTRAP_T_ARM64_LDR_X_PC_REL:
			valsize = 8;
			break;
		case FASTTRAP_T_ARM64_LDR_Q_PC_REL:
			valsize = 16;
			break;
		default:
			panic("Should never get here!");
			valsize = -1;
			break;
		}

		if (copyin(address, &value, valsize) != 0) {
			fasttrap_sigsegv(p, uthread, address, state);
#ifndef DEBUG
			new_pc = regs64->pc;         /* Bit of a hack, we know about update in fasttrap_sigsegv() */
			break;
#endif
		}

		/* Stash in correct register slot */
		switch (tp->ftt_type) {
		case FASTTRAP_T_ARM64_LDR_W_PC_REL:
			set_saved_state64_regno(regs64, regno, 1, value.val32);
			break;
		case FASTTRAP_T_ARM64_LDRSW_PC_REL:
			set_saved_state64_regno(regs64, regno, 1, sign_extend(value.val32, 31));
			break;
		case FASTTRAP_T_ARM64_LDR_X_PC_REL:
			set_saved_state64_regno(regs64, regno, 1, value.val64);
			break;
		case FASTTRAP_T_ARM64_LDR_S_PC_REL:
			ns64->v.s[regno][0] = value.val32;
			break;
		case FASTTRAP_T_ARM64_LDR_D_PC_REL:
			ns64->v.d[regno][0] = value.val64;
			break;
		case FASTTRAP_T_ARM64_LDR_Q_PC_REL:
			ns64->v.q[regno] = value.val128;
			break;
		default:
			panic("Should never get here!");
		}


		/* Move PC forward */
		new_pc = regs64->pc + 4;
		*was_simulated = 1;
		break;
	}

	case FASTTRAP_T_ARM64_PRFM:
	{
		/* Becomes a NOP (architecturally permitted).  Just move PC forward */
		new_pc = regs64->pc + 4;
		*was_simulated = 1;
		break;
	}

	/*
	 * End explicit memory accesses.
	 */

	/*
	 * Branches: parse condition codes if needed, emulate for correctness and
	 * in the case of the indirect branches, convenience
	 *      B.cond
	 *      CBNZ Wn, label
	 *      CBNZ Xn, label
	 *      CBZ Wn, label
	 *      CBZ Xn, label
	 *      TBNZ, Xn|Wn, #uimm16, label
	 *      TBZ, Xn|Wn, #uimm16, label
	 *
	 *      B label
	 *      BL label
	 *
	 *	BLR Xm
	 *	BR Xm
	 *	RET Xm
	 */
	case FASTTRAP_T_ARM64_B_COND:
	{
		int cond;

		/* Extract condition code */
		cond = (instr & 0xf);

		/* Determine if it passes */
		if (condition_true(cond, regs64->cpsr)) {
			uint64_t offset;

			/* Extract 19-bit target offset, add to PC */
			offset = extract_address_literal_sign_extended(instr, 5, 19);
			new_pc = regs64->pc + offset;
		} else {
			/* Move forwards */
			new_pc = regs64->pc + 4;
		}

		*was_simulated = 1;
		break;
	}

	case FASTTRAP_T_ARM64_CBNZ_W:
	{
		do_cbz_cnbz(regs64, 32, instr, 0, &new_pc);
		*was_simulated = 1;
		break;
	}
	case FASTTRAP_T_ARM64_CBNZ_X:
	{
		do_cbz_cnbz(regs64, 64, instr, 0, &new_pc);
		*was_simulated = 1;
		break;
	}
	case FASTTRAP_T_ARM64_CBZ_W:
	{
		do_cbz_cnbz(regs64, 32, instr, 1, &new_pc);
		*was_simulated = 1;
		break;
	}
	case FASTTRAP_T_ARM64_CBZ_X:
	{
		do_cbz_cnbz(regs64, 64, instr, 1, &new_pc);
		*was_simulated = 1;
		break;
	}

	case FASTTRAP_T_ARM64_TBNZ:
	{
		do_tbz_tbnz(regs64, instr, 0, &new_pc);
		*was_simulated = 1;
		break;
	}
	case FASTTRAP_T_ARM64_TBZ:
	{
		do_tbz_tbnz(regs64, instr, 1, &new_pc);
		*was_simulated = 1;
		break;
	}
	case FASTTRAP_T_ARM64_B:
	case FASTTRAP_T_ARM64_BL:
	{
		uint64_t offset;

		/* Extract offset from instruction */
		offset = extract_address_literal_sign_extended(instr, 0, 26);

		/* Update LR if appropriate */
		if (tp->ftt_type == FASTTRAP_T_ARM64_BL) {
			regs64->lr = regs64->pc + 4;
		}

		/* Compute PC (unsigned addition for defined overflow) */
		new_pc = regs64->pc + offset;
		*was_simulated = 1;
		break;
	}

	case FASTTRAP_T_ARM64_BLR:
	case FASTTRAP_T_ARM64_BR:
	{
		uint32_t regno;

		/* Extract register from instruction */
		regno = ((instr >> 5) & 0x1f);
		assert(regno <= 31);

		/* Update LR if appropriate */
		if (tp->ftt_type == FASTTRAP_T_ARM64_BLR) {
			regs64->lr = regs64->pc + 4;
		}

		/* Update PC in saved state */
		new_pc = get_saved_state64_regno(regs64, regno, 1);
		*was_simulated = 1;
		break;
	}

	case FASTTRAP_T_ARM64_RET:
	{
		/* Extract register */
		unsigned regno = ((instr >> 5) & 0x1f);
		assert(regno <= 31);

		/* Set PC to register value (xzr, not sp) */
		new_pc = get_saved_state64_regno(regs64, regno, 1);

		*was_simulated = 1;
		break;
	}
	case FASTTRAP_T_ARM64_RETAB:
	{
		/* Set PC to register value (xzr, not sp) */
		new_pc = get_saved_state64_regno(regs64, 30, 1);
#if __has_feature(ptrauth_calls)
		new_pc = (user_addr_t) ptrauth_strip((void *)new_pc, ptrauth_key_return_address);
#endif

		*was_simulated = 1;
		break;
	}
	/*
	 * End branches.
	 */

	/*
	 * Address calculations: emulate for correctness.
	 *
	 *      ADRP Xd, label
	 *      ADR Xd, label
	 */
	case FASTTRAP_T_ARM64_ADRP:
	case FASTTRAP_T_ARM64_ADR:
	{
		uint64_t immhi, immlo, offset, result;
		uint32_t regno;

		/* Extract destination register */
		regno = (instr & 0x1f);
		assert(regno <= 31);

		/* Extract offset */
		immhi = ((instr & 0x00ffffe0) >> 5);                    /* bits [23,5]: 19 bits */
		immlo = ((instr & 0x60000000) >> 29);                   /* bits [30,29]: 2 bits */

		/* Add to PC.  Use unsigned addition so that overflow wraps (rather than being undefined). */
		if (tp->ftt_type == FASTTRAP_T_ARM64_ADRP) {
			offset =  (immhi << 14) | (immlo << 12);                /* Concatenate bits into [32,12]*/
			offset = sign_extend(offset, 32);                       /* Sign extend from bit 32 */
			result = (regs64->pc & ~0xfffULL) + offset;             /* And add to page of current pc */
		} else {
			assert(tp->ftt_type == FASTTRAP_T_ARM64_ADR);
			offset =  (immhi << 2) | immlo;                         /* Concatenate bits into [20,0] */
			offset = sign_extend(offset, 20);                       /* Sign-extend */
			result = regs64->pc + offset;                           /* And add to page of current pc */
		}

		/* xzr, not sp */
		set_saved_state64_regno(regs64, regno, 1, result);

		/* Move PC forward */
		new_pc = regs64->pc + 4;
		*was_simulated = 1;
		break;
	}

	/*
	 *  End address calculations.
	 */

	/*
	 * Everything else: thunk to userland
	 */
	case FASTTRAP_T_COMMON:
	{
		fasttrap_pid_probe_thunk_instr64(state, tp, p, uthread, &tp->ftt_instr, 1, &new_pc);
		*was_simulated = 0;
		break;
	}
	default:
	{
		panic("An instruction DTrace doesn't expect: %d\n", tp->ftt_type);
		break;
	}
	}

	set_saved_state_pc(state, new_pc);
	return;
}

int
fasttrap_pid_probe(arm_saved_state_t *state)
{
	proc_t *p = current_proc();
	fasttrap_bucket_t *bucket;
	lck_mtx_t *pid_mtx;
	fasttrap_tracepoint_t *tp, tp_local;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;
	int was_simulated, retire_tp = 1;

	uint64_t pc = get_saved_state_pc(state);

	assert(is_saved_state64(state));

	uthread_t uthread = (uthread_t) get_bsdthread_info(current_thread());

	/*
	 * It's possible that a user (in a veritable orgy of bad planning)
	 * could redirect this thread's flow of control before it reached the
	 * return probe fasttrap. In this case we need to kill the process
	 * since it's in a unrecoverable state.
	 */
	if (uthread->t_dtrace_step) {
		ASSERT(uthread->t_dtrace_on);
		fasttrap_sigtrap(p, uthread, (user_addr_t)pc);
		return 0;
	}

	/*
	 * Clear all user tracing flags.
	 */
	uthread->t_dtrace_ft = 0;
	uthread->t_dtrace_pc = 0;
	uthread->t_dtrace_npc = 0;
	uthread->t_dtrace_scrpc = 0;
	uthread->t_dtrace_astpc = 0;
	uthread->t_dtrace_reg = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	if (p->p_lflag & P_LINVFORK) {
		proc_list_lock();
		while (p->p_lflag & P_LINVFORK) {
			p = p->p_pptr;
		}
		proc_list_unlock();
	}

	pid = p->p_pid;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0) {
			break;
		}
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return -1;
	}

	/* Execute the actual probe */
	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;
		uint64_t arg4;

		if (is_saved_state64(state)) {
			arg4 = get_saved_state_reg(state, 4);
		} else {
			return -1;
		}


		/* First four parameters are passed in registers */

		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;

#if defined(XNU_TARGET_OS_OSX)
			if (ISSET(current_proc()->p_lflag, P_LNOATTACH)) {
				dtrace_probe(dtrace_probeid_error, 0 /* state */, probe->ftp_id,
				    1 /* ndx */, -1 /* offset */, DTRACEFLT_UPRIV);
#else
			if (FALSE) {
#endif /* defined(XNU_TARGET_OS_OSX) */
			} else {
				if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
					if (os_atomic_xchg(&probe->ftp_triggered, 1, relaxed)) {
						/* already triggered */
						continue;
					}
				}
				/*
				 * If we have at least one probe associated that
				 * is not a oneshot probe, don't remove the
				 * tracepoint
				 */
				else {
					retire_tp = 0;
				}
				if (id->fti_ptype == DTFTP_ENTRY) {
					/*
					 * We note that this was an entry
					 * probe to help ustack() find the
					 * first caller.
					 */
					cookie = dtrace_interrupt_disable();
					DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
					dtrace_probe(probe->ftp_id,
					    get_saved_state_reg(state, 0),
					    get_saved_state_reg(state, 1),
					    get_saved_state_reg(state, 2),
					    get_saved_state_reg(state, 3),
					    arg4);
					DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_ENTRY);
					dtrace_interrupt_enable(cookie);
				} else if (id->fti_ptype == DTFTP_IS_ENABLED) {
					/*
					 * Note that in this case, we don't
					 * call dtrace_probe() since it's only
					 * an artificial probe meant to change
					 * the flow of control so that it
					 * encounters the true probe.
					 */
					is_enabled = 1;
				} else if (probe->ftp_argmap == NULL) {
					dtrace_probe(probe->ftp_id,
					    get_saved_state_reg(state, 0),
					    get_saved_state_reg(state, 1),
					    get_saved_state_reg(state, 2),
					    get_saved_state_reg(state, 3),
					    arg4);
				} else {
					uint64_t t[5];

					fasttrap_usdt_args64(probe, saved_state64(state), 5, t);
					dtrace_probe(probe->ftp_id, t[0], t[1], t[2], t[3], t[4]);
				}
			}
		}
		if (retire_tp) {
			fasttrap_tracepoint_retire(p, tp);
		}
	}
	/*
	 * We're about to do a bunch of work so we cache a local copy of
	 * the tracepoint to emulate the instruction, and then find the
	 * tracepoint again later if we need to light up any return probes.
	 */
	tp_local = *tp;
	lck_mtx_unlock(pid_mtx);
	tp = &tp_local;

	/*
	 * APPLE NOTE:
	 *
	 * Subroutines should update PC.
	 * We're setting this earlier than Solaris does, to get a "correct"
	 * ustack() output. In the Sun code,  a() -> b() -> c() -> d() is
	 * reported at: d, b, a. The new way gives c, b, a, which is closer
	 * to correct, as the return instruction has already exectued.
	 */
	fasttrap_pid_probe_handle_patched_instr64(state, tp, uthread, p, is_enabled, &was_simulated);

	/*
	 * If there were no return probes when we first found the tracepoint,
	 * we should feel no obligation to honor any return probes that were
	 * subsequently enabled -- they'll just have to wait until the next
	 * time around.
	 */
	if (tp->ftt_retids != NULL) {
		/*
		 * We need to wait until the results of the instruction are
		 * apparent before invoking any return probes. If this
		 * instruction was emulated we can just call
		 * fasttrap_return_common(); if it needs to be executed, we
		 * need to wait until the user thread returns to the kernel.
		 */
		/*
		 * It used to be that only common instructions were simulated.
		 * For performance reasons, we now simulate some instructions
		 * when safe and go back to userland otherwise. The was_simulated
		 * flag means we don't need to go back to userland.
		 */
		if (was_simulated) {
			fasttrap_return_common(p, state, (user_addr_t)pc, (user_addr_t)get_saved_state_pc(state));
		} else {
			ASSERT(uthread->t_dtrace_ret != 0);
			ASSERT(uthread->t_dtrace_pc == pc);
			ASSERT(uthread->t_dtrace_scrpc != 0);
			ASSERT(((user_addr_t)get_saved_state_pc(state)) == uthread->t_dtrace_astpc);
		}
	}

	return 0;
}

int
fasttrap_return_probe(arm_saved_state_t *regs)
{
	proc_t *p = current_proc();
	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
	user_addr_t pc = uthread->t_dtrace_pc;
	user_addr_t npc = uthread->t_dtrace_npc;

	uthread->t_dtrace_pc = 0;
	uthread->t_dtrace_npc = 0;
	uthread->t_dtrace_scrpc = 0;
	uthread->t_dtrace_astpc = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	if (p->p_lflag & P_LINVFORK) {
		proc_list_lock();
		while (p->p_lflag & P_LINVFORK) {
			p = p->p_pptr;
		}
		proc_list_unlock();
	}

	/*
	 * We set rp->r_pc to the address of the traced instruction so
	 * that it appears to dtrace_probe() that we're on the original
	 * instruction, and so that the user can't easily detect our
	 * complex web of lies. dtrace_return_probe() (our caller)
	 * will correctly set %pc after we return.
	 */
	set_saved_state_pc(regs, pc);

	fasttrap_return_common(p, regs, pc, npc);

	return 0;
}

uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
#pragma unused(arg, id, parg, aframes)
	arm_saved_state_t* regs = find_user_regs(current_thread());

	/* First eight arguments are in registers */
	if (argno < 8) {
		return saved_state64(regs)->x[argno];
	}

	/* Look on the stack for the rest */
	uint64_t value;
	uint64_t* sp = (uint64_t*) saved_state64(regs)->sp;
	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	value = dtrace_fuword64((user_addr_t) (sp + argno - 8));
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);

	return value;
}

uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg, id, parg, argno, aframes)
	return 0;
}
