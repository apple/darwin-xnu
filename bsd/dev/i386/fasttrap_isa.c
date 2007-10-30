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

/*
 * #pragma ident	"@(#)fasttrap_isa.c	1.23	06/09/19 SMI"
 */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>

#include "fasttrap_regset.h"

#include <sys/dtrace_ptss.h>
#include <kern/debug.h>

#define proc_t struct proc

/*
 * Lossless User-Land Tracing on x86
 * ---------------------------------
 *
 * The execution of most instructions is not dependent on the address; for
 * these instructions it is sufficient to copy them into the user process's
 * address space and execute them. To effectively single-step an instruction
 * in user-land, we copy out the following sequence of instructions to scratch
 * space in the user thread's ulwp_t structure.
 *
 * We then set the program counter (%eip or %rip) to point to this scratch
 * space. Once execution resumes, the original instruction is executed and
 * then control flow is redirected to what was originally the subsequent
 * instruction. If the kernel attemps to deliver a signal while single-
 * stepping, the signal is deferred and the program counter is moved into the
 * second sequence of instructions. The second sequence ends in a trap into
 * the kernel where the deferred signal is then properly handled and delivered.
 *
 * For instructions whose execute is position dependent, we perform simple
 * emulation. These instructions are limited to control transfer
 * instructions in 32-bit mode, but in 64-bit mode there's the added wrinkle
 * of %rip-relative addressing that means that almost any instruction can be
 * position dependent. For all the details on how we emulate generic
 * instructions included %rip-relative instructions, see the code in
 * fasttrap_pid_probe() below where we handle instructions of type
 * FASTTRAP_T_COMMON (under the header: Generic Instruction Tracing).
 */

#define	FASTTRAP_MODRM_MOD(modrm)	(((modrm) >> 6) & 0x3)
#define	FASTTRAP_MODRM_REG(modrm)	(((modrm) >> 3) & 0x7)
#define	FASTTRAP_MODRM_RM(modrm)	((modrm) & 0x7)
#define	FASTTRAP_MODRM(mod, reg, rm)	(((mod) << 6) | ((reg) << 3) | (rm))

#define	FASTTRAP_SIB_SCALE(sib)		(((sib) >> 6) & 0x3)
#define	FASTTRAP_SIB_INDEX(sib)		(((sib) >> 3) & 0x7)
#define	FASTTRAP_SIB_BASE(sib)		((sib) & 0x7)

#define	FASTTRAP_REX_W(rex)		(((rex) >> 3) & 1)
#define	FASTTRAP_REX_R(rex)		(((rex) >> 2) & 1)
#define	FASTTRAP_REX_X(rex)		(((rex) >> 1) & 1)
#define	FASTTRAP_REX_B(rex)		((rex) & 1)
#define	FASTTRAP_REX(w, r, x, b)	\
	(0x40 | ((w) << 3) | ((r) << 2) | ((x) << 1) | (b))

/*
 * Single-byte op-codes.
 */
#define	FASTTRAP_PUSHL_EBP	0x55

#define	FASTTRAP_JO		0x70
#define	FASTTRAP_JNO		0x71
#define	FASTTRAP_JB		0x72
#define	FASTTRAP_JAE		0x73
#define	FASTTRAP_JE		0x74
#define	FASTTRAP_JNE		0x75
#define	FASTTRAP_JBE		0x76
#define	FASTTRAP_JA		0x77
#define	FASTTRAP_JS		0x78
#define	FASTTRAP_JNS		0x79
#define	FASTTRAP_JP		0x7a
#define	FASTTRAP_JNP		0x7b
#define	FASTTRAP_JL		0x7c
#define	FASTTRAP_JGE		0x7d
#define	FASTTRAP_JLE		0x7e
#define	FASTTRAP_JG		0x7f

#define	FASTTRAP_NOP		0x90

#define	FASTTRAP_MOV_EAX	0xb8
#define	FASTTRAP_MOV_ECX	0xb9

#define	FASTTRAP_RET16		0xc2
#define	FASTTRAP_RET		0xc3

#define	FASTTRAP_LOOPNZ		0xe0
#define	FASTTRAP_LOOPZ		0xe1
#define	FASTTRAP_LOOP		0xe2
#define	FASTTRAP_JCXZ		0xe3

#define	FASTTRAP_CALL		0xe8
#define	FASTTRAP_JMP32		0xe9
#define	FASTTRAP_JMP8		0xeb

#define	FASTTRAP_INT3		0xcc
#define	FASTTRAP_INT		0xcd
#define	T_DTRACE_RET		0x7f

#define	FASTTRAP_2_BYTE_OP	0x0f
#define	FASTTRAP_GROUP5_OP	0xff

/*
 * Two-byte op-codes (second byte only).
 */
#define	FASTTRAP_0F_JO		0x80
#define	FASTTRAP_0F_JNO		0x81
#define	FASTTRAP_0F_JB		0x82
#define	FASTTRAP_0F_JAE		0x83
#define	FASTTRAP_0F_JE		0x84
#define	FASTTRAP_0F_JNE		0x85
#define	FASTTRAP_0F_JBE		0x86
#define	FASTTRAP_0F_JA		0x87
#define	FASTTRAP_0F_JS		0x88
#define	FASTTRAP_0F_JNS		0x89
#define	FASTTRAP_0F_JP		0x8a
#define	FASTTRAP_0F_JNP		0x8b
#define	FASTTRAP_0F_JL		0x8c
#define	FASTTRAP_0F_JGE		0x8d
#define	FASTTRAP_0F_JLE		0x8e
#define	FASTTRAP_0F_JG		0x8f

#define	FASTTRAP_EFLAGS_OF	0x800
#define	FASTTRAP_EFLAGS_DF	0x400
#define	FASTTRAP_EFLAGS_SF	0x080
#define	FASTTRAP_EFLAGS_ZF	0x040
#define	FASTTRAP_EFLAGS_AF	0x010
#define	FASTTRAP_EFLAGS_PF	0x004
#define	FASTTRAP_EFLAGS_CF	0x001

/*
 * Instruction prefixes.
 */
#define	FASTTRAP_PREFIX_OPERAND	0x66
#define	FASTTRAP_PREFIX_ADDRESS	0x67
#define	FASTTRAP_PREFIX_CS	0x2E
#define	FASTTRAP_PREFIX_DS	0x3E
#define	FASTTRAP_PREFIX_ES	0x26
#define	FASTTRAP_PREFIX_FS	0x64
#define	FASTTRAP_PREFIX_GS	0x65
#define	FASTTRAP_PREFIX_SS	0x36
#define	FASTTRAP_PREFIX_LOCK	0xF0
#define	FASTTRAP_PREFIX_REP	0xF3
#define	FASTTRAP_PREFIX_REPNE	0xF2

#define	FASTTRAP_NOREG	0xff

/*
 * Map between instruction register encodings and the kernel constants which
 * correspond to indicies into struct regs.
 */

/*
 * APPLE NOTE: We are cheating here. The regmap is used to decode which register
 * a given instruction is trying to reference. OS X does not have extended registers
 * for 32 bit apps, but the *order* is the same. So for 32 bit state, we will return:
 *
 * REG_RAX -> EAX
 * REG_RCX -> ECX
 * ...
 * REG_RDI -> EDI
 *
 * The fasttrap_getreg function knows how to make the correct transformation.
 */
#if __sol64 || defined(__APPLE__)
static const uint8_t regmap[16] = {
	REG_RAX, REG_RCX, REG_RDX, REG_RBX, REG_RSP, REG_RBP, REG_RSI, REG_RDI,
	REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
};
#else
static const uint8_t regmap[8] = {
	EAX, ECX, EDX, EBX, UESP, EBP, ESI, EDI
};
#endif

static user_addr_t fasttrap_getreg(x86_saved_state_t *, uint_t);

static uint64_t
fasttrap_anarg(x86_saved_state_t *regs, int function_entry, int argno)
{
	uint64_t value;
	int shift = function_entry ? 1 : 0;

	x86_saved_state64_t *regs64;
	x86_saved_state32_t *regs32;
	unsigned int p_model;

        if (is_saved_state64(regs)) {
                regs64 = saved_state64(regs);
		regs32 = NULL;
		p_model = DATAMODEL_LP64;
        } else {
		regs64 = NULL;
                regs32 = saved_state32(regs);
		p_model = DATAMODEL_ILP32;
        }

	if (p_model == DATAMODEL_LP64) {
		user_addr_t stack;
		
		/*
		 * In 64-bit mode, the first six arguments are stored in
		 * registers.
		 */
		if (argno < 6)
			return ((&regs64->rdi)[argno]);

		stack = regs64->isf.rsp + sizeof(uint64_t) * (argno - 6 + shift);
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fuword64(stack);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);
	} else {
		uint32_t *stack = (uint32_t *)regs32->uesp;
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fuword32((user_addr_t)(unsigned long)&stack[argno + shift]);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);
	}

	return (value);
}

/*ARGSUSED*/
int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, user_addr_t pc,
    fasttrap_probe_type_t type)
{
#pragma unused(type)
	uint8_t instr[FASTTRAP_MAX_INSTR_SIZE + 10];
	size_t len = FASTTRAP_MAX_INSTR_SIZE;
	size_t first = MIN(len, PAGE_SIZE - (pc & PAGE_MASK));
	uint_t start = 0;
	size_t size;
	int rmindex;
	uint8_t seg, rex = 0;
	unsigned int p_model = (p->p_flag & P_LP64) ? DATAMODEL_LP64 : DATAMODEL_ILP32;

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
	if (uread(p, &instr[0], first, pc) != 0)
		return (-1);
	if (len > first &&
	    uread(p, &instr[first], len - first, pc + first) != 0) {
		bzero(&instr[first], len - first);
		len = first;
	}

	/*
	 * If the disassembly fails, then we have a malformed instruction.
	 */
	if ((size = dtrace_instr_size_isa(instr, p_model, &rmindex)) <= 0)
		return (-1);

	/*
	 * Make sure the disassembler isn't completely broken.
	 */
	ASSERT(-1 <= rmindex && rmindex < (int)size);

	/*
	 * If the computed size is greater than the number of bytes read,
	 * then it was a malformed instruction possibly because it fell on a
	 * page boundary and the subsequent page was missing or because of
	 * some malicious user.
	 */
	if (size > len)
		return (-1);

	tp->ftt_size = (uint8_t)size;
	tp->ftt_segment = FASTTRAP_SEG_NONE;

	/*
	 * Find the start of the instruction's opcode by processing any
	 * legacy prefixes.
	 */
	for (;;) {
		seg = 0;
		switch (instr[start]) {
		case FASTTRAP_PREFIX_SS:
			seg++;
			/*FALLTHRU*/
		case FASTTRAP_PREFIX_GS:
			seg++;
			/*FALLTHRU*/
		case FASTTRAP_PREFIX_FS:
			seg++;
			/*FALLTHRU*/
		case FASTTRAP_PREFIX_ES:
			seg++;
			/*FALLTHRU*/
		case FASTTRAP_PREFIX_DS:
			seg++;
			/*FALLTHRU*/
		case FASTTRAP_PREFIX_CS:
			seg++;
			/*FALLTHRU*/
		case FASTTRAP_PREFIX_OPERAND:
		case FASTTRAP_PREFIX_ADDRESS:
		case FASTTRAP_PREFIX_LOCK:
		case FASTTRAP_PREFIX_REP:
		case FASTTRAP_PREFIX_REPNE:
			if (seg != 0) {
				/*
				 * It's illegal for an instruction to specify
				 * two segment prefixes -- give up on this
				 * illegal instruction.
				 */
				if (tp->ftt_segment != FASTTRAP_SEG_NONE)
					return (-1);

				tp->ftt_segment = seg;
			}
			start++;
			continue;
		}
		break;
	}

#if __sol64 || defined(__APPLE__)
	/*
	 * Identify the REX prefix on 64-bit processes.
	 */
	if (p_model == DATAMODEL_LP64 && (instr[start] & 0xf0) == 0x40)
		rex = instr[start++];
#endif

	/*
	 * Now that we're pretty sure that the instruction is okay, copy the
	 * valid part to the tracepoint.
	 */
	bcopy(instr, tp->ftt_instr, FASTTRAP_MAX_INSTR_SIZE);

	tp->ftt_type = FASTTRAP_T_COMMON;
	if (instr[start] == FASTTRAP_2_BYTE_OP) {
		switch (instr[start + 1]) {
		case FASTTRAP_0F_JO:
		case FASTTRAP_0F_JNO:
		case FASTTRAP_0F_JB:
		case FASTTRAP_0F_JAE:
		case FASTTRAP_0F_JE:
		case FASTTRAP_0F_JNE:
		case FASTTRAP_0F_JBE:
		case FASTTRAP_0F_JA:
		case FASTTRAP_0F_JS:
		case FASTTRAP_0F_JNS:
		case FASTTRAP_0F_JP:
		case FASTTRAP_0F_JNP:
		case FASTTRAP_0F_JL:
		case FASTTRAP_0F_JGE:
		case FASTTRAP_0F_JLE:
		case FASTTRAP_0F_JG:
			tp->ftt_type = FASTTRAP_T_JCC;
			tp->ftt_code = (instr[start + 1] & 0x0f) | FASTTRAP_JO;
			tp->ftt_dest = pc + tp->ftt_size +
			    *(int32_t *)&instr[start + 2];
			break;
		}
	} else if (instr[start] == FASTTRAP_GROUP5_OP) {
		uint_t mod = FASTTRAP_MODRM_MOD(instr[start + 1]);
		uint_t reg = FASTTRAP_MODRM_REG(instr[start + 1]);
		uint_t rm = FASTTRAP_MODRM_RM(instr[start + 1]);

		if (reg == 2 || reg == 4) {
			uint_t i, sz;

			if (reg == 2)
				tp->ftt_type = FASTTRAP_T_CALL;
			else
				tp->ftt_type = FASTTRAP_T_JMP;

			if (mod == 3)
				tp->ftt_code = 2;
			else
				tp->ftt_code = 1;

			ASSERT(p_model == DATAMODEL_LP64 || rex == 0);

			/*
			 * See AMD x86-64 Architecture Programmer's Manual
			 * Volume 3, Section 1.2.7, Table 1-12, and
			 * Appendix A.3.1, Table A-15.
			 */
			if (mod != 3 && rm == 4) {
				uint8_t sib = instr[start + 2];
				uint_t index = FASTTRAP_SIB_INDEX(sib);
				uint_t base = FASTTRAP_SIB_BASE(sib);

				tp->ftt_scale = FASTTRAP_SIB_SCALE(sib);

				tp->ftt_index = (index == 4) ?
				    FASTTRAP_NOREG :
				    regmap[index | (FASTTRAP_REX_X(rex) << 3)];
				tp->ftt_base = (mod == 0 && base == 5) ?
				    FASTTRAP_NOREG :
				    regmap[base | (FASTTRAP_REX_B(rex) << 3)];

				i = 3;
				sz = mod == 1 ? 1 : 4;
			} else {
				/*
				 * In 64-bit mode, mod == 0 and r/m == 5
				 * denotes %rip-relative addressing; in 32-bit
				 * mode, the base register isn't used. In both
				 * modes, there is a 32-bit operand.
				 */
				if (mod == 0 && rm == 5) {
#if __sol64 || defined(__APPLE__)
					if (p_model == DATAMODEL_LP64)
						tp->ftt_base = REG_RIP;
					else
#endif
						tp->ftt_base = FASTTRAP_NOREG;
					sz = 4;
				} else  {
					uint8_t base = rm |
					    (FASTTRAP_REX_B(rex) << 3);

					tp->ftt_base = regmap[base];
					sz = mod == 1 ? 1 : mod == 2 ? 4 : 0;
				}
				tp->ftt_index = FASTTRAP_NOREG;
				i = 2;
			}

			if (sz == 1)
				tp->ftt_dest = *(int8_t *)&instr[start + i];
			else if (sz == 4)
				tp->ftt_dest = *(int32_t *)&instr[start + i];
			else
				tp->ftt_dest = 0;
		}
	} else {
		switch (instr[start]) {
		case FASTTRAP_RET:
			tp->ftt_type = FASTTRAP_T_RET;
			break;

		case FASTTRAP_RET16:
			tp->ftt_type = FASTTRAP_T_RET16;
			tp->ftt_dest = *(uint16_t *)&instr[start + 1];
			break;

		case FASTTRAP_JO:
		case FASTTRAP_JNO:
		case FASTTRAP_JB:
		case FASTTRAP_JAE:
		case FASTTRAP_JE:
		case FASTTRAP_JNE:
		case FASTTRAP_JBE:
		case FASTTRAP_JA:
		case FASTTRAP_JS:
		case FASTTRAP_JNS:
		case FASTTRAP_JP:
		case FASTTRAP_JNP:
		case FASTTRAP_JL:
		case FASTTRAP_JGE:
		case FASTTRAP_JLE:
		case FASTTRAP_JG:
			tp->ftt_type = FASTTRAP_T_JCC;
			tp->ftt_code = instr[start];
			tp->ftt_dest = pc + tp->ftt_size +
			    (int8_t)instr[start + 1];
			break;

		case FASTTRAP_LOOPNZ:
		case FASTTRAP_LOOPZ:
		case FASTTRAP_LOOP:
			tp->ftt_type = FASTTRAP_T_LOOP;
			tp->ftt_code = instr[start];
			tp->ftt_dest = pc + tp->ftt_size +
			    (int8_t)instr[start + 1];
			break;

		case FASTTRAP_JCXZ:
			tp->ftt_type = FASTTRAP_T_JCXZ;
			tp->ftt_dest = pc + tp->ftt_size +
			    (int8_t)instr[start + 1];
			break;

		case FASTTRAP_CALL:
			tp->ftt_type = FASTTRAP_T_CALL;
			tp->ftt_dest = pc + tp->ftt_size +
			    *(int32_t *)&instr[start + 1];
			tp->ftt_code = 0;
			break;

		case FASTTRAP_JMP32:
			tp->ftt_type = FASTTRAP_T_JMP;
			tp->ftt_dest = pc + tp->ftt_size +
			    *(int32_t *)&instr[start + 1];
			break;
		case FASTTRAP_JMP8:
			tp->ftt_type = FASTTRAP_T_JMP;
			tp->ftt_dest = pc + tp->ftt_size +
			    (int8_t)instr[start + 1];
			break;

		case FASTTRAP_PUSHL_EBP:
			if (start == 0)
				tp->ftt_type = FASTTRAP_T_PUSHL_EBP;
			break;

		case FASTTRAP_NOP:
#if __sol64 || defined(__APPLE__)
			ASSERT(p_model == DATAMODEL_LP64 || rex == 0);

			/*
			 * On sol64 we have to be careful not to confuse a nop
			 * (actually xchgl %eax, %eax) with an instruction using
			 * the same opcode, but that does something different
			 * (e.g. xchgl %r8d, %eax or xcghq %r8, %rax).
			 */
			if (FASTTRAP_REX_B(rex) == 0)
#endif
				tp->ftt_type = FASTTRAP_T_NOP;
			break;

		case FASTTRAP_INT3:
			/*
			 * The pid provider shares the int3 trap with debugger
			 * breakpoints so we can't instrument them.
			 */
			ASSERT(instr[start] == FASTTRAP_INSTR);
			return (-1);

		case FASTTRAP_INT:
			/*
			 * Interrupts seem like they could be traced with
			 * no negative implications, but it's possible that
			 * a thread could be redirected by the trap handling
			 * code which would eventually return to the
			 * instruction after the interrupt. If the interrupt
			 * were in our scratch space, the subsequent
			 * instruction might be overwritten before we return.
			 * Accordingly we refuse to instrument any interrupt.
			 */
			return (-1);
		}
	}

#if __sol64 || defined(__APPLE__)
	if (p_model == DATAMODEL_LP64 && tp->ftt_type == FASTTRAP_T_COMMON) {
		/*
		 * If the process is 64-bit and the instruction type is still
		 * FASTTRAP_T_COMMON -- meaning we're going to copy it out an
		 * execute it -- we need to watch for %rip-relative
		 * addressing mode. See the portion of fasttrap_pid_probe()
		 * below where we handle tracepoints with type
		 * FASTTRAP_T_COMMON for how we emulate instructions that
		 * employ %rip-relative addressing.
		 */
		if (rmindex != -1) {
			uint_t mod = FASTTRAP_MODRM_MOD(instr[rmindex]);
			uint_t reg = FASTTRAP_MODRM_REG(instr[rmindex]);
			uint_t rm = FASTTRAP_MODRM_RM(instr[rmindex]);

			ASSERT(rmindex > (int)start);

			if (mod == 0 && rm == 5) {
				/*
				 * We need to be sure to avoid other
				 * registers used by this instruction. While
				 * the reg field may determine the op code
				 * rather than denoting a register, assuming
				 * that it denotes a register is always safe.
				 * We leave the REX field intact and use
				 * whatever value's there for simplicity.
				 */
				if (reg != 0) {
					tp->ftt_ripmode = FASTTRAP_RIP_1 |
					    (FASTTRAP_RIP_X *
					    FASTTRAP_REX_B(rex));
					rm = 0;
				} else {
					tp->ftt_ripmode = FASTTRAP_RIP_2 |
					    (FASTTRAP_RIP_X *
					    FASTTRAP_REX_B(rex));
					rm = 1;
				}

				tp->ftt_modrm = tp->ftt_instr[rmindex];
				tp->ftt_instr[rmindex] =
				    FASTTRAP_MODRM(2, reg, rm);
			}
		}
	}
#endif

	return (0);
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	fasttrap_instr_t instr = FASTTRAP_INSTR;

	if (uwrite(p, &instr, 1, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint8_t instr;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (uread(p, &instr, 1, tp->ftt_pc) != 0)
		return (0);
	if (instr != FASTTRAP_INSTR)
		return (0);
	if (uwrite(p, &tp->ftt_instr[0], 1, tp->ftt_pc) != 0)
		return (-1);

	return (0);
}

static void
fasttrap_return_common(x86_saved_state_t *regs, user_addr_t pc, pid_t pid,
    user_addr_t new_pc)
{
	x86_saved_state64_t *regs64;
	x86_saved_state32_t *regs32;
	unsigned int p_model;

        if (is_saved_state64(regs)) {
                regs64 = saved_state64(regs);
		regs32 = NULL;
		p_model = DATAMODEL_LP64;
        } else {
		regs64 = NULL;
                regs32 = saved_state32(regs);
		p_model = DATAMODEL_ILP32;
        }

	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;
	lck_mtx_t *pid_mtx;

	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    !tp->ftt_proc->ftpc_defunct)
			break;
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
		/*
		 * If there's a branch that could act as a return site, we
		 * need to trace it, and check here if the program counter is
		 * external to the function.
		 */
		if (tp->ftt_type != FASTTRAP_T_RET &&
		    tp->ftt_type != FASTTRAP_T_RET16 &&
		    new_pc - id->fti_probe->ftp_faddr <
		    id->fti_probe->ftp_fsize)
			continue;

		if (p_model == DATAMODEL_LP64) {
			dtrace_probe(id->fti_probe->ftp_id,
				     pc - id->fti_probe->ftp_faddr,
				     regs64->rax, regs64->rdx, 0, 0);
		} else {
			dtrace_probe(id->fti_probe->ftp_id,
				     pc - id->fti_probe->ftp_faddr,
				     regs32->eax, regs32->edx, 0, 0);
		}
	}

	lck_mtx_unlock(pid_mtx);
}

static void
fasttrap_sigsegv(proc_t *p, uthread_t t, user_addr_t addr)
{	
	proc_lock(p);

	/* Set fault address and mark signal */
	t->uu_code = addr;
	t->uu_siglist |= sigmask(SIGSEGV);

	/* 
         * XXX These two line may be redundant; if not, then we need
	 * XXX to potentially set the data address in the machine
	 * XXX specific thread state structure to indicate the address.
	 */
	t->uu_exception = KERN_INVALID_ADDRESS;		/* SIGSEGV */
	t->uu_subcode = 0;	/* XXX pad */

	proc_unlock(p);

	/* raise signal */
	signal_setast(t->uu_context.vc_thread);
}

static void
fasttrap_usdt_args64(fasttrap_probe_t *probe, x86_saved_state64_t *regs64, int argc,
    uint64_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);
	user_addr_t stack = (user_addr_t)regs64->isf.rsp;

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		if (x < 6) {
			/* FIXME! This may be broken, needs testing */
			argv[i] = (&regs64->rdi)[x];
		} else {
			fasttrap_fuword64_noerr(stack + (x * sizeof(uint64_t)), &argv[i]);
		}
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}
}

static void
fasttrap_usdt_args32(fasttrap_probe_t *probe, x86_saved_state32_t *regs32, int argc,
    uint32_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);
	uint32_t *stack = (uint32_t *)regs32->uesp;

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[x], &argv[i]);
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}
}

/*
 * FIXME!
 */
static int
fasttrap_do_seg(fasttrap_tracepoint_t *tp, x86_saved_state_t *rp, user_addr_t *addr) // 64 bit
{
#pragma unused(tp, rp, addr)
	printf("fasttrap_do_seg() called while unimplemented.\n");
#if 0
	proc_t *p = curproc;
	user_desc_t *desc;
	uint16_t sel, ndx, type;
	uintptr_t limit;

	switch (tp->ftt_segment) {
	case FASTTRAP_SEG_CS:
		sel = rp->r_cs;
		break;
	case FASTTRAP_SEG_DS:
		sel = rp->r_ds;
		break;
	case FASTTRAP_SEG_ES:
		sel = rp->r_es;
		break;
	case FASTTRAP_SEG_FS:
		sel = rp->r_fs;
		break;
	case FASTTRAP_SEG_GS:
		sel = rp->r_gs;
		break;
	case FASTTRAP_SEG_SS:
		sel = rp->r_ss;
		break;
	}

	/*
	 * Make sure the given segment register specifies a user priority
	 * selector rather than a kernel selector.
	 */
	if (!SELISUPL(sel))
		return (-1);

	ndx = SELTOIDX(sel);

	/*
	 * Check the bounds and grab the descriptor out of the specified
	 * descriptor table.
	 */
	if (SELISLDT(sel)) {
		if (ndx > p->p_ldtlimit)
			return (-1);

		desc = p->p_ldt + ndx;

	} else {
		if (ndx >= NGDT)
			return (-1);

		desc = cpu_get_gdt() + ndx;
	}

	/*
	 * The descriptor must have user privilege level and it must be
	 * present in memory.
	 */
	if (desc->usd_dpl != SEL_UPL || desc->usd_p != 1)
		return (-1);

	type = desc->usd_type;

	/*
	 * If the S bit in the type field is not set, this descriptor can
	 * only be used in system context.
	 */
	if ((type & 0x10) != 0x10)
		return (-1);

	limit = USEGD_GETLIMIT(desc) * (desc->usd_gran ? PAGESIZE : 1);

	if (tp->ftt_segment == FASTTRAP_SEG_CS) {
		/*
		 * The code/data bit and readable bit must both be set.
		 */
		if ((type & 0xa) != 0xa)
			return (-1);

		if (*addr > limit)
			return (-1);
	} else {
		/*
		 * The code/data bit must be clear.
		 */
		if ((type & 0x8) != 0)
			return (-1);

		/*
		 * If the expand-down bit is clear, we just check the limit as
		 * it would naturally be applied. Otherwise, we need to check
		 * that the address is the range [limit + 1 .. 0xffff] or
		 * [limit + 1 ... 0xffffffff] depending on if the default
		 * operand size bit is set.
		 */
		if ((type & 0x4) == 0) {
			if (*addr > limit)
				return (-1);
		} else if (desc->usd_def32) {
			if (*addr < limit + 1 || 0xffff < *addr)
				return (-1);
		} else {
			if (*addr < limit + 1 || 0xffffffff < *addr)
				return (-1);
		}
	}

	*addr += USEGD_GETBASE(desc);
#endif /* 0 */
	return (0);
}

/*
 * Due to variances between Solaris and xnu, I have split this into a 32 bit and 64 bit
 * code path. It still takes an x86_saved_state_t* argument, because it must sometimes
 * call other methods that require a x86_saved_state_t.
 *
 * NOTE!!!!
 *
 * Any changes made to this method must be echo'd in fasttrap_pid_probe64!
 *
 */
static int
fasttrap_pid_probe32(x86_saved_state_t *regs)
{
	ASSERT(is_saved_state32(regs));

	x86_saved_state32_t *regs32  = saved_state32(regs);
	user_addr_t pc = regs32->eip - 1;
	proc_t *p = current_proc();
	user_addr_t new_pc = 0;
	fasttrap_bucket_t *bucket;
	lck_mtx_t *pid_mtx;
	fasttrap_tracepoint_t *tp, tp_local;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

	/*
	 * It's possible that a user (in a veritable orgy of bad planning)
	 * could redirect this thread's flow of control before it reached the
	 * return probe fasttrap. In this case we need to kill the process
	 * since it's in a unrecoverable state.
	 */
	if (uthread->t_dtrace_step) {
		ASSERT(uthread->t_dtrace_on);
		fasttrap_sigtrap(p, uthread, pc);
		return (0);
	}

	/*
	 * Clear all user tracing flags.
	 */
	uthread->t_dtrace_ft = 0;
	uthread->t_dtrace_pc = 0;
	uthread->t_dtrace_npc = 0;
	uthread->t_dtrace_scrpc = 0;
	uthread->t_dtrace_astpc = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	/*
	 * APPLE NOTE: Terry says: "You need to hold the process locks (currently: kernel funnel) for this traversal"
	 * FIXME: How do we assert this?
	 */
	while (p->p_lflag & P_LINVFORK)
		p = p->p_pptr;

	pid = p->p_pid;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    !tp->ftt_proc->ftpc_defunct)
			break;
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return (-1);
	}

	/*
	 * Set the program counter to the address of the traced instruction
	 * so that it looks right in ustack() output.
	 */
	regs32->eip = pc;

	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;
		
		uint32_t s0, s1, s2, s3, s4, s5;
		uint32_t *stack = (uint32_t *)regs32->uesp;
		
		/*
		 * In 32-bit mode, all arguments are passed on the
		 * stack. If this is a function entry probe, we need
		 * to skip the first entry on the stack as it
		 * represents the return address rather than a
		 * parameter to the function.
		 */
		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[0], &s0);
		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[1], &s1);
		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[2], &s2);
		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[3], &s3);
		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[4], &s4);
		fasttrap_fuword32_noerr((user_addr_t)(unsigned long)&stack[5], &s5);
		
		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;
			
			if (id->fti_ptype == DTFTP_ENTRY) {
				/*
				 * We note that this was an entry
				 * probe to help ustack() find the
				 * first caller.
				 */
				cookie = dtrace_interrupt_disable();
				DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
				dtrace_probe(probe->ftp_id, s1, s2,
					     s3, s4, s5);
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
				dtrace_probe(probe->ftp_id, s0, s1,
					     s2, s3, s4);
			} else {
				uint32_t t[5];
				
				fasttrap_usdt_args32(probe, regs32,
						     sizeof (t) / sizeof (t[0]), t);
				
				dtrace_probe(probe->ftp_id, t[0], t[1],
					     t[2], t[3], t[4]);
			}

			/* APPLE NOTE: Oneshot probes get one and only one chance... */
			if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
				fasttrap_tracepoint_remove(p, tp);
			}
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
	 * Set the program counter to appear as though the traced instruction
	 * had completely executed. This ensures that fasttrap_getreg() will
	 * report the expected value for REG_RIP.
	 */
	regs32->eip = pc + tp->ftt_size;

	/*
	 * If there's an is-enabled probe connected to this tracepoint it
	 * means that there was a 'xorl %eax, %eax' or 'xorq %rax, %rax'
	 * instruction that was placed there by DTrace when the binary was
	 * linked. As this probe is, in fact, enabled, we need to stuff 1
	 * into %eax or %rax. Accordingly, we can bypass all the instruction
	 * emulation logic since we know the inevitable result. It's possible
	 * that a user could construct a scenario where the 'is-enabled'
	 * probe was on some other instruction, but that would be a rather
	 * exotic way to shoot oneself in the foot.
	 */
	if (is_enabled) {
		regs32->eax = 1;
		new_pc = regs32->eip;
		goto done;
	}

	/*
	 * We emulate certain types of instructions to ensure correctness
	 * (in the case of position dependent instructions) or optimize
	 * common cases. The rest we have the thread execute back in user-
	 * land.
	 */
	switch (tp->ftt_type) {
		case FASTTRAP_T_RET:
		case FASTTRAP_T_RET16:
		{
			user_addr_t dst;
			user_addr_t addr;
			int ret;

			/*
			 * We have to emulate _every_ facet of the behavior of a ret
			 * instruction including what happens if the load from %esp
			 * fails; in that case, we send a SIGSEGV.
			 */
			uint32_t dst32;
			ret = fasttrap_fuword32((user_addr_t)regs32->uesp, &dst32);
			dst = dst32;
			addr = regs32->uesp + sizeof (uint32_t);

			if (ret == -1) {
				fasttrap_sigsegv(p, uthread, (user_addr_t)regs32->uesp);
				new_pc = pc;
				break;
			}
			
			if (tp->ftt_type == FASTTRAP_T_RET16)
				addr += tp->ftt_dest;
			
			regs32->uesp = addr;
			new_pc = dst;
			break;
		}

		case FASTTRAP_T_JCC:
		{
			uint_t taken;
			
			switch (tp->ftt_code) {
				case FASTTRAP_JO:
					taken = (regs32->efl & FASTTRAP_EFLAGS_OF) != 0;
					break;
				case FASTTRAP_JNO:
					taken = (regs32->efl & FASTTRAP_EFLAGS_OF) == 0;
					break;
				case FASTTRAP_JB:
					taken = (regs32->efl & FASTTRAP_EFLAGS_CF) != 0;
					break;
				case FASTTRAP_JAE:
					taken = (regs32->efl & FASTTRAP_EFLAGS_CF) == 0;
					break;
				case FASTTRAP_JE:
					taken = (regs32->efl & FASTTRAP_EFLAGS_ZF) != 0;
					break;
				case FASTTRAP_JNE:
					taken = (regs32->efl & FASTTRAP_EFLAGS_ZF) == 0;
					break;
				case FASTTRAP_JBE:
					taken = (regs32->efl & FASTTRAP_EFLAGS_CF) != 0 ||
						(regs32->efl & FASTTRAP_EFLAGS_ZF) != 0;
					break;
				case FASTTRAP_JA:
					taken = (regs32->efl & FASTTRAP_EFLAGS_CF) == 0 &&
						(regs32->efl & FASTTRAP_EFLAGS_ZF) == 0;
					break;
				case FASTTRAP_JS:
					taken = (regs32->efl & FASTTRAP_EFLAGS_SF) != 0;
					break;
				case FASTTRAP_JNS:
					taken = (regs32->efl & FASTTRAP_EFLAGS_SF) == 0;
					break;
				case FASTTRAP_JP:
					taken = (regs32->efl & FASTTRAP_EFLAGS_PF) != 0;
					break;
				case FASTTRAP_JNP:
					taken = (regs32->efl & FASTTRAP_EFLAGS_PF) == 0;
					break;
				case FASTTRAP_JL:
					taken = ((regs32->efl & FASTTRAP_EFLAGS_SF) == 0) !=
						((regs32->efl & FASTTRAP_EFLAGS_OF) == 0);
					break;
				case FASTTRAP_JGE:
					taken = ((regs32->efl & FASTTRAP_EFLAGS_SF) == 0) ==
						((regs32->efl & FASTTRAP_EFLAGS_OF) == 0);
					break;
				case FASTTRAP_JLE:
					taken = (regs32->efl & FASTTRAP_EFLAGS_ZF) != 0 ||
						((regs32->efl & FASTTRAP_EFLAGS_SF) == 0) !=
						((regs32->efl & FASTTRAP_EFLAGS_OF) == 0);
					break;
				case FASTTRAP_JG:
					taken = (regs32->efl & FASTTRAP_EFLAGS_ZF) == 0 &&
						((regs32->efl & FASTTRAP_EFLAGS_SF) == 0) ==
						((regs32->efl & FASTTRAP_EFLAGS_OF) == 0);
					break;
				default:
					taken = FALSE;
			}
			
			if (taken)
				new_pc = tp->ftt_dest;
			else
				new_pc = pc + tp->ftt_size;
			break;
		}

		case FASTTRAP_T_LOOP:
		{
			uint_t taken;
			greg_t cx = regs32->ecx--;

			switch (tp->ftt_code) {
				case FASTTRAP_LOOPNZ:
					taken = (regs32->efl & FASTTRAP_EFLAGS_ZF) == 0 &&
						cx != 0;
					break;
				case FASTTRAP_LOOPZ:
					taken = (regs32->efl & FASTTRAP_EFLAGS_ZF) != 0 &&
						cx != 0;
					break;
				case FASTTRAP_LOOP:
					taken = (cx != 0);
					break;
				default:
					taken = FALSE;
			}
			
			if (taken)
				new_pc = tp->ftt_dest;
			else
				new_pc = pc + tp->ftt_size;
			break;
		}

		case FASTTRAP_T_JCXZ:
		{
			greg_t cx = regs32->ecx;
			
			if (cx == 0)
				new_pc = tp->ftt_dest;
			else
				new_pc = pc + tp->ftt_size;
			break;
		}

		case FASTTRAP_T_PUSHL_EBP:
		{
			user_addr_t addr = regs32->uesp - sizeof (uint32_t);
			int ret = fasttrap_suword32(addr, (uint32_t)regs32->ebp);
			
			if (ret == -1) {
				fasttrap_sigsegv(p, uthread, addr);
				new_pc = pc;
				break;
			}
			
			regs32->uesp = addr;
			new_pc = pc + tp->ftt_size;
			break;
		}
		
		case FASTTRAP_T_NOP:
			new_pc = pc + tp->ftt_size;
			break;

		case FASTTRAP_T_JMP:
		case FASTTRAP_T_CALL:
			if (tp->ftt_code == 0) {
				new_pc = tp->ftt_dest;
			} else {
				user_addr_t /* value ,*/ addr = tp->ftt_dest;

				if (tp->ftt_base != FASTTRAP_NOREG)
					addr += fasttrap_getreg(regs, tp->ftt_base);
				if (tp->ftt_index != FASTTRAP_NOREG)
					addr += fasttrap_getreg(regs, tp->ftt_index) <<
						tp->ftt_scale;
				
				if (tp->ftt_code == 1) {
					/*
					 * If there's a segment prefix for this
					 * instruction, we'll need to check permissions
					 * and bounds on the given selector, and adjust
					 * the address accordingly.
					 */
					if (tp->ftt_segment != FASTTRAP_SEG_NONE &&
					    fasttrap_do_seg(tp, regs, &addr) != 0) {
						fasttrap_sigsegv(p, uthread, addr);
						new_pc = pc;
						break;
					}
					
					uint32_t value32;
					addr = (user_addr_t)(uint32_t)addr;
					if (fasttrap_fuword32(addr, &value32) == -1) {
						fasttrap_sigsegv(p, uthread, addr);
						new_pc = pc;
						break;
					}
					new_pc = value32;
				} else {
					new_pc = addr;
				}
			}

			/*
			 * If this is a call instruction, we need to push the return
			 * address onto the stack. If this fails, we send the process
			 * a SIGSEGV and reset the pc to emulate what would happen if
			 * this instruction weren't traced.
			 */
			if (tp->ftt_type == FASTTRAP_T_CALL) {
				user_addr_t addr = regs32->uesp - sizeof (uint32_t);
				int ret = fasttrap_suword32(addr, (uint32_t)(pc + tp->ftt_size));
				
				if (ret == -1) {
					fasttrap_sigsegv(p, uthread, addr);
					new_pc = pc;
					break;
				}
				
				regs32->uesp = addr;
			}
			break;

		case FASTTRAP_T_COMMON:
		{
			user_addr_t addr;
			uint8_t scratch[2 * FASTTRAP_MAX_INSTR_SIZE + 5 + 2];
			uint_t i = 0;

			/*
			 * Generic Instruction Tracing
			 * ---------------------------
			 *
			 * This is the layout of the scratch space in the user-land
			 * thread structure for our generated instructions.
			 *
			 *	32-bit mode			bytes
			 *	------------------------	-----
			 * a:	<original instruction>		<= 15
			 *	jmp	<pc + tp->ftt_size>	    5
			 * b:	<original instrction>		<= 15
			 *	int	T_DTRACE_RET		    2
			 *					-----
			 *					<= 37
			 *
			 *	64-bit mode			bytes
			 *	------------------------	-----
			 * a:	<original instruction>		<= 15
			 *	jmp	0(%rip)			    6
			 *	<pc + tp->ftt_size>		    8
			 * b:	<original instruction>		<= 15
			 * 	int	T_DTRACE_RET		    2
			 * 					-----
			 * 					<= 46
			 *
			 * The %pc is set to a, and curthread->t_dtrace_astpc is set
			 * to b. If we encounter a signal on the way out of the
			 * kernel, trap() will set %pc to curthread->t_dtrace_astpc
			 * so that we execute the original instruction and re-enter
			 * the kernel rather than redirecting to the next instruction.
			 *
			 * If there are return probes (so we know that we're going to
			 * need to reenter the kernel after executing the original
			 * instruction), the scratch space will just contain the
			 * original instruction followed by an interrupt -- the same
			 * data as at b.
			 */

			addr = uthread->t_dtrace_scratch->addr;

			if (addr == 0LL) {
				fasttrap_sigtrap(p, uthread, pc); // Should be killing target proc
				new_pc = pc;
				break;
			}

			ASSERT(tp->ftt_size < FASTTRAP_MAX_INSTR_SIZE);

			uthread->t_dtrace_scrpc = addr;
			bcopy(tp->ftt_instr, &scratch[i], tp->ftt_size);
			i += tp->ftt_size;

			/*
			 * Set up the jmp to the next instruction; note that
			 * the size of the traced instruction cancels out.
			 */
			scratch[i++] = FASTTRAP_JMP32;
			*(uint32_t *)&scratch[i] = pc - addr - 5;
			i += sizeof (uint32_t);

			uthread->t_dtrace_astpc = addr + i;
			bcopy(tp->ftt_instr, &scratch[i], tp->ftt_size);
			i += tp->ftt_size;
			scratch[i++] = FASTTRAP_INT;
			scratch[i++] = T_DTRACE_RET;
			
			if (fasttrap_copyout(scratch, addr, i)) {
				fasttrap_sigtrap(p, uthread, pc);
				new_pc = pc;
				break;
			}
			
			if (tp->ftt_retids != NULL) {
				uthread->t_dtrace_step = 1;
				uthread->t_dtrace_ret = 1;
				new_pc = uthread->t_dtrace_astpc;
			} else {
				new_pc = uthread->t_dtrace_scrpc;
			}
			
			uthread->t_dtrace_pc = pc;
			uthread->t_dtrace_npc = pc + tp->ftt_size;
			uthread->t_dtrace_on = 1;
			break;
		}
		
		default:
			panic("fasttrap: mishandled an instruction");
	}
	
done:
	/*
	 * APPLE NOTE:
	 *
	 * We're setting this earlier than Solaris does, to get a "correct"
	 * ustack() output. In the Sun code,  a() -> b() -> c() -> d() is
	 * reported at: d, b, a. The new way gives c, b, a, which is closer
	 * to correct, as the return instruction has already exectued.
	 */
	regs32->eip = new_pc;

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
		if (tp->ftt_type != FASTTRAP_T_COMMON) {
			fasttrap_return_common(regs, pc, pid, new_pc);
		} else {
			ASSERT(uthread->t_dtrace_ret != 0);
			ASSERT(uthread->t_dtrace_pc == pc);
			ASSERT(uthread->t_dtrace_scrpc != 0);
			ASSERT(new_pc == uthread->t_dtrace_astpc);
		}
	}

	return (0);
}

/*
 * Due to variances between Solaris and xnu, I have split this into a 32 bit and 64 bit
 * code path. It still takes an x86_saved_state_t* argument, because it must sometimes
 * call other methods that require a x86_saved_state_t.
 *
 * NOTE!!!!
 *
 * Any changes made to this method must be echo'd in fasttrap_pid_probe32!
 *
 */
static int
fasttrap_pid_probe64(x86_saved_state_t *regs)
{
	ASSERT(is_saved_state64(regs));

	x86_saved_state64_t *regs64 = saved_state64(regs);
	user_addr_t pc = regs64->isf.rip - 1;
	proc_t *p = current_proc();
	user_addr_t new_pc = 0;
	fasttrap_bucket_t *bucket;
	lck_mtx_t *pid_mtx;
	fasttrap_tracepoint_t *tp, tp_local;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

	/*
	 * It's possible that a user (in a veritable orgy of bad planning)
	 * could redirect this thread's flow of control before it reached the
	 * return probe fasttrap. In this case we need to kill the process
	 * since it's in a unrecoverable state.
	 */
	if (uthread->t_dtrace_step) {
		ASSERT(uthread->t_dtrace_on);
		fasttrap_sigtrap(p, uthread, pc);
		return (0);
	}

	/*
	 * Clear all user tracing flags.
	 */
	uthread->t_dtrace_ft = 0;
	uthread->t_dtrace_pc = 0;
	uthread->t_dtrace_npc = 0;
	uthread->t_dtrace_scrpc = 0;
	uthread->t_dtrace_astpc = 0;
	uthread->t_dtrace_regv = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	/*
	 * APPLE NOTE: Terry says: "You need to hold the process locks (currently: kernel funnel) for this traversal"
	 * FIXME: How do we assert this?
	 */
	while (p->p_lflag & P_LINVFORK)
		p = p->p_pptr;

	pid = p->p_pid;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    !tp->ftt_proc->ftpc_defunct)
			break;
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return (-1);
	}

	/*
	 * Set the program counter to the address of the traced instruction
	 * so that it looks right in ustack() output.
	 */
	regs64->isf.rip = pc;

	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;

		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;
			
			if (id->fti_ptype == DTFTP_ENTRY) {
				/*
				 * We note that this was an entry
				 * probe to help ustack() find the
				 * first caller.
				 */
				cookie = dtrace_interrupt_disable();
				DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
				dtrace_probe(probe->ftp_id, regs64->rdi,
					     regs64->rsi, regs64->rdx, regs64->rcx,
					     regs64->r8);
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
				dtrace_probe(probe->ftp_id, regs64->rdi,
					     regs64->rsi, regs64->rdx, regs64->rcx,
					     regs64->r8);
			} else {
				uint64_t t[5];
				
				fasttrap_usdt_args64(probe, regs64,
						     sizeof (t) / sizeof (t[0]), t);
				
				dtrace_probe(probe->ftp_id, t[0], t[1],
					     t[2], t[3], t[4]);
			}

			/* APPLE NOTE: Oneshot probes get one and only one chance... */
			if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
				fasttrap_tracepoint_remove(p, tp);
			}
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
	 * Set the program counter to appear as though the traced instruction
	 * had completely executed. This ensures that fasttrap_getreg() will
	 * report the expected value for REG_RIP.
	 */
	regs64->isf.rip = pc + tp->ftt_size;

	/*
	 * If there's an is-enabled probe connected to this tracepoint it
	 * means that there was a 'xorl %eax, %eax' or 'xorq %rax, %rax'
	 * instruction that was placed there by DTrace when the binary was
	 * linked. As this probe is, in fact, enabled, we need to stuff 1
	 * into %eax or %rax. Accordingly, we can bypass all the instruction
	 * emulation logic since we know the inevitable result. It's possible
	 * that a user could construct a scenario where the 'is-enabled'
	 * probe was on some other instruction, but that would be a rather
	 * exotic way to shoot oneself in the foot.
	 */
	if (is_enabled) {
		regs64->rax = 1;
		new_pc = regs64->isf.rip;
		goto done;
	}

	/*
	 * We emulate certain types of instructions to ensure correctness
	 * (in the case of position dependent instructions) or optimize
	 * common cases. The rest we have the thread execute back in user-
	 * land.
	 */
	switch (tp->ftt_type) {
		case FASTTRAP_T_RET:
		case FASTTRAP_T_RET16:
		{
			user_addr_t dst;
			user_addr_t addr;
			int ret;
			
			/*
			 * We have to emulate _every_ facet of the behavior of a ret
			 * instruction including what happens if the load from %esp
			 * fails; in that case, we send a SIGSEGV.
			 */
			ret = fasttrap_fuword64((user_addr_t)regs64->isf.rsp, &dst);
			addr = regs64->isf.rsp + sizeof (uint64_t);
			
			if (ret == -1) {
				fasttrap_sigsegv(p, uthread, (user_addr_t)regs64->isf.rsp);
				new_pc = pc;
				break;
			}
			
			if (tp->ftt_type == FASTTRAP_T_RET16)
				addr += tp->ftt_dest;
			
			regs64->isf.rsp = addr;
			new_pc = dst;
			break;
		}
		
		case FASTTRAP_T_JCC:
		{
			uint_t taken;
			
			switch (tp->ftt_code) {
				case FASTTRAP_JO:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_OF) != 0;
					break;
				case FASTTRAP_JNO:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_OF) == 0;
					break;
				case FASTTRAP_JB:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_CF) != 0;
					break;
				case FASTTRAP_JAE:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_CF) == 0;
					break;
				case FASTTRAP_JE:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) != 0;
					break;
				case FASTTRAP_JNE:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) == 0;
					break;
				case FASTTRAP_JBE:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_CF) != 0 ||
						(regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) != 0;
					break;
				case FASTTRAP_JA:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_CF) == 0 &&
						(regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) == 0;
					break;
				case FASTTRAP_JS:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_SF) != 0;
					break;
				case FASTTRAP_JNS:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_SF) == 0;
					break;
				case FASTTRAP_JP:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_PF) != 0;
					break;
				case FASTTRAP_JNP:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_PF) == 0;
					break;
				case FASTTRAP_JL:
					taken = ((regs64->isf.rflags & FASTTRAP_EFLAGS_SF) == 0) !=
						((regs64->isf.rflags & FASTTRAP_EFLAGS_OF) == 0);
					break;
				case FASTTRAP_JGE:
					taken = ((regs64->isf.rflags & FASTTRAP_EFLAGS_SF) == 0) ==
						((regs64->isf.rflags & FASTTRAP_EFLAGS_OF) == 0);
					break;
				case FASTTRAP_JLE:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) != 0 ||
						((regs64->isf.rflags & FASTTRAP_EFLAGS_SF) == 0) !=
						((regs64->isf.rflags & FASTTRAP_EFLAGS_OF) == 0);
					break;
				case FASTTRAP_JG:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) == 0 &&
						((regs64->isf.rflags & FASTTRAP_EFLAGS_SF) == 0) ==
						((regs64->isf.rflags & FASTTRAP_EFLAGS_OF) == 0);
					break;
				default:
					taken = FALSE;
			}
			
			if (taken)
				new_pc = tp->ftt_dest;
			else
				new_pc = pc + tp->ftt_size;
			break;
		}

		case FASTTRAP_T_LOOP:
		{
			uint_t taken;
			uint64_t cx = regs64->rcx--;
			
			switch (tp->ftt_code) {
				case FASTTRAP_LOOPNZ:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) == 0 &&
						cx != 0;
					break;
				case FASTTRAP_LOOPZ:
					taken = (regs64->isf.rflags & FASTTRAP_EFLAGS_ZF) != 0 &&
						cx != 0;
					break;
				case FASTTRAP_LOOP:
					taken = (cx != 0);
					break;
				default:
					taken = FALSE;
			}
			
			if (taken)
				new_pc = tp->ftt_dest;
			else
				new_pc = pc + tp->ftt_size;
			break;
		}
		
		case FASTTRAP_T_JCXZ:
		{
			uint64_t cx = regs64->rcx;

			if (cx == 0)
				new_pc = tp->ftt_dest;
			else
				new_pc = pc + tp->ftt_size;
			break;
		}

		case FASTTRAP_T_PUSHL_EBP:
		{
			user_addr_t addr = regs64->isf.rsp - sizeof (uint64_t);
			int ret = fasttrap_suword64(addr, (uint64_t)regs64->rbp);
			
			if (ret == -1) {
				fasttrap_sigsegv(p, uthread, addr);
				new_pc = pc;
				break;
			}
			
			regs64->isf.rsp = addr;
			new_pc = pc + tp->ftt_size;
			break;
		}
		
		case FASTTRAP_T_NOP:
			new_pc = pc + tp->ftt_size;
			break;

		case FASTTRAP_T_JMP:
		case FASTTRAP_T_CALL:
			if (tp->ftt_code == 0) {
				new_pc = tp->ftt_dest;
			} else {
				user_addr_t value, addr = tp->ftt_dest;
				
				if (tp->ftt_base != FASTTRAP_NOREG)
					addr += fasttrap_getreg(regs, tp->ftt_base);
				if (tp->ftt_index != FASTTRAP_NOREG)
					addr += fasttrap_getreg(regs, tp->ftt_index) <<
						tp->ftt_scale;
				
				if (tp->ftt_code == 1) {
					/*
					 * If there's a segment prefix for this
					 * instruction, we'll need to check permissions
					 * and bounds on the given selector, and adjust
					 * the address accordingly.
					 */
					if (tp->ftt_segment != FASTTRAP_SEG_NONE &&
					    fasttrap_do_seg(tp, regs, &addr) != 0) {
						fasttrap_sigsegv(p, uthread, addr);
						new_pc = pc;
						break;
					}
					
					if (fasttrap_fuword64(addr, &value) == -1) {
						fasttrap_sigsegv(p, uthread, addr);
						new_pc = pc;
						break;
					}
					new_pc = value;
				} else {
					new_pc = addr;
				}
			}

			/*
			 * If this is a call instruction, we need to push the return
			 * address onto the stack. If this fails, we send the process
			 * a SIGSEGV and reset the pc to emulate what would happen if
			 * this instruction weren't traced.
			 */
			if (tp->ftt_type == FASTTRAP_T_CALL) {
				user_addr_t addr = regs64->isf.rsp - sizeof (uint64_t);
				int ret = fasttrap_suword64(addr, pc + tp->ftt_size);
				
				if (ret == -1) {
					fasttrap_sigsegv(p, uthread, addr);
					new_pc = pc;
					break;
				}
				
				regs64->isf.rsp = addr;
			}
			break;

		case FASTTRAP_T_COMMON:
		{
			user_addr_t addr;
			uint8_t scratch[2 * FASTTRAP_MAX_INSTR_SIZE + 5 + 2];
			uint_t i = 0;
			
			/*
			 * Generic Instruction Tracing
			 * ---------------------------
			 *
			 * This is the layout of the scratch space in the user-land
			 * thread structure for our generated instructions.
			 *
			 *	32-bit mode			bytes
			 *	------------------------	-----
			 * a:	<original instruction>		<= 15
			 *	jmp	<pc + tp->ftt_size>	    5
			 * b:	<original instrction>		<= 15
			 *	int	T_DTRACE_RET		    2
			 *					-----
			 *					<= 37
			 *
			 *	64-bit mode			bytes
			 *	------------------------	-----
			 * a:	<original instruction>		<= 15
			 *	jmp	0(%rip)			    6
			 *	<pc + tp->ftt_size>		    8
			 * b:	<original instruction>		<= 15
			 * 	int	T_DTRACE_RET		    2
			 * 					-----
			 * 					<= 46
			 *
			 * The %pc is set to a, and curthread->t_dtrace_astpc is set
			 * to b. If we encounter a signal on the way out of the
			 * kernel, trap() will set %pc to curthread->t_dtrace_astpc
			 * so that we execute the original instruction and re-enter
			 * the kernel rather than redirecting to the next instruction.
			 *
			 * If there are return probes (so we know that we're going to
			 * need to reenter the kernel after executing the original
			 * instruction), the scratch space will just contain the
			 * original instruction followed by an interrupt -- the same
			 * data as at b.
			 *
			 * %rip-relative Addressing
			 * ------------------------
			 *
			 * There's a further complication in 64-bit mode due to %rip-
			 * relative addressing. While this is clearly a beneficial
			 * architectural decision for position independent code, it's
			 * hard not to see it as a personal attack against the pid
			 * provider since before there was a relatively small set of
			 * instructions to emulate; with %rip-relative addressing,
			 * almost every instruction can potentially depend on the
			 * address at which it's executed. Rather than emulating
			 * the broad spectrum of instructions that can now be
			 * position dependent, we emulate jumps and others as in
			 * 32-bit mode, and take a different tack for instructions
			 * using %rip-relative addressing.
			 *
			 * For every instruction that uses the ModRM byte, the
			 * in-kernel disassembler reports its location. We use the
			 * ModRM byte to identify that an instruction uses
			 * %rip-relative addressing and to see what other registers
			 * the instruction uses. To emulate those instructions,
			 * we modify the instruction to be %rax-relative rather than
			 * %rip-relative (or %rcx-relative if the instruction uses
			 * %rax; or %r8- or %r9-relative if the REX.B is present so
			 * we don't have to rewrite the REX prefix). We then load
			 * the value that %rip would have been into the scratch
			 * register and generate an instruction to reset the scratch
			 * register back to its original value. The instruction
			 * sequence looks like this:
			 *
			 *	64-mode %rip-relative		bytes
			 *	------------------------	-----
			 * a:	<modified instruction>		<= 15
			 *	movq	$<value>, %<scratch>	    6
			 *	jmp	0(%rip)			    6
			 *	<pc + tp->ftt_size>		    8
			 * b:	<modified instruction>  	<= 15
			 * 	int	T_DTRACE_RET		    2
			 * 					-----
			 *					   52
			 *
			 * We set curthread->t_dtrace_regv so that upon receiving
			 * a signal we can reset the value of the scratch register.
			 */

			addr = uthread->t_dtrace_scratch->addr;

			if (addr == 0LL) {
				fasttrap_sigtrap(p, uthread, pc); // Should be killing target proc
				new_pc = pc;
				break;
			}

			ASSERT(tp->ftt_size < FASTTRAP_MAX_INSTR_SIZE);

			uthread->t_dtrace_scrpc = addr;
			bcopy(tp->ftt_instr, &scratch[i], tp->ftt_size);
			i += tp->ftt_size;

			if (tp->ftt_ripmode != 0) {
				uint64_t* reg;
				
				ASSERT(tp->ftt_ripmode &
				       (FASTTRAP_RIP_1 | FASTTRAP_RIP_2));
				
				/*
				 * If this was a %rip-relative instruction, we change
				 * it to be either a %rax- or %rcx-relative
				 * instruction (depending on whether those registers
				 * are used as another operand; or %r8- or %r9-
				 * relative depending on the value of REX.B). We then
				 * set that register and generate a movq instruction
				 * to reset the value.
				 */
				if (tp->ftt_ripmode & FASTTRAP_RIP_X)
					scratch[i++] = FASTTRAP_REX(1, 0, 0, 1);
				else
					scratch[i++] = FASTTRAP_REX(1, 0, 0, 0);
				
				if (tp->ftt_ripmode & FASTTRAP_RIP_1)
					scratch[i++] = FASTTRAP_MOV_EAX;
				else
					scratch[i++] = FASTTRAP_MOV_ECX;
				
				switch (tp->ftt_ripmode) {
					case FASTTRAP_RIP_1:
						reg = &regs64->rax;
						uthread->t_dtrace_reg = REG_RAX;
						break;
					case FASTTRAP_RIP_2:
						reg = &regs64->rcx;
						uthread->t_dtrace_reg = REG_RCX;
						break;
					case FASTTRAP_RIP_1 | FASTTRAP_RIP_X:
						reg = &regs64->r8;
						uthread->t_dtrace_reg = REG_R8;
						break;
					case FASTTRAP_RIP_2 | FASTTRAP_RIP_X:
						reg = &regs64->r9;
						uthread->t_dtrace_reg = REG_R9;
						break;
					default:
						reg = NULL;
						panic("unhandled ripmode in fasttrap_pid_probe64");
				}
				
				*(uint64_t *)&scratch[i] = *reg;
				uthread->t_dtrace_regv = *reg;
				*reg = pc + tp->ftt_size;
				i += sizeof (uint64_t);
			}

			/*
			 * Generate the branch instruction to what would have
			 * normally been the subsequent instruction. In 32-bit mode,
			 * this is just a relative branch; in 64-bit mode this is a
			 * %rip-relative branch that loads the 64-bit pc value
			 * immediately after the jmp instruction.
			 */
			scratch[i++] = FASTTRAP_GROUP5_OP;
			scratch[i++] = FASTTRAP_MODRM(0, 4, 5);
			*(uint32_t *)&scratch[i] = 0;
			i += sizeof (uint32_t);
			*(uint64_t *)&scratch[i] = pc + tp->ftt_size;
			i += sizeof (uint64_t);

			uthread->t_dtrace_astpc = addr + i;
			bcopy(tp->ftt_instr, &scratch[i], tp->ftt_size);
			i += tp->ftt_size;
			scratch[i++] = FASTTRAP_INT;
			scratch[i++] = T_DTRACE_RET;

			if (fasttrap_copyout(scratch, addr, i)) {
				fasttrap_sigtrap(p, uthread, pc);
				new_pc = pc;
				break;
			}

			if (tp->ftt_retids != NULL) {
				uthread->t_dtrace_step = 1;
				uthread->t_dtrace_ret = 1;
				new_pc = uthread->t_dtrace_astpc;
			} else {
				new_pc = uthread->t_dtrace_scrpc;
			}
			
			uthread->t_dtrace_pc = pc;
			uthread->t_dtrace_npc = pc + tp->ftt_size;
			uthread->t_dtrace_on = 1;
			break;
		}
		
		default:
			panic("fasttrap: mishandled an instruction");
	}
	
done:
	/*
	 * APPLE NOTE:
	 *
	 * We're setting this earlier than Solaris does, to get a "correct"
	 * ustack() output. In the Sun code,  a() -> b() -> c() -> d() is
	 * reported at: d, b, a. The new way gives c, b, a, which is closer
	 * to correct, as the return instruction has already exectued.
	 */
	regs64->isf.rip = new_pc;


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
		if (tp->ftt_type != FASTTRAP_T_COMMON) {
			fasttrap_return_common(regs, pc, pid, new_pc);
		} else {
			ASSERT(uthread->t_dtrace_ret != 0);
			ASSERT(uthread->t_dtrace_pc == pc);
			ASSERT(uthread->t_dtrace_scrpc != 0);
			ASSERT(new_pc == uthread->t_dtrace_astpc);
		}
	}

	return (0);
}

int
fasttrap_pid_probe(x86_saved_state_t *regs)
{
        if (is_saved_state64(regs))
		return fasttrap_pid_probe64(regs);

	return fasttrap_pid_probe32(regs);
}

int
fasttrap_return_probe(x86_saved_state_t *regs)
{
	x86_saved_state64_t *regs64;
	x86_saved_state32_t *regs32;
	unsigned int p_model;

        if (is_saved_state64(regs)) {
                regs64 = saved_state64(regs);
		regs32 = NULL;
		p_model = DATAMODEL_LP64;
        } else {
		regs64 = NULL;
                regs32 = saved_state32(regs);
		p_model = DATAMODEL_ILP32;
        }

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
	/*
	 * APPLE NOTE: Terry says: "You need to hold the process locks (currently: kernel funnel) for this traversal"
	 * How do we assert this?
	 */
	while (p->p_lflag & P_LINVFORK) {
		p = p->p_pptr;
	}

	/*
	 * We set rp->r_pc to the address of the traced instruction so
	 * that it appears to dtrace_probe() that we're on the original
	 * instruction, and so that the user can't easily detect our
	 * complex web of lies. dtrace_return_probe() (our caller)
	 * will correctly set %pc after we return.
	 */
	if (p_model == DATAMODEL_LP64)
		regs64->isf.rip = pc;
	else
		regs32->eip = pc;

	fasttrap_return_common(regs, pc, p->p_pid, npc);

	return (0);
}

uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
#pragma unused(arg, id, parg, aframes)
	return (fasttrap_anarg((x86_saved_state_t *)find_user_regs(current_thread()), 1, argno));
}

uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
#pragma unused(arg, id, parg, aframes)
	return (fasttrap_anarg((x86_saved_state_t *)find_user_regs(current_thread()), 0, argno));
}

/*
 * APPLE NOTE: See comments by regmap array definition. We are cheating
 * when returning 32 bit registers.
 */
static user_addr_t
fasttrap_getreg(x86_saved_state_t *regs, uint_t reg)
{
	if (is_saved_state64(regs)) {
		x86_saved_state64_t *regs64 = saved_state64(regs);

		switch (reg) {
			case REG_RAX:		return regs64->rax;
			case REG_RCX:		return regs64->rcx;
			case REG_RDX:		return regs64->rdx;
			case REG_RBX:		return regs64->rbx;
			case REG_RSP:		return regs64->isf.rsp;
			case REG_RBP:		return regs64->rbp;
			case REG_RSI:		return regs64->rsi;
			case REG_RDI:		return regs64->rdi;
			case REG_R8:		return regs64->r8;
			case REG_R9:		return regs64->r9;
			case REG_R10:		return regs64->r10;
			case REG_R11:		return regs64->r11;
			case REG_R12:		return regs64->r12;
			case REG_R13:		return regs64->r13;
			case REG_R14:		return regs64->r14;
			case REG_R15:		return regs64->r15;
		}

		panic("dtrace: unhandled x86_64 getreg() constant");
	} else {
		x86_saved_state32_t *regs32 = saved_state32(regs);

		switch (reg) {
			case REG_RAX:		return regs32->eax;
			case REG_RCX:		return regs32->ecx;
			case REG_RDX:		return regs32->edx;
			case REG_RBX:		return regs32->ebx;
			case REG_RSP:		return regs32->uesp;
			case REG_RBP:		return regs32->ebp;
			case REG_RSI:		return regs32->esi;
			case REG_RDI:		return regs32->edi;
		}

		panic("dtrace: unhandled i386 getreg() constant");
	}

	return 0;
}
