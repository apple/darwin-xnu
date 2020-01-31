/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
 *
 * Disassemblers for ARM (arm), Thumb (thumb16), and Thumb2 (thumb32).
 *
 * Each disassembly begins with a call to dtrace_decode_arm or dtrace_decode_thumb. The thumb
 * decoder will then call dtrace_decode_thumb16 or dtrace_decode_thumb32 as appropriate.
 *
 * The respective disassembly functions are all of the form {arm,thumb16,thumb32}_type. They
 * follow the ordering and breakdown in the ARMv7 Architecture Reference Manual.
 */

#include  <sys/fasttrap_isa.h>

#define BITS(x, n, mask) (((x) >> (n)) & (mask))

static uint32_t
thumb32_instword_to_arm(uint16_t hw1, uint16_t hw2)
{
	return (hw1 << 16) | hw2;
}

int dtrace_decode_arm(uint32_t instr);
int dtrace_decode_arm64(uint32_t instr);
int dtrace_decode_thumb(uint32_t instr);

/*
 * VFP decoder - shared between ARM and THUMB32 mode
 */

static
int
vfp_struct_loadstore(uint32_t instr)
{
	if (ARM_RM(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
vfp_64transfer(uint32_t instr)
{
	/* These instructions all use RD and RN */
	if (ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
vfp_transfer(uint32_t instr)
{
	/* These instructions all use RD only */
	if (ARM_RD(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
vfp_loadstore(uint32_t instr)
{
	int opcode = BITS(instr, 20, 0x1F);

	/* Instrument VLDR */
	if ((opcode & 0x13) == 0x11 && ARM_RN(instr) == REG_PC) {
		return FASTTRAP_T_VLDR_PC_IMMED;
	}

	/* These instructions all use RN only */
	if (ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

/*
 * ARM decoder
 */

static
int
arm_unconditional_misc(uint32_t instr)
{
	int op = BITS(instr, 20, 0x7F);

	if ((op & 0x60) == 0x20) {
		/* VFP data processing uses its own registers */
		return FASTTRAP_T_COMMON;
	}

	if ((op & 0x71) == 0x40) {
		return vfp_struct_loadstore(instr);
	}

	return FASTTRAP_T_INV;
}

static
int
arm_unconditional(uint32_t instr)
{
	if (BITS(instr, 27, 0x1) == 0) {
		return arm_unconditional_misc(instr);
	}

	/* The rest are privileged or BL/BLX, do not instrument */

	/* Do not need to instrument BL/BLX either, see comment in arm_misc(uint32_t) */

	return FASTTRAP_T_INV;
}

static
int
arm_syscall_coproc(uint32_t instr)
{
	/* Instrument any VFP data processing instructions, ignore the rest */

	int op1 = BITS(instr, 20, 0x3F), coproc = BITS(instr, 8, 0xF), op = BITS(instr, 4, 0x1);

	if ((op1 & 0x3E) == 0 || (op1 & 0x30) == 0x30) {
		/* Undefined or swi */
		return FASTTRAP_T_INV;
	}

	if ((coproc & 0xE) == 0xA) {
		/* VFP instruction */

		if ((op1 & 0x20) == 0 && (op1 & 0x3A) != 0) {
			return vfp_loadstore(instr);
		}

		if ((op1 & 0x3E) == 0x04) {
			return vfp_64transfer(instr);
		}

		if ((op1 & 0x30) == 0x20) {
			/* VFP data processing or 8, 16, or 32 bit move between ARM reg and VFP reg */
			if (op == 0) {
				/* VFP data processing uses its own registers */
				return FASTTRAP_T_COMMON;
			} else {
				return vfp_transfer(instr);
			}
		}
	}

	return FASTTRAP_T_INV;
}

static
int
arm_branch_link_blockdata(uint32_t instr)
{
	int branch = BITS(instr, 25, 0x1), link = BITS(instr, 24, 0x1), op = BITS(instr, 20, 0x1F), uses_pc = BITS(instr, 15, 0x1), uses_lr = BITS(instr, 14, 0x1);

	if (branch == 1) {
		if (link == 0) {
			return FASTTRAP_T_B_COND;
		}
		return FASTTRAP_T_INV;
	} else {
		/* Only emulate a use of the pc if it's a return from function: ldmia sp!, { ... pc } */
		if (op == 0x0B && ARM_RN(instr) == REG_SP && uses_pc == 1) {
			return FASTTRAP_T_LDM_PC;
		}

		/* stmia sp!, { ... lr } doesn't touch the pc, but it is very common, so special case it */
		if (op == 0x12 && ARM_RN(instr) == REG_SP && uses_lr == 1) {
			return FASTTRAP_T_STM_LR;
		}

		if (ARM_RN(instr) != REG_PC && uses_pc == 0) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
arm_signed_multiplies(uint32_t instr)
{
	int op1 = BITS(instr, 20, 0x7), op2 = BITS(instr, 5, 0x7);

	/* smlald, smlsld, smmls use RD in addition to RM, RS, and RN */
	if ((op1 == 0x4 && (op2 & 0x4) == 0) || (op1 == 0x5 && (op2 & 0x6) == 0x6)) {
		if (ARM_RD(instr) == REG_PC) {
			return FASTTRAP_T_INV;
		}
	}

	if (ARM_RM(instr) != REG_PC && ARM_RS(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_pack_unpack_sat_reversal(uint32_t instr)
{
	int op1 = BITS(instr, 20, 0x7), op2 = BITS(instr, 5, 0x7);

	/* pkh, sel use RN in addition to RD and RM */
	if ((op1 == 0 && (op2 & 0x1) == 0) || (op1 == 0 && op2 == 0x5)) {
		if (ARM_RN(instr) == REG_PC) {
			return FASTTRAP_T_INV;
		}
	}

	if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_parallel_addsub_unsigned(uint32_t instr)
{
	if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_parallel_addsub_signed(uint32_t instr)
{
	if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_media(uint32_t instr)
{
	int op1 = BITS(instr, 20, 0x1F), op2 = BITS(instr, 5, 0x7);

	if ((op1 & 0x1C) == 0) {
		return arm_parallel_addsub_signed(instr);
	}

	if ((op1 & 0x1C) == 0x04) {
		return arm_parallel_addsub_unsigned(instr);
	}

	if ((op1 & 0x18) == 0x08) {
		return arm_pack_unpack_sat_reversal(instr);
	}

	if ((op1 & 0x18) == 0x10) {
		return arm_signed_multiplies(instr);
	}

	if (op1 == 0x1F && op2 == 0x7) {
		/* Undefined instruction */
		return FASTTRAP_T_INV;
	}

	if (op1 == 0x18 && op2 == 0) {
		/* usad8 usada8 */
		/* The registers are named differently in the reference manual for this instruction
		 * but the following positions are correct */

		if (ARM_RM(instr) != REG_PC && ARM_RS(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}

		return FASTTRAP_T_INV;
	}

	if ((op1 & 0x1E) == 0x1C && (op2 & 0x3) == 0) {
		/* bfc bfi */
		if (ARM_RD(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}

		return FASTTRAP_T_INV;
	}

	if (((op1 & 0x1E) == 0x1A || (op1 & 0x1E) == 0x1E) && ((op2 & 0x3) == 0x2)) {
		/* sbfx ubfx */
		if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}

		return FASTTRAP_T_INV;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_loadstore_wordbyte(uint32_t instr)
{
	/* Instrument PC relative load with immediate, ignore any other uses of the PC */
	int R = BITS(instr, 25, 0x1), L = BITS(instr, 20, 0x1);

	if (R == 1) {
		/* Three register load/store */
		if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	} else {
		/* Immediate load/store, but still do not support ldr pc, [pc...] */
		if (L == 1 && ARM_RN(instr) == REG_PC && ARM_RD(instr) != REG_PC) {
			return FASTTRAP_T_LDR_PC_IMMED;
		}

		if (ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
arm_saturating(uint32_t instr)
{
	if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_misc(uint32_t instr)
{
	int op = BITS(instr, 21, 0x3), __unused op1 = BITS(instr, 16, 0xF), op2 = BITS(instr, 4, 0x7);

	if (op2 == 1 && op == 1) {
		return FASTTRAP_T_BX_REG;
	}

	/* We do not need to emulate BLX for entry/return probes; if we eventually support full offset
	 * tracing, then we will. This is because BLX overwrites the link register, so a function that
	 * can execute this as its first instruction is a special function indeed.
	 */

	if (op2 == 0x5) {
		return arm_saturating(instr);
	}

	return FASTTRAP_T_INV;
}

static
int
arm_msr_hints(__unused uint32_t instr)
{
	/* These deal with the psr, not instrumented */

	return FASTTRAP_T_INV;
}

static
int
arm_sync_primitive(__unused uint32_t instr)
{
	/* TODO will instrumenting these interfere with any kernel usage of these instructions? */
	/* Don't instrument for now */

	return FASTTRAP_T_INV;
}

static
int
arm_extra_loadstore_unpriv(uint32_t instr)
{
	int op = BITS(instr, 20, 0x1), __unused op2 = BITS(instr, 5, 0x3), immed = BITS(instr, 22, 0x1);

	if (op == 0 && (op2 & 0x2) == 0x2) {
		/* Unpredictable or undefined */
		return FASTTRAP_T_INV;
	}

	if (immed == 1) {
		if (ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	} else {
		if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
arm_extra_loadstore(uint32_t instr)
{
	int op1 = BITS(instr, 20, 0x1F);

	/* There are two variants, and we do not instrument either of them that use the PC */

	if ((op1 & 0x4) == 0) {
		/* Variant 1, register */
		if (ARM_RM(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	} else {
		/* Variant 2, immediate */
		if (ARM_RD(instr) != REG_PC && ARM_RN(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
arm_halfword_multiply(uint32_t instr)
{
	/* Not all multiply instructions use all four registers. The ones that don't should have those
	 * register locations set to 0, so we can test them anyway.
	 */

	if (ARM_RN(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RS(instr) != REG_PC && ARM_RM(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_multiply(uint32_t instr)
{
	/* Not all multiply instructions use all four registers. The ones that don't should have those
	 * register locations set to 0, so we can test them anyway.
	 */

	if (ARM_RN(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RS(instr) != REG_PC && ARM_RM(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_dataproc_immed(uint32_t instr)
{
	/* All these instructions are either two registers, or one register and have 0 where the other reg would be used */
	if (ARM_RN(instr) != REG_PC && ARM_RD(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_dataproc_regshift(uint32_t instr)
{
	/* All these instructions are either four registers, or three registers and have 0 where there last reg would be used */
	if (ARM_RN(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RS(instr) != REG_PC && ARM_RM(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_dataproc_reg(uint32_t instr)
{
	int op1 = BITS(instr, 20, 0x1F), op2 = BITS(instr, 7, 0x1F), op3 = BITS(instr, 5, 0x3);

	if (op1 == 0x11 || op1 == 0x13 || op1 == 0x15 || op1 == 0x17) {
		/* These are comparison flag setting instructions and do not have RD */
		if (ARM_RN(instr) != REG_PC && ARM_RM(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}

		return FASTTRAP_T_INV;
	}

	/* The rest can, in theory, write or use the PC. The only one we instrument is mov pc, reg.
	 * movs pc, reg is a privileged instruction so we don't instrument that variant. The s bit
	 * is bit 0 of op1 and should be zero.
	 */
	if (op1 == 0x1A && op2 == 0 && op3 == 0 && ARM_RD(instr) == REG_PC) {
		return FASTTRAP_T_MOV_PC_REG;
	}

	/* Any instruction at this point is a three register instruction or two register instruction with RN = 0 */
	if (ARM_RN(instr) != REG_PC && ARM_RD(instr) != REG_PC && ARM_RM(instr) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
arm_dataproc_misc(uint32_t instr)
{
	int op = BITS(instr, 25, 0x1), op1 = BITS(instr, 20, 0x1F), op2 = BITS(instr, 4, 0xF);

	if (op == 0) {
		if ((op1 & 0x19) != 0x10 && (op2 & 0x1) == 0) {
			return arm_dataproc_reg(instr);
		}

		if ((op1 & 0x19) != 0x10 && (op2 & 0x9) == 0x1) {
			return arm_dataproc_regshift(instr);
		}

		if ((op1 & 0x19) == 0x10 && (op2 & 0x8) == 0) {
			return arm_misc(instr);
		}

		if ((op1 & 0x19) == 0x19 && (op2 & 0x9) == 0x8) {
			return arm_halfword_multiply(instr);
		}

		if ((op1 & 0x10) == 0 && op2 == 0x9) {
			return arm_multiply(instr);
		}

		if ((op1 & 0x10) == 0x10 && op2 == 0x9) {
			return arm_sync_primitive(instr);
		}

		if ((op1 & 0x12) != 0x02 && (op2 == 0xB || (op2 & 0xD) == 0xD)) {
			return arm_extra_loadstore(instr);
		}

		if ((op1 & 0x12) == 0x02 && (op2 == 0xB || (op2 & 0xD) == 0xD)) {
			return arm_extra_loadstore_unpriv(instr);
		}
	} else {
		if ((op1 & 0x19) != 0x10) {
			return arm_dataproc_immed(instr);
		}

		if (op1 == 0x10) {
			/* 16 bit immediate load (mov (immed)) [encoding A2] */
			if (ARM_RD(instr) != REG_PC) {
				return FASTTRAP_T_COMMON;
			}

			return FASTTRAP_T_INV;
		}

		if (op1 == 0x14) {
			/* high halfword 16 bit immediate load (movt) [encoding A1] */
			if (ARM_RD(instr) != REG_PC) {
				return FASTTRAP_T_COMMON;
			}

			return FASTTRAP_T_INV;
		}

		if ((op1 & 0x1B) == 0x12) {
			return arm_msr_hints(instr);
		}
	}

	return FASTTRAP_T_INV;
}

int
dtrace_decode_arm(uint32_t instr)
{
	int cond = BITS(instr, 28, 0xF), op1 = BITS(instr, 25, 0x7), op = BITS(instr, 4, 0x1);

	if (cond == 0xF) {
		return arm_unconditional(instr);
	}

	if ((op1 & 0x6) == 0) {
		return arm_dataproc_misc(instr);
	}

	if (op1 == 0x2) {
		return arm_loadstore_wordbyte(instr);
	}

	if (op1 == 0x3 && op == 0) {
		return arm_loadstore_wordbyte(instr);
	}

	if (op1 == 0x3 && op == 1) {
		return arm_media(instr);
	}

	if ((op1 & 0x6) == 0x4) {
		return arm_branch_link_blockdata(instr);
	}

	if ((op1 & 0x6) == 0x6) {
		return arm_syscall_coproc(instr);
	}

	return FASTTRAP_T_INV;
}

/*
 * Thumb 16-bit decoder
 */

static
int
thumb16_cond_supervisor(uint16_t instr)
{
	int opcode = BITS(instr, 8, 0xF);

	if ((opcode & 0xE) != 0xE) {
		return FASTTRAP_T_B_COND;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb16_misc(uint16_t instr)
{
	int opcode = BITS(instr, 5, 0x7F);

	if ((opcode & 0x70) == 0x30 || (opcode & 0x70) == 0x70) {
		/* setend, cps, breakpoint, or if-then, not instrumentable */
		return FASTTRAP_T_INV;
	} else if ((opcode & 0x78) == 0x28) {
		/* Doesn't modify pc, but this happens a lot so make this a special case for emulation */
		return FASTTRAP_T_PUSH_LR;
	} else if ((opcode & 0x78) == 0x68) {
		return FASTTRAP_T_POP_PC;
	} else if ((opcode & 0x28) == 0x08) {
		return FASTTRAP_T_CB_N_Z;
	}

	/* All other instructions work on low regs only and are instrumentable */
	return FASTTRAP_T_COMMON;
}

static
int
thumb16_loadstore_single(__unused uint16_t instr)
{
	/* These all access the low registers or SP only */
	return FASTTRAP_T_COMMON;
}

static
int
thumb16_data_special_and_branch(uint16_t instr)
{
	int opcode = BITS(instr, 6, 0xF);

	if (opcode == 0x4) {
		/* Unpredictable */
		return FASTTRAP_T_INV;
	} else if ((opcode & 0xC) == 0xC) {
		/* bx or blx */
		/* Only instrument the bx */
		if ((opcode & 0x2) == 0) {
			return FASTTRAP_T_BX_REG;
		}
		return FASTTRAP_T_INV;
	} else {
		/* Data processing on high registers, only instrument mov pc, reg */
		if ((opcode & 0xC) == 0x8 && THUMB16_HRD(instr) == REG_PC) {
			return FASTTRAP_T_CPY_PC;
		}

		if (THUMB16_HRM(instr) != REG_PC && THUMB16_HRD(instr) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
thumb16_data_proc(__unused uint16_t instr)
{
	/* These all access the low registers only */
	return FASTTRAP_T_COMMON;
}

static
int
thumb16_shift_addsub_move_compare(__unused uint16_t instr)
{
	/* These all access the low registers only */
	return FASTTRAP_T_COMMON;
}

static
int
dtrace_decode_thumb16(uint16_t instr)
{
	int opcode = BITS(instr, 10, 0x3F);

	if ((opcode & 0x30) == 0) {
		return thumb16_shift_addsub_move_compare(instr);
	}

	if (opcode == 0x10) {
		return thumb16_data_proc(instr);
	}

	if (opcode == 0x11) {
		return thumb16_data_special_and_branch(instr);
	}

	if ((opcode & 0x3E) == 0x12) {
		/* ldr (literal) */
		return FASTTRAP_T_LDR_PC_IMMED;
	}

	if ((opcode & 0x3C) == 0x14 || (opcode & 0x38) == 0x18 || (opcode & 0x38) == 0x20) {
		return thumb16_loadstore_single(instr);
	}

	if ((opcode & 0x3E) == 0x28) {
		/* adr, uses the pc */
		return FASTTRAP_T_INV;
	}

	if ((opcode & 0x3E) == 0x2A) {
		/* add (sp plus immediate) */
		return FASTTRAP_T_COMMON;
	}

	if ((opcode & 0x3C) == 0x2C) {
		return thumb16_misc(instr);
	}

	if ((opcode & 0x3E) == 0x30) {
		/* stm - can't access high registers */
		return FASTTRAP_T_COMMON;
	}

	if ((opcode & 0x3E) == 0x32) {
		/* ldm - can't access high registers */
		return FASTTRAP_T_COMMON;
	}

	if ((opcode & 0x3C) == 0x34) {
		return thumb16_cond_supervisor(instr);
	}

	if ((opcode & 0x3E) == 0x38) {
		/* b unconditional */
		return FASTTRAP_T_B_UNCOND;
	}

	return FASTTRAP_T_INV;
}

/*
 * Thumb 32-bit decoder
 */

static
int
thumb32_coproc(uint16_t instr1, uint16_t instr2)
{
	/* Instrument any VFP data processing instructions, ignore the rest */

	int op1 = BITS(instr1, 4, 0x3F), coproc = BITS(instr2, 8, 0xF), op = BITS(instr2, 4, 0x1);

	if ((op1 & 0x3E) == 0) {
		/* Undefined */
		return FASTTRAP_T_INV;
	}

	if ((coproc & 0xE) == 0xA || (op1 & 0x30) == 0x30) {
		/* VFP instruction */
		uint32_t instr = thumb32_instword_to_arm(instr1, instr2);

		if ((op1 & 0x30) == 0x30) {
			/* VFP data processing uses its own registers */
			return FASTTRAP_T_COMMON;
		}

		if ((op1 & 0x3A) == 0x02 || (op1 & 0x38) == 0x08 || (op1 & 0x30) == 0x10) {
			return vfp_loadstore(instr);
		}

		if ((op1 & 0x3E) == 0x04) {
			return vfp_64transfer(instr);
		}

		if ((op1 & 0x30) == 0x20) {
			/* VFP data processing or 8, 16, or 32 bit move between ARM reg and VFP reg */
			if (op == 0) {
				/* VFP data processing uses its own registers */
				return FASTTRAP_T_COMMON;
			} else {
				return vfp_transfer(instr);
			}
		}
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_longmultiply(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 4, 0x7), op2 = BITS(instr2, 4, 0xF);

	if ((op1 == 1 && op2 == 0xF) || (op1 == 0x3 && op2 == 0xF)) {
		/* Three register instruction */
		if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	} else {
		/* Four register instruction */
		if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC &&
		    THUMB32_RT(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_multiply(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 4, 0x7), op2 = BITS(instr2, 4, 0x3);

	if ((op1 == 0 && op2 == 1) || (op1 == 0x6 && (op2 & 0x2) == 0)) {
		if (THUMB32_RT(instr1, instr2) == REG_PC) {
			return FASTTRAP_T_INV;
		}
	}

	if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_misc(uint16_t instr1, uint16_t instr2)
{
	if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_parallel_addsub_unsigned(uint16_t instr1, uint16_t instr2)
{
	if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_parallel_addsub_signed(uint16_t instr1, uint16_t instr2)
{
	if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_dataproc_reg(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 4, 0xF), op2 = BITS(instr2, 4, 0xF);

	if (((0 <= op1) && (op1 <= 5)) && (op2 & 0x8) == 0x8) {
		if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	if ((op1 & 0x8) == 0 && op2 == 0) {
		if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	if ((op1 & 0x8) == 0x8 && (op2 & 0xC) == 0) {
		return thumb32_parallel_addsub_signed(instr1, instr2);
	}

	if ((op1 & 0x8) == 0x8 && (op2 & 0xC) == 0x4) {
		return thumb32_parallel_addsub_unsigned(instr1, instr2);
	}

	if ((op1 & 0xC) == 0x8 && (op2 & 0xC) == 0x8) {
		return thumb32_misc(instr1, instr2);
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_dataproc_regshift(uint16_t instr1, uint16_t instr2)
{
	int op = BITS(instr1, 5, 0xF), S = BITS(instr1, 4, 0x1);

	if (op == 0 || op == 0x4 || op == 0x8 || op == 0xD) {
		/* These become test instructions if S is 1 and Rd is PC, otherwise they are data instructions. */
		if (S == 1) {
			if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
				return FASTTRAP_T_COMMON;
			}
		} else {
			if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC &&
			    THUMB32_RN(instr1, instr2) != REG_PC) {
				return FASTTRAP_T_COMMON;
			}
		}
	} else if (op == 0x2 || op == 0x3) {
		/* These become moves if RN is PC, otherwise they are data insts. We don't instrument mov pc, reg here */
		if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	} else {
		/* Normal three register instruction */
		if (THUMB32_RM(instr1, instr2) != REG_PC && THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_store_single(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 5, 0x7), op2 = BITS(instr2, 6, 0x3F);

	/* Do not support any use of the pc yet */
	if ((op1 == 0 || op1 == 1 || op1 == 2) && (op2 & 0x20) == 0) {
		/* str (register) uses RM */
		if (THUMB32_RM(instr1, instr2) == REG_PC) {
			return FASTTRAP_T_INV;
		}
	}

	if (THUMB32_RT(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_loadbyte_memhint(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 7, 0x3), __unused op2 = BITS(instr2, 6, 0x3F);

	/* Do not support any use of the pc yet */
	if ((op1 == 0 || op1 == 0x2) && THUMB32_RM(instr1, instr2) == REG_PC) {
		return FASTTRAP_T_INV;
	}

	if (THUMB32_RT(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_loadhalfword_memhint(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 7, 0x3), op2 = BITS(instr2, 6, 0x3F);

	/* Do not support any use of the PC yet */
	if (op1 == 0 && op2 == 0 && THUMB32_RM(inst1, instr2) == REG_PC) {
		return FASTTRAP_T_INV;
	}

	if (THUMB32_RT(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_loadword(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 7, 0x3), op2 = BITS(instr2, 6, 0x3F);

	if ((op1 & 0x2) == 0 && THUMB32_RN(instr1, instr2) == REG_PC && THUMB32_RT(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_LDR_PC_IMMED;
	}

	if (op1 == 0 && op2 == 0) {
		/* ldr (register) uses an additional reg */
		if (THUMB32_RM(instr1, instr2) == REG_PC) {
			return FASTTRAP_T_INV;
		}
	}

	if (THUMB32_RT(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_loadstore_double_exclusive_table(__unused uint16_t instr1, __unused uint16_t instr2)
{
	/* Don't instrument any of these */

	return FASTTRAP_T_INV;
}

static
int
thumb32_loadstore_multiple(uint16_t instr1, uint16_t instr2)
{
	int op = BITS(instr1, 7, 0x3), L = BITS(instr1, 4, 0x1), uses_pc = BITS(instr2, 15, 0x1), uses_lr = BITS(instr2, 14, 0x1);

	if (op == 0 || op == 0x3) {
		/* Privileged instructions: srs, rfe */
		return FASTTRAP_T_INV;
	}

	/* Only emulate a use of the pc if it's a return from function: ldmia sp!, { ... pc }, aka pop { ... pc } */
	if (op == 0x1 && L == 1 && THUMB32_RN(instr1, instr2) == REG_SP && uses_pc == 1) {
		return FASTTRAP_T_LDM_PC;
	}

	/* stmia sp!, { ... lr }, aka push { ... lr } doesn't touch the pc, but it is very common, so special case it */
	if (op == 0x2 && L == 0 && THUMB32_RN(instr1, instr2) == REG_SP && uses_lr == 1) {
		return FASTTRAP_T_STM_LR;
	}

	if (THUMB32_RN(instr1, instr2) != REG_PC && uses_pc == 0) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_misc_control(__unused uint16_t instr1, __unused uint16_t instr2)
{
	/* Privileged, and instructions dealing with ThumbEE */
	return FASTTRAP_T_INV;
}

static
int
thumb32_cps_hints(__unused uint16_t instr1, __unused uint16_t instr2)
{
	/* Privileged */
	return FASTTRAP_T_INV;
}

static
int
thumb32_b_misc_control(uint16_t instr1, uint16_t instr2)
{
	int op = BITS(instr1, 4, 0x7F), op1 = BITS(instr2, 12, 0x7), __unused op2 = BITS(instr2, 8, 0xF);

	if ((op1 & 0x5) == 0) {
		if ((op & 0x38) != 0x38) {
			return FASTTRAP_T_B_COND;
		}

		if (op == 0x3A) {
			return thumb32_cps_hints(instr1, instr2);
		}

		if (op == 0x3B) {
			return thumb32_misc_control(instr1, instr2);
		}
	}

	if ((op1 & 0x5) == 1) {
		return FASTTRAP_T_B_UNCOND;
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_dataproc_plain_immed(uint16_t instr1, uint16_t instr2)
{
	int op = BITS(instr1, 4, 0x1F);

	if (op == 0x04 || op == 0x0C || op == 0x16) {
		/* mov, movt, bfi, bfc */
		/* These use only RD */
		if (THUMB32_RD(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	} else {
		if (THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	return FASTTRAP_T_INV;
}

static
int
thumb32_dataproc_mod_immed(uint16_t instr1, uint16_t instr2)
{
	int op = BITS(instr1, 5, 0xF), S = BITS(instr1, 4, 0x1);

	if (op == 0x2 || op == 0x3) {
		/* These allow REG_PC in RN, but it doesn't mean use the PC! */
		if (THUMB32_RD(instr1, instr2) != REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	if (op == 0 || op == 0x4 || op == 0x8 || op == 0xD) {
		/* These are test instructions, if the sign bit is set and RD is the PC. */
		if (S && THUMB32_RD(instr1, instr2) == REG_PC) {
			return FASTTRAP_T_COMMON;
		}
	}

	if (THUMB32_RD(instr1, instr2) != REG_PC && THUMB32_RN(instr1, instr2) != REG_PC) {
		return FASTTRAP_T_COMMON;
	}

	return FASTTRAP_T_INV;
}

static
int
dtrace_decode_thumb32(uint16_t instr1, uint16_t instr2)
{
	int op1 = BITS(instr1, 11, 0x3), op2 = BITS(instr1, 4, 0x7F), op = BITS(instr2, 15, 0x1);

	if (op1 == 0x1) {
		if ((op2 & 0x64) == 0) {
			return thumb32_loadstore_multiple(instr1, instr2);
		}

		if ((op2 & 0x64) == 0x04) {
			return thumb32_loadstore_double_exclusive_table(instr1, instr2);
		}

		if ((op2 & 0x60) == 0x20) {
			return thumb32_dataproc_regshift(instr1, instr2);
		}

		if ((op2 & 0x40) == 0x40) {
			return thumb32_coproc(instr1, instr2);
		}
	}

	if (op1 == 0x2) {
		if ((op2 & 0x20) == 0 && op == 0) {
			return thumb32_dataproc_mod_immed(instr1, instr2);
		}

		if ((op2 & 0x20) == 0x20 && op == 0) {
			return thumb32_dataproc_plain_immed(instr1, instr2);
		}

		if (op == 1) {
			return thumb32_b_misc_control(instr1, instr2);
		}
	}

	if (op1 == 0x3) {
		if ((op2 & 0x71) == 0) {
			return thumb32_store_single(instr1, instr2);
		}

		if ((op2 & 0x71) == 0x10) {
			return vfp_struct_loadstore(thumb32_instword_to_arm(instr1, instr2));
		}

		if ((op2 & 0x67) == 0x01) {
			return thumb32_loadbyte_memhint(instr1, instr2);
		}

		if ((op2 & 0x67) == 0x03) {
			return thumb32_loadhalfword_memhint(instr1, instr2);
		}

		if ((op2 & 0x67) == 0x05) {
			return thumb32_loadword(instr1, instr2);
		}

		if ((op2 & 0x67) == 0x07) {
			/* Undefined instruction */
			return FASTTRAP_T_INV;
		}

		if ((op2 & 0x70) == 0x20) {
			return thumb32_dataproc_reg(instr1, instr2);
		}

		if ((op2 & 0x78) == 0x30) {
			return thumb32_multiply(instr1, instr2);
		}

		if ((op2 & 0x78) == 0x38) {
			return thumb32_longmultiply(instr1, instr2);
		}

		if ((op2 & 0x40) == 0x40) {
			return thumb32_coproc(instr1, instr2);
		}
	}

	return FASTTRAP_T_INV;
}

int
dtrace_decode_thumb(uint32_t instr)
{
	uint16_t* pInstr = (uint16_t*) &instr;
	uint16_t hw1 = pInstr[0], hw2 = pInstr[1];

	int size = BITS(hw1, 11, 0x1F);

	if (size == 0x1D || size == 0x1E || size == 0x1F) {
		return dtrace_decode_thumb32(hw1, hw2);
	} else {
		return dtrace_decode_thumb16(hw1);
	}
}

struct arm64_decode_entry {
	uint32_t mask;
	uint32_t value;
	uint32_t type;
};

struct arm64_decode_entry arm64_decode_table[] = {
	{ .mask = 0xFFFFFFFF, .value = FASTTRAP_ARM64_OP_VALUE_FUNC_ENTRY, .type = FASTTRAP_T_ARM64_STANDARD_FUNCTION_ENTRY },
	{ .mask = FASTTRAP_ARM64_OP_MASK_LDR_S_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_LDR_S_PC_REL, .type = FASTTRAP_T_ARM64_LDR_S_PC_REL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_LDR_W_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_LDR_W_PC_REL, .type = FASTTRAP_T_ARM64_LDR_W_PC_REL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_LDR_D_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_LDR_D_PC_REL, .type = FASTTRAP_T_ARM64_LDR_D_PC_REL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_LDR_X_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_LDR_X_PC_REL, .type = FASTTRAP_T_ARM64_LDR_X_PC_REL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_LDR_Q_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_LDR_Q_PC_REL, .type = FASTTRAP_T_ARM64_LDR_Q_PC_REL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_LRDSW_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_LRDSW_PC_REL, .type = FASTTRAP_T_ARM64_LDRSW_PC_REL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_B_COND_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_B_COND_PC_REL, .type = FASTTRAP_T_ARM64_B_COND },
	{ .mask = FASTTRAP_ARM64_OP_MASK_CBNZ_W_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_CBNZ_W_PC_REL, .type = FASTTRAP_T_ARM64_CBNZ_W },
	{ .mask = FASTTRAP_ARM64_OP_MASK_CBNZ_X_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_CBNZ_X_PC_REL, .type = FASTTRAP_T_ARM64_CBNZ_X },
	{ .mask = FASTTRAP_ARM64_OP_MASK_CBZ_W_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_CBZ_W_PC_REL, .type = FASTTRAP_T_ARM64_CBZ_W },
	{ .mask = FASTTRAP_ARM64_OP_MASK_CBZ_X_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_CBZ_X_PC_REL, .type = FASTTRAP_T_ARM64_CBZ_X },
	{ .mask = FASTTRAP_ARM64_OP_MASK_TBNZ_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_TBNZ_PC_REL, .type = FASTTRAP_T_ARM64_TBNZ },
	{ .mask = FASTTRAP_ARM64_OP_MASK_TBZ_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_TBZ_PC_REL, .type = FASTTRAP_T_ARM64_TBZ },
	{ .mask = FASTTRAP_ARM64_OP_MASK_B_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_B_PC_REL, .type = FASTTRAP_T_ARM64_B },
	{ .mask = FASTTRAP_ARM64_OP_MASK_BL_PC_REL, .value = FASTTRAP_ARM64_OP_VALUE_BL_PC_REL, .type = FASTTRAP_T_ARM64_BL },
	{ .mask = FASTTRAP_ARM64_OP_MASK_BLR, .value = FASTTRAP_ARM64_OP_VALUE_BLR, .type = FASTTRAP_T_ARM64_BLR },
	{ .mask = FASTTRAP_ARM64_OP_MASK_BR, .value = FASTTRAP_ARM64_OP_VALUE_BR, .type = FASTTRAP_T_ARM64_BR },
	{ .mask = FASTTRAP_ARM64_OP_MASK_RET, .value = FASTTRAP_ARM64_OP_VALUE_RET, .type = FASTTRAP_T_ARM64_RET },
	{ .mask = FASTTRAP_ARM64_OP_MASK_ADRP, .value = FASTTRAP_ARM64_OP_VALUE_ADRP, .type = FASTTRAP_T_ARM64_ADRP },
	{ .mask = FASTTRAP_ARM64_OP_MASK_ADR, .value = FASTTRAP_ARM64_OP_VALUE_ADR, .type = FASTTRAP_T_ARM64_ADR },
	{ .mask = FASTTRAP_ARM64_OP_MASK_PRFM, .value = FASTTRAP_ARM64_OP_VALUE_PRFM, .type = FASTTRAP_T_ARM64_PRFM },
	{ .mask = FASTTRAP_ARM64_OP_MASK_EXCL_MEM, .value = FASTTRAP_ARM64_OP_VALUE_EXCL_MEM, .type = FASTTRAP_T_ARM64_EXCLUSIVE_MEM },
	{ .mask = FASTTRAP_ARM64_OP_MASK_RETAB, .value = FASTTRAP_ARM64_OP_VALUE_RETAB, .type = FASTTRAP_T_ARM64_RETAB }
};

#define NUM_DECODE_ENTRIES (sizeof(arm64_decode_table) / sizeof(struct arm64_decode_entry))



int
dtrace_decode_arm64(uint32_t instr)
{
	unsigned i;

	for (i = 0; i < NUM_DECODE_ENTRIES; i++) {
		if ((instr & arm64_decode_table[i].mask) == arm64_decode_table[i].value) {
			return arm64_decode_table[i].type;
		}
	}

	return FASTTRAP_T_COMMON;
}
