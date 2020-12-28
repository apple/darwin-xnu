/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <arm/cpu_data_internal.h>
#include <arm/dbgwrap.h>
#include <arm64/proc_reg.h>
#include <machine/atomic.h>
#include <pexpert/arm64/board_config.h>

#define DBGWRAP_REG_OFFSET      0
#define DBGWRAP_DBGHALT         (1ULL << 31)
#define DBGWRAP_DBGACK          (1ULL << 28)

#define EDDTRRX_REG_OFFSET      0x80
#define EDITR_REG_OFFSET        0x84
#define EDSCR_REG_OFFSET        0x88
#define EDSCR_TXFULL            (1ULL << 29)
#define EDSCR_ITE               (1ULL << 24)
#define EDSCR_MA                (1ULL << 20)
#define EDSCR_ERR               (1ULL << 6)
#define EDDTRTX_REG_OFFSET      0x8C
#define EDRCR_REG_OFFSET        0x90
#define EDRCR_CSE               (1ULL << 2)
#define EDPRSR_REG_OFFSET       0x314
#define EDPRSR_OSLK             (1ULL << 5)

#define MAX_EDITR_RETRIES       16

/* Older SoCs require 32-bit accesses for DBGWRAP;
 * newer ones require 64-bit accesses. */
#ifdef HAS_32BIT_DBGWRAP
typedef uint32_t dbgwrap_reg_t;
#else
typedef uint64_t dbgwrap_reg_t;
#endif

#if DEVELOPMENT || DEBUG
#define MAX_STUFFED_INSTRS      64
uint32_t stuffed_instrs[MAX_STUFFED_INSTRS];
volatile uint32_t stuffed_instr_count = 0;
#endif

static volatile uint32_t halt_from_cpu = (uint32_t)-1;

boolean_t
ml_dbgwrap_cpu_is_halted(int cpu_index)
{
	cpu_data_t *cdp = cpu_datap(cpu_index);
	if ((cdp == NULL) || (cdp->coresight_base[CORESIGHT_UTT] == 0)) {
		return FALSE;
	}

	return (*(volatile dbgwrap_reg_t *)(cdp->coresight_base[CORESIGHT_UTT] + DBGWRAP_REG_OFFSET) & DBGWRAP_DBGACK) != 0;
}

dbgwrap_status_t
ml_dbgwrap_wait_cpu_halted(int cpu_index, uint64_t timeout_ns)
{
	cpu_data_t *cdp = cpu_datap(cpu_index);
	if ((cdp == NULL) || (cdp->coresight_base[CORESIGHT_UTT] == 0)) {
		return DBGWRAP_ERR_UNSUPPORTED;
	}

	volatile dbgwrap_reg_t *dbgWrapReg = (volatile dbgwrap_reg_t *)(cdp->coresight_base[CORESIGHT_UTT] + DBGWRAP_REG_OFFSET);

	uint64_t interval;
	nanoseconds_to_absolutetime(timeout_ns, &interval);
	uint64_t deadline = mach_absolute_time() + interval;
	while (!(*dbgWrapReg & DBGWRAP_DBGACK)) {
		if (mach_absolute_time() > deadline) {
			return DBGWRAP_ERR_HALT_TIMEOUT;
		}
	}

	return DBGWRAP_SUCCESS;
}

dbgwrap_status_t
ml_dbgwrap_halt_cpu(int cpu_index, uint64_t timeout_ns)
{
	cpu_data_t *cdp = cpu_datap(cpu_index);
	if ((cdp == NULL) || (cdp->coresight_base[CORESIGHT_UTT] == 0)) {
		return DBGWRAP_ERR_UNSUPPORTED;
	}

	/* Only one cpu is allowed to initiate the halt sequence, to prevent cpus from cross-halting
	 * each other.  The first cpu to request a halt may then halt any and all other cpus besides itself. */
	int curcpu = cpu_number();
	if (cpu_index == curcpu) {
		return DBGWRAP_ERR_SELF_HALT;
	}

	if (!os_atomic_cmpxchg(&halt_from_cpu, (uint32_t)-1, (unsigned int)curcpu, acq_rel) &&
	    (halt_from_cpu != (uint32_t)curcpu)) {
		return DBGWRAP_ERR_INPROGRESS;
	}

	volatile dbgwrap_reg_t *dbgWrapReg = (volatile dbgwrap_reg_t *)(cdp->coresight_base[CORESIGHT_UTT] + DBGWRAP_REG_OFFSET);

	if (ml_dbgwrap_cpu_is_halted(cpu_index)) {
		return DBGWRAP_WARN_ALREADY_HALTED;
	}

	/* Clear all other writable bits besides dbgHalt; none of the power-down or reset bits must be set. */
	*dbgWrapReg = DBGWRAP_DBGHALT;

	if (timeout_ns != 0) {
		dbgwrap_status_t stat = ml_dbgwrap_wait_cpu_halted(cpu_index, timeout_ns);
		return stat;
	} else {
		return DBGWRAP_SUCCESS;
	}
}

static void
ml_dbgwrap_stuff_instr(cpu_data_t *cdp, uint32_t instr, uint64_t timeout_ns, dbgwrap_status_t *status)
{
	if (*status < 0) {
		return;
	}

	volatile uint32_t *editr = (volatile uint32_t *)(cdp->coresight_base[CORESIGHT_ED] + EDITR_REG_OFFSET);
	volatile uint32_t *edscr = (volatile uint32_t *)(cdp->coresight_base[CORESIGHT_ED] + EDSCR_REG_OFFSET);
	volatile uint32_t *edrcr = (volatile uint32_t *)(cdp->coresight_base[CORESIGHT_ED] + EDRCR_REG_OFFSET);

	int retries = 0;

	uint64_t interval;
	nanoseconds_to_absolutetime(timeout_ns, &interval);
	uint64_t deadline = mach_absolute_time() + interval;

#if DEVELOPMENT || DEBUG
	uint32_t stuffed_instr_index = os_atomic_inc(&stuffed_instr_count, relaxed);
	stuffed_instrs[(stuffed_instr_index - 1) % MAX_STUFFED_INSTRS] = instr;
#endif

	do {
		*editr = instr;
		volatile uint32_t edscr_val;
		while (!((edscr_val = *edscr) & EDSCR_ITE)) {
			if (mach_absolute_time() > deadline) {
				*status = DBGWRAP_ERR_INSTR_TIMEOUT;
				return;
			}
			if (edscr_val & EDSCR_ERR) {
				break;
			}
		}
		if (edscr_val & EDSCR_ERR) {
			/* If memory access mode was enable by a debugger, clear it.
			 * This will cause ERR to be set on any attempt to use EDITR. */
			if (edscr_val & EDSCR_MA) {
				*edscr = edscr_val & ~EDSCR_MA;
			}
			*edrcr = EDRCR_CSE;
			++retries;
		} else {
			break;
		}
	} while (retries < MAX_EDITR_RETRIES);

	if (retries >= MAX_EDITR_RETRIES) {
		*status = DBGWRAP_ERR_INSTR_ERROR;
		return;
	}
}

static uint64_t
ml_dbgwrap_read_dtr(cpu_data_t *cdp, uint64_t timeout_ns, dbgwrap_status_t *status)
{
	if (*status < 0) {
		return 0;
	}

	uint64_t interval;
	nanoseconds_to_absolutetime(timeout_ns, &interval);
	uint64_t deadline = mach_absolute_time() + interval;

	/* Per armv8 debug spec, writes to DBGDTR_EL0 on target cpu will set EDSCR.TXFull,
	 * with bits 63:32 available in EDDTRRX and bits 31:0 availabe in EDDTRTX. */
	volatile uint32_t *edscr = (volatile uint32_t *)(cdp->coresight_base[CORESIGHT_ED] + EDSCR_REG_OFFSET);

	while (!(*edscr & EDSCR_TXFULL)) {
		if (*edscr & EDSCR_ERR) {
			*status = DBGWRAP_ERR_INSTR_ERROR;
			return 0;
		}
		if (mach_absolute_time() > deadline) {
			*status = DBGWRAP_ERR_INSTR_TIMEOUT;
			return 0;
		}
	}

	uint32_t dtrrx = *((volatile uint32_t*)(cdp->coresight_base[CORESIGHT_ED] + EDDTRRX_REG_OFFSET));
	uint32_t dtrtx = *((volatile uint32_t*)(cdp->coresight_base[CORESIGHT_ED] + EDDTRTX_REG_OFFSET));

	return ((uint64_t)dtrrx << 32) | dtrtx;
}

dbgwrap_status_t
ml_dbgwrap_halt_cpu_with_state(int cpu_index, uint64_t timeout_ns, dbgwrap_thread_state_t *state)
{
	cpu_data_t *cdp = cpu_datap(cpu_index);
	if ((cdp == NULL) || (cdp->coresight_base[CORESIGHT_ED] == 0)) {
		return DBGWRAP_ERR_UNSUPPORTED;
	}

	/* Ensure memory-mapped coresight registers can be written */
	*((volatile uint32_t *)(cdp->coresight_base[CORESIGHT_ED] + ARM_DEBUG_OFFSET_DBGLAR)) = ARM_DBG_LOCK_ACCESS_KEY;

	dbgwrap_status_t status = ml_dbgwrap_halt_cpu(cpu_index, timeout_ns);

	/* A core that is not fully powered (e.g. idling in wfi) can still be halted; the dbgwrap
	 * register and certain coresight registers such EDPRSR are in the always-on domain.
	 * However, EDSCR/EDITR are not in the always-on domain and will generate a parity abort
	 * on read.  EDPRSR can be safely read in all cases, and the OS lock defaults to being set
	 * but we clear it first thing, so use that to detect the offline state. */
	if (*((volatile uint32_t *)(cdp->coresight_base[CORESIGHT_ED] + EDPRSR_REG_OFFSET)) & EDPRSR_OSLK) {
		bzero(state, sizeof(*state));
		return DBGWRAP_WARN_CPU_OFFLINE;
	}

	uint32_t instr;

	for (unsigned int i = 0; i < (sizeof(state->x) / sizeof(state->x[0])); ++i) {
		instr = (0xD51U << 20) | (2 << 19) | (3 << 16) | (4 << 8) | i; // msr DBGDTR0, x<i>
		ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
		state->x[i] = ml_dbgwrap_read_dtr(cdp, timeout_ns, &status);
	}

	instr = (0xD51U << 20) | (2 << 19) | (3 << 16) | (4 << 8) | 29; // msr DBGDTR0, fp
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	state->fp = ml_dbgwrap_read_dtr(cdp, timeout_ns, &status);

	instr = (0xD51U << 20) | (2 << 19) | (3 << 16) | (4 << 8) | 30; // msr DBGDTR0, lr
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	state->lr = ml_dbgwrap_read_dtr(cdp, timeout_ns, &status);

	/* Stack pointer (x31) can't be used as a register operand for msr; register 31 is treated as xzr
	 * rather than sp when used as the transfer operand there.  Instead, load sp into a GPR
	 * we've already saved off and then store that register in the DTR.  I've chosen x18
	 * as the temporary GPR since it's reserved by the arm64 ABI and unused by xnu, so overwriting
	 * it poses the least risk of causing trouble for external debuggers. */

	instr = (0x91U << 24) | (31 << 5) | 18; // mov x18, sp
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	instr = (0xD51U << 20) | (2 << 19) | (3 << 16) | (4 << 8) | 18; // msr DBGDTR0, x18
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	state->sp = ml_dbgwrap_read_dtr(cdp, timeout_ns, &status);

	/* reading PC (e.g. through adr) is undefined in debug state.  Instead use DLR_EL0,
	 * which contains PC at time of entry into debug state.*/

	instr = (0xD53U << 20) | (1 << 19) | (3 << 16) | (4 << 12) | (5 << 8) | (1 << 5) | 18; // mrs    x18, DLR_EL0
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	instr = (0xD51U << 20) | (2 << 19) | (3 << 16) | (4 << 8) | 18; // msr DBGDTR0, x18
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	state->pc = ml_dbgwrap_read_dtr(cdp, timeout_ns, &status);

	/* reading CPSR is undefined in debug state.  Instead use DSPSR_EL0,
	 * which contains CPSR at time of entry into debug state.*/
	instr = (0xD53U << 20) | (1 << 19) | (3 << 16) | (4 << 12) | (5 << 8) | 18; // mrs    x18, DSPSR_EL0
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	instr = (0xD51U << 20) | (2 << 19) | (3 << 16) | (4 << 8) | 18; // msr DBGDTR0, x18
	ml_dbgwrap_stuff_instr(cdp, instr, timeout_ns, &status);
	state->cpsr = (uint32_t)ml_dbgwrap_read_dtr(cdp, timeout_ns, &status);

	return status;
}
