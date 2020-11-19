/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach_debug.h>
#include <mach_ldebug.h>

#include <sys/kdebug.h>

#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/mach_param.h>
#include <kern/processor.h>
#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/spl.h>
#include <kern/machine.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <vm/vm_protos.h>

#include <i386/commpage/commpage.h>
#include <i386/cpu_data.h>
#include <i386/cpu_number.h>
#include <i386/cpuid.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/seg.h>
#include <i386/machine_routines.h>

#if HYPERVISOR
#include <kern/hv_support.h>
#endif

#define ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(_type_)        \
extern char assert_is_16byte_multiple_sizeof_ ## _type_ \
	        [(sizeof(_type_) % 16) == 0 ? 1 : -1]

/* Compile-time checks for vital save area sizing: */
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_64_intr_stack_frame_t);
ASSERT_IS_16BYTE_MULTIPLE_SIZEOF(x86_saved_state_t);

#define DIRECTION_FLAG_DEBUG (DEBUG | DEVELOPMENT)

extern zone_t           iss_zone;               /* zone for saved_state area */
extern zone_t           ids_zone;               /* zone for debug_state area */
extern int              tecs_mode_supported;
extern boolean_t        cpuid_tsx_supported;

bool lbr_need_tsx_workaround = false;

int force_thread_policy_tecs;

struct lbr_group {
	uint32_t        msr_from;
	uint32_t        msr_to;
	uint32_t        msr_info;
};

struct cpu_lbrs {
	uint32_t                lbr_count;
	struct lbr_group        msr_lbrs[X86_MAX_LBRS];
};

const struct cpu_lbrs *cpu_lbr_setp = NULL;
int cpu_lbr_type;

const struct cpu_lbrs nhm_cpu_lbrs = {
	16 /* LBR count */,
	{
		{ 0x680 /* FROM_0 */, 0x6c0 /* TO_0 */, 0 /* INFO_0 */ },
		{ 0x681 /* FROM_1 */, 0x6c1 /* TO_1 */, 0 /* INFO_1 */ },
		{ 0x682 /* FROM_2 */, 0x6c2 /* TO_2 */, 0 /* INFO_2 */ },
		{ 0x683 /* FROM_3 */, 0x6c3 /* TO_3 */, 0 /* INFO_3 */ },
		{ 0x684 /* FROM_4 */, 0x6c4 /* TO_4 */, 0 /* INFO_4 */ },
		{ 0x685 /* FROM_5 */, 0x6c5 /* TO_5 */, 0 /* INFO_5 */ },
		{ 0x686 /* FROM_6 */, 0x6c6 /* TO_6 */, 0 /* INFO_6 */ },
		{ 0x687 /* FROM_7 */, 0x6c7 /* TO_7 */, 0 /* INFO_7 */ },
		{ 0x688 /* FROM_8 */, 0x6c8 /* TO_8 */, 0 /* INFO_8 */ },
		{ 0x689 /* FROM_9 */, 0x6c9 /* TO_9 */, 0 /* INFO_9 */ },
		{ 0x68A /* FROM_10 */, 0x6ca /* TO_10 */, 0 /* INFO_10 */ },
		{ 0x68B /* FROM_11 */, 0x6cb /* TO_11 */, 0 /* INFO_11 */ },
		{ 0x68C /* FROM_12 */, 0x6cc /* TO_12 */, 0 /* INFO_12 */ },
		{ 0x68D /* FROM_13 */, 0x6cd /* TO_13 */, 0 /* INFO_13 */ },
		{ 0x68E /* FROM_14 */, 0x6ce /* TO_14 */, 0 /* INFO_14 */ },
		{ 0x68F /* FROM_15 */, 0x6cf /* TO_15 */, 0 /* INFO_15 */ }
	}
},
    skl_cpu_lbrs = {
	32 /* LBR count */,
	{
		{ 0x680 /* FROM_0 */, 0x6c0 /* TO_0 */, 0xdc0 /* INFO_0 */ },
		{ 0x681 /* FROM_1 */, 0x6c1 /* TO_1 */, 0xdc1 /* INFO_1 */ },
		{ 0x682 /* FROM_2 */, 0x6c2 /* TO_2 */, 0xdc2 /* INFO_2 */ },
		{ 0x683 /* FROM_3 */, 0x6c3 /* TO_3 */, 0xdc3 /* INFO_3 */ },
		{ 0x684 /* FROM_4 */, 0x6c4 /* TO_4 */, 0xdc4 /* INFO_4 */ },
		{ 0x685 /* FROM_5 */, 0x6c5 /* TO_5 */, 0xdc5 /* INFO_5 */ },
		{ 0x686 /* FROM_6 */, 0x6c6 /* TO_6 */, 0xdc6 /* INFO_6 */ },
		{ 0x687 /* FROM_7 */, 0x6c7 /* TO_7 */, 0xdc7 /* INFO_7 */ },
		{ 0x688 /* FROM_8 */, 0x6c8 /* TO_8 */, 0xdc8 /* INFO_8 */ },
		{ 0x689 /* FROM_9 */, 0x6c9 /* TO_9 */, 0xdc9 /* INFO_9 */ },
		{ 0x68A /* FROM_10 */, 0x6ca /* TO_10 */, 0xdca /* INFO_10 */ },
		{ 0x68B /* FROM_11 */, 0x6cb /* TO_11 */, 0xdcb /* INFO_11 */ },
		{ 0x68C /* FROM_12 */, 0x6cc /* TO_12 */, 0xdcc /* INFO_12 */ },
		{ 0x68D /* FROM_13 */, 0x6cd /* TO_13 */, 0xdcd /* INFO_13 */ },
		{ 0x68E /* FROM_14 */, 0x6ce /* TO_14 */, 0xdce /* INFO_14 */ },
		{ 0x68F /* FROM_15 */, 0x6cf /* TO_15 */, 0xdcf /* INFO_15 */ },
		{ 0x690 /* FROM_16 */, 0x6d0 /* TO_16 */, 0xdd0 /* INFO_16 */ },
		{ 0x691 /* FROM_17 */, 0x6d1 /* TO_17 */, 0xdd1 /* INFO_17 */ },
		{ 0x692 /* FROM_18 */, 0x6d2 /* TO_18 */, 0xdd2 /* INFO_18 */ },
		{ 0x693 /* FROM_19 */, 0x6d3 /* TO_19 */, 0xdd3 /* INFO_19 */ },
		{ 0x694 /* FROM_20 */, 0x6d4 /* TO_20 */, 0xdd4 /* INFO_20 */ },
		{ 0x695 /* FROM_21 */, 0x6d5 /* TO_21 */, 0xdd5 /* INFO_21 */ },
		{ 0x696 /* FROM_22 */, 0x6d6 /* TO_22 */, 0xdd6 /* INFO_22 */ },
		{ 0x697 /* FROM_23 */, 0x6d7 /* TO_23 */, 0xdd7 /* INFO_23 */ },
		{ 0x698 /* FROM_24 */, 0x6d8 /* TO_24 */, 0xdd8 /* INFO_24 */ },
		{ 0x699 /* FROM_25 */, 0x6d9 /* TO_25 */, 0xdd9 /* INFO_25 */ },
		{ 0x69a /* FROM_26 */, 0x6da /* TO_26 */, 0xdda /* INFO_26 */ },
		{ 0x69b /* FROM_27 */, 0x6db /* TO_27 */, 0xddb /* INFO_27 */ },
		{ 0x69c /* FROM_28 */, 0x6dc /* TO_28 */, 0xddc /* INFO_28 */ },
		{ 0x69d /* FROM_29 */, 0x6dd /* TO_29 */, 0xddd /* INFO_29 */ },
		{ 0x69e /* FROM_30 */, 0x6de /* TO_30 */, 0xdde /* INFO_30 */ },
		{ 0x69f /* FROM_31 */, 0x6df /* TO_31 */, 0xddf /* INFO_31 */ }
	}
};

void
i386_lbr_disable(void)
{
	/* Enable LBRs */
	wrmsr64(MSR_IA32_DEBUGCTLMSR, rdmsr64(MSR_IA32_DEBUGCTLMSR) & ~DEBUGCTL_LBR_ENA);
}

/*
 * Disable ASAN for i386_lbr_enable and i386_lbr_init, otherwise we get a KASAN panic
 * because the shadow map is not been initialized when these functions are called in
 * early boot.
 */
void __attribute__((no_sanitize("address")))
i386_lbr_enable(void)
{
	if (last_branch_support_enabled) {
		/* Enable LBRs */
		wrmsr64(MSR_IA32_DEBUGCTLMSR, rdmsr64(MSR_IA32_DEBUGCTLMSR) | DEBUGCTL_LBR_ENA);
	}
}

void __attribute__((no_sanitize("address")))
i386_lbr_init(i386_cpu_info_t *info_p, bool is_master)
{
	if (!last_branch_support_enabled) {
		i386_lbr_disable();
		return;
	}

	if (is_master) {
		/* All NHM+ CPUs support PERF_CAPABILITIES, so no need to check cpuid for its presence */
		cpu_lbr_type = PERFCAP_LBR_TYPE(rdmsr64(MSR_IA32_PERF_CAPABILITIES));

		switch (info_p->cpuid_cpufamily) {
		case CPUFAMILY_INTEL_NEHALEM:
		case CPUFAMILY_INTEL_WESTMERE:
			/* NHM family shares an LBR_SELECT MSR for both logical CPUs per core */
			cpu_lbr_setp = &nhm_cpu_lbrs;
			break;

		case CPUFAMILY_INTEL_SANDYBRIDGE:
		case CPUFAMILY_INTEL_IVYBRIDGE:
			/* SNB+ has dedicated LBR_SELECT MSRs for each logical CPU per core */
			cpu_lbr_setp = &nhm_cpu_lbrs;
			break;

		case CPUFAMILY_INTEL_HASWELL:
		case CPUFAMILY_INTEL_BROADWELL:
			lbr_need_tsx_workaround = cpuid_tsx_supported ? false : true;
			cpu_lbr_setp = &nhm_cpu_lbrs;
			break;

		case CPUFAMILY_INTEL_SKYLAKE:
		case CPUFAMILY_INTEL_KABYLAKE:
		case CPUFAMILY_INTEL_ICELAKE:
			cpu_lbr_setp = &skl_cpu_lbrs;
			break;

		default:
			panic("Unknown CPU family");
		}
	}

	/* Configure LBR_SELECT for CPL > 0 records only */
	wrmsr64(MSR_IA32_LBR_SELECT, LBR_SELECT_CPL_EQ_0);

	/* Enable LBRs */
	wrmsr64(MSR_IA32_DEBUGCTLMSR, rdmsr64(MSR_IA32_DEBUGCTLMSR) | DEBUGCTL_LBR_ENA);
}

int
i386_lbr_native_state_to_mach_thread_state(pcb_t pcb, last_branch_state_t *machlbrp)
{
	int last_entry;
	int i, j, lbr_tos;
	uint64_t from_rip, to_rip;
#define LBR_SENTINEL_KERNEL_MODE (0x66726d6b65726e6cULL /* "frmkernl" */ )

	machlbrp->lbr_count = cpu_lbr_setp->lbr_count;
	lbr_tos = pcb->lbrs.lbr_tos & (X86_MAX_LBRS - 1);
	last_entry = (lbr_tos == (cpu_lbr_setp->lbr_count - 1)) ? 0 : (lbr_tos + 1);

	switch (cpu_lbr_type) {
	case PERFCAP_LBR_TYPE_MISPRED:                  /* NHM */

		machlbrp->lbr_supported_tsx = 0;
		machlbrp->lbr_supported_cycle_count = 0;
		for (j = 0, i = lbr_tos;; (i = (i == 0) ? (cpu_lbr_setp->lbr_count - 1) : (i - 1)), j++) {
			to_rip = pcb->lbrs.lbrs[i].to_rip;
			machlbrp->lbrs[j].to_ip = (to_rip > VM_MAX_USER_PAGE_ADDRESS) ? LBR_SENTINEL_KERNEL_MODE : to_rip;
			from_rip = LBR_TYPE_MISPRED_FROMRIP(pcb->lbrs.lbrs[i].from_rip);
			machlbrp->lbrs[j].from_ip = (from_rip > VM_MAX_USER_PAGE_ADDRESS) ? LBR_SENTINEL_KERNEL_MODE : from_rip;
			machlbrp->lbrs[j].mispredict = LBR_TYPE_MISPRED_MISPREDICT(pcb->lbrs.lbrs[i].from_rip);
			machlbrp->lbrs[j].tsx_abort = machlbrp->lbrs[j].in_tsx = 0;     /* Not Supported */
			if (i == last_entry) {
				break;
			}
		}
		break;

	case PERFCAP_LBR_TYPE_TSXINFO:                  /* HSW/BDW */

		machlbrp->lbr_supported_tsx = cpuid_tsx_supported ? 1 : 0;
		machlbrp->lbr_supported_cycle_count = 0;
		for (j = 0, i = lbr_tos;; (i = (i == 0) ? (cpu_lbr_setp->lbr_count - 1) : (i - 1)), j++) {
			to_rip = pcb->lbrs.lbrs[i].to_rip;
			machlbrp->lbrs[j].to_ip = (to_rip > VM_MAX_USER_PAGE_ADDRESS) ? LBR_SENTINEL_KERNEL_MODE : to_rip;

			from_rip = LBR_TYPE_TSXINFO_FROMRIP(pcb->lbrs.lbrs[i].from_rip);
			machlbrp->lbrs[j].from_ip = (from_rip > VM_MAX_USER_PAGE_ADDRESS) ? LBR_SENTINEL_KERNEL_MODE : from_rip;
			machlbrp->lbrs[j].mispredict = LBR_TYPE_TSXINFO_MISPREDICT(pcb->lbrs.lbrs[i].from_rip);
			if (cpuid_tsx_supported) {
				machlbrp->lbrs[j].tsx_abort = LBR_TYPE_TSXINFO_TSX_ABORT(pcb->lbrs.lbrs[i].from_rip);
				machlbrp->lbrs[j].in_tsx = LBR_TYPE_TSXINFO_IN_TSX(pcb->lbrs.lbrs[i].from_rip);
			} else {
				machlbrp->lbrs[j].tsx_abort = 0;
				machlbrp->lbrs[j].in_tsx = 0;
			}
			if (i == last_entry) {
				break;
			}
		}
		break;

	case PERFCAP_LBR_TYPE_EIP_WITH_LBRINFO:         /* SKL+ */

		machlbrp->lbr_supported_tsx = cpuid_tsx_supported ? 1 : 0;
		machlbrp->lbr_supported_cycle_count = 1;
		for (j = 0, i = lbr_tos;; (i = (i == 0) ? (cpu_lbr_setp->lbr_count - 1) : (i - 1)), j++) {
			from_rip = pcb->lbrs.lbrs[i].from_rip;
			machlbrp->lbrs[j].from_ip = (from_rip > VM_MAX_USER_PAGE_ADDRESS) ? LBR_SENTINEL_KERNEL_MODE : from_rip;
			to_rip = pcb->lbrs.lbrs[i].to_rip;
			machlbrp->lbrs[j].to_ip = (to_rip > VM_MAX_USER_PAGE_ADDRESS) ? LBR_SENTINEL_KERNEL_MODE : to_rip;
			machlbrp->lbrs[j].mispredict = LBR_TYPE_EIP_WITH_LBRINFO_MISPREDICT(pcb->lbrs.lbrs[i].info);
			machlbrp->lbrs[j].tsx_abort = LBR_TYPE_EIP_WITH_LBRINFO_TSX_ABORT(pcb->lbrs.lbrs[i].info);
			machlbrp->lbrs[j].in_tsx = LBR_TYPE_EIP_WITH_LBRINFO_IN_TSX(pcb->lbrs.lbrs[i].info);
			machlbrp->lbrs[j].cycle_count = LBR_TYPE_EIP_WITH_LBRINFO_CYC_COUNT(pcb->lbrs.lbrs[i].info);
			if (i == last_entry) {
				break;
			}
		}
		break;

	default:
#if DEBUG || DEVELOPMENT
		panic("Unknown LBR format: %d!", cpu_lbr_type);
		/*NOTREACHED*/
#else
		return -1;
#endif
	}

	return 0;
}

void
i386_lbr_synch(thread_t thr)
{
	pcb_t old_pcb = THREAD_TO_PCB(thr);
	int i;

	/* First, save current LBRs to the old thread's PCB */
	if (cpu_lbr_setp->msr_lbrs[0].msr_info != 0) {
		for (i = 0; i < cpu_lbr_setp->lbr_count; i++) {
			old_pcb->lbrs.lbrs[i].from_rip = rdmsr64(cpu_lbr_setp->msr_lbrs[i].msr_from);
			old_pcb->lbrs.lbrs[i].to_rip = rdmsr64(cpu_lbr_setp->msr_lbrs[i].msr_to);
			old_pcb->lbrs.lbrs[i].info = rdmsr64(cpu_lbr_setp->msr_lbrs[i].msr_info);
		}
	} else {
		for (i = 0; i < cpu_lbr_setp->lbr_count; i++) {
			old_pcb->lbrs.lbrs[i].from_rip = rdmsr64(cpu_lbr_setp->msr_lbrs[i].msr_from);
			old_pcb->lbrs.lbrs[i].to_rip = rdmsr64(cpu_lbr_setp->msr_lbrs[i].msr_to);
		}
	}

	/* Finally, save the TOS */
	old_pcb->lbrs.lbr_tos = rdmsr64(MSR_IA32_LASTBRANCH_TOS);
}

void
i386_switch_lbrs(thread_t old, thread_t new)
{
	pcb_t   new_pcb;
	int     i;
	bool    save_old = (old != NULL && old->task != kernel_task);
	bool    restore_new = (new->task != kernel_task);

	if (!save_old && !restore_new) {
		return;
	}

	assert(cpu_lbr_setp != NULL);

	new_pcb = THREAD_TO_PCB(new);

	i386_lbr_disable();

	if (save_old) {
		i386_lbr_synch(old);
	}

	if (restore_new) {
		/* Now restore the new threads's LBRs */
		if (cpu_lbr_setp->msr_lbrs[0].msr_info != 0) {
			for (i = 0; i < cpu_lbr_setp->lbr_count; i++) {
				wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_from, new_pcb->lbrs.lbrs[i].from_rip);
				wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_to, new_pcb->lbrs.lbrs[i].to_rip);
				wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_info, new_pcb->lbrs.lbrs[i].info);
			}
		} else {
			if (lbr_need_tsx_workaround) {
				for (i = 0; i < cpu_lbr_setp->lbr_count; i++) {
					/*
					 * If TSX has been disabled, the hardware expects those two bits to be sign
					 * extensions of bit 47 (even though it didn't return them that way via the rdmsr!)
					 */
#define BIT_47 (1ULL << 47)
					wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_from,
					    new_pcb->lbrs.lbrs[i].from_rip |
					    ((new_pcb->lbrs.lbrs[i].from_rip & BIT_47) ? 0x6000000000000000ULL : 0));
					wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_to,
					    new_pcb->lbrs.lbrs[i].to_rip |
					    ((new_pcb->lbrs.lbrs[i].to_rip & BIT_47) ? 0x6000000000000000ULL : 0));
				}
			} else {
				for (i = 0; i < cpu_lbr_setp->lbr_count; i++) {
					wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_from, new_pcb->lbrs.lbrs[i].from_rip);
					wrmsr64(cpu_lbr_setp->msr_lbrs[i].msr_to, new_pcb->lbrs.lbrs[i].to_rip);
				}
			}
		}

		/* Lastly, restore the new threads's TOS */
		wrmsr64(MSR_IA32_LASTBRANCH_TOS, new_pcb->lbrs.lbr_tos);
	}

	i386_lbr_enable();
}

void
act_machine_switch_pcb(thread_t old, thread_t new)
{
	pcb_t                   pcb = THREAD_TO_PCB(new);
	cpu_data_t              *cdp = current_cpu_datap();
	struct real_descriptor  *ldtp;
	mach_vm_offset_t        pcb_stack_top;

	assert(new->kernel_stack != 0);
	assert(ml_get_interrupts_enabled() == FALSE);
#ifdef  DIRECTION_FLAG_DEBUG
	if (x86_get_flags() & EFL_DF) {
		panic("Direction flag detected: 0x%lx", x86_get_flags());
	}
#endif

	/*
	 * Clear segment state
	 * unconditionally for DS/ES/FS but more carefully for GS whose
	 * cached state we track.
	 */
	set_ds(NULL_SEG);
	set_es(NULL_SEG);
	set_fs(NULL_SEG);

	if (get_gs() != NULL_SEG) {
		swapgs();               /* switch to user's GS context */
		set_gs(NULL_SEG);
		swapgs();               /* and back to kernel */

		/* record the active machine state lost */
		cdp->cpu_uber.cu_user_gs_base = 0;
	}

	vm_offset_t                     isf;

	/*
	 * Set pointer to PCB's interrupt stack frame in cpu data.
	 * Used by syscall and double-fault trap handlers.
	 */
	isf = (vm_offset_t) &pcb->iss->ss_64.isf;
	cdp->cpu_uber.cu_isf = isf;
	pcb_stack_top = (vm_offset_t) (pcb->iss + 1);
	/* require 16-byte alignment */
	assert((pcb_stack_top & 0xF) == 0);

	current_ktss64()->rsp0 = cdp->cpu_desc_index.cdi_sstku;
	/*
	 * Top of temporary sysenter stack points to pcb stack.
	 * Although this is not normally used by 64-bit users,
	 * it needs to be set in case a sysenter is attempted.
	 */
	*current_sstk64() = pcb_stack_top;

	cdp->cd_estack = cpu_shadowp(cdp->cpu_number)->cd_estack = cdp->cpu_desc_index.cdi_sstku;

	if (is_saved_state64(pcb->iss)) {
		cdp->cpu_task_map = new->map->pmap->pm_task_map;

		/*
		 * Enable the 64-bit user code segment, USER64_CS.
		 * Disable the 32-bit user code segment, USER_CS.
		 */
		gdt_desc_p(USER64_CS)->access |= ACC_PL_U;
		gdt_desc_p(USER_CS)->access &= ~ACC_PL_U;

		/*
		 * Switch user's GS base if necessary
		 * by setting the Kernel's GS base MSR
		 * - this will become the user's on the swapgs when
		 * returning to user-space.  Avoid this for
		 * kernel threads (no user TLS support required)
		 * and verify the memory shadow of the segment base
		 * in the event it was altered in user space.
		 */
		if ((pcb->cthread_self != 0) || (new->task != kernel_task)) {
			if ((cdp->cpu_uber.cu_user_gs_base != pcb->cthread_self) ||
			    (pcb->cthread_self != rdmsr64(MSR_IA32_KERNEL_GS_BASE))) {
				cdp->cpu_uber.cu_user_gs_base = pcb->cthread_self;
				wrmsr64(MSR_IA32_KERNEL_GS_BASE, pcb->cthread_self);
			}
		}
	} else {
		cdp->cpu_task_map = TASK_MAP_32BIT;

		/*
		 * Disable USER64_CS
		 * Enable USER_CS
		 */

		/* It's possible that writing to the GDT areas
		 * is expensive, if the processor intercepts those
		 * writes to invalidate its internal segment caches
		 * TODO: perhaps only do this if switching bitness
		 */
		gdt_desc_p(USER64_CS)->access &= ~ACC_PL_U;
		gdt_desc_p(USER_CS)->access |= ACC_PL_U;

		/*
		 * Set the thread`s cthread (a.k.a pthread)
		 * For 32-bit user this involves setting the USER_CTHREAD
		 * descriptor in the LDT to point to the cthread data.
		 * The involves copying in the pre-initialized descriptor.
		 */
		ldtp = current_ldt();
		ldtp[sel_idx(USER_CTHREAD)] = pcb->cthread_desc;
		if (pcb->uldt_selector != 0) {
			ldtp[sel_idx(pcb->uldt_selector)] = pcb->uldt_desc;
		}
		cdp->cpu_uber.cu_user_gs_base = pcb->cthread_self;
	}

	cdp->cpu_curthread_do_segchk = new->machine.mthr_do_segchk;

	if (last_branch_support_enabled) {
		i386_switch_lbrs(old, new);
	}

	/*
	 * Set the thread`s LDT or LDT entry.
	 */
	if (__probable(new->task == TASK_NULL || new->task->i386_ldt == 0)) {
		/*
		 * Use system LDT.
		 */
		ml_cpu_set_ldt(KERNEL_LDT);
		cdp->cpu_curtask_has_ldt = 0;
	} else {
		/*
		 * Task has its own LDT.
		 */
		user_ldt_set(new);
		cdp->cpu_curtask_has_ldt = 1;
	}
}

kern_return_t
thread_set_wq_state32(thread_t thread, thread_state_t tstate)
{
	x86_thread_state32_t    *state;
	x86_saved_state32_t     *saved_state;
	thread_t curth = current_thread();
	spl_t                   s = 0;

	pal_register_cache_state(thread, DIRTY);

	saved_state = USER_REGS32(thread);

	state = (x86_thread_state32_t *)tstate;

	if (curth != thread) {
		s = splsched();
		thread_lock(thread);
	}

	saved_state->ebp = 0;
	saved_state->eip = state->eip;
	saved_state->eax = state->eax;
	saved_state->ebx = state->ebx;
	saved_state->ecx = state->ecx;
	saved_state->edx = state->edx;
	saved_state->edi = state->edi;
	saved_state->esi = state->esi;
	saved_state->uesp = state->esp;
	saved_state->efl = EFL_USER_SET;

	saved_state->cs = USER_CS;
	saved_state->ss = USER_DS;
	saved_state->ds = USER_DS;
	saved_state->es = USER_DS;

	if (curth != thread) {
		thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}


kern_return_t
thread_set_wq_state64(thread_t thread, thread_state_t tstate)
{
	x86_thread_state64_t    *state;
	x86_saved_state64_t     *saved_state;
	thread_t curth = current_thread();
	spl_t                   s = 0;

	saved_state = USER_REGS64(thread);
	state = (x86_thread_state64_t *)tstate;

	/* Disallow setting non-canonical PC or stack */
	if (!IS_USERADDR64_CANONICAL(state->rsp) ||
	    !IS_USERADDR64_CANONICAL(state->rip)) {
		return KERN_FAILURE;
	}

	pal_register_cache_state(thread, DIRTY);

	if (curth != thread) {
		s = splsched();
		thread_lock(thread);
	}

	saved_state->rbp = 0;
	saved_state->rdi = state->rdi;
	saved_state->rsi = state->rsi;
	saved_state->rdx = state->rdx;
	saved_state->rcx = state->rcx;
	saved_state->r8  = state->r8;
	saved_state->r9  = state->r9;

	saved_state->isf.rip = state->rip;
	saved_state->isf.rsp = state->rsp;
	saved_state->isf.cs = USER64_CS;
	saved_state->isf.rflags = EFL_USER_SET;

	if (curth != thread) {
		thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}

/*
 * Initialize the machine-dependent state for a new thread.
 */
kern_return_t
machine_thread_create(
	thread_t                thread,
	task_t                  task)
{
	pcb_t                   pcb = THREAD_TO_PCB(thread);

	if ((task->t_flags & TF_TECS) || __improbable(force_thread_policy_tecs)) {
		thread->machine.mthr_do_segchk = 1;
	} else {
		thread->machine.mthr_do_segchk = 0;
	}

	/*
	 * Allocate save frame only if required.
	 */
	if (pcb->iss == NULL) {
		assert((get_preemption_level() == 0));
		pcb->iss = (x86_saved_state_t *) zalloc(iss_zone);
		if (pcb->iss == NULL) {
			panic("iss_zone");
		}
	}

	/*
	 * Ensure that the synthesized 32-bit state including
	 * the 64-bit interrupt state can be acommodated in the
	 * 64-bit state we allocate for both 32-bit and 64-bit threads.
	 */
	assert(sizeof(pcb->iss->ss_32) + sizeof(pcb->iss->ss_64.isf) <=
	    sizeof(pcb->iss->ss_64));

	bzero((char *)pcb->iss, sizeof(x86_saved_state_t));

	bzero(&pcb->lbrs, sizeof(x86_lbrs_t));

	if (task_has_64Bit_addr(task)) {
		pcb->iss->flavor = x86_SAVED_STATE64;

		pcb->iss->ss_64.isf.cs = USER64_CS;
		pcb->iss->ss_64.isf.ss = USER_DS;
		pcb->iss->ss_64.fs = USER_DS;
		pcb->iss->ss_64.gs = USER_DS;
		pcb->iss->ss_64.isf.rflags = EFL_USER_SET;
	} else {
		pcb->iss->flavor = x86_SAVED_STATE32;

		pcb->iss->ss_32.cs = USER_CS;
		pcb->iss->ss_32.ss = USER_DS;
		pcb->iss->ss_32.ds = USER_DS;
		pcb->iss->ss_32.es = USER_DS;
		pcb->iss->ss_32.fs = USER_DS;
		pcb->iss->ss_32.gs = USER_DS;
		pcb->iss->ss_32.efl = EFL_USER_SET;
	}

	simple_lock_init(&pcb->lock, 0);

	pcb->cthread_self = 0;
	pcb->uldt_selector = 0;
	pcb->thread_gpu_ns = 0;
	/* Ensure that the "cthread" descriptor describes a valid
	 * segment.
	 */
	if ((pcb->cthread_desc.access & ACC_P) == 0) {
		pcb->cthread_desc = *gdt_desc_p(USER_DS);
	}


	pcb->insn_state_copyin_failure_errorcode = 0;
	if (pcb->insn_state != 0) {     /* Reinit for new thread */
		bzero(pcb->insn_state, sizeof(x86_instruction_state_t));
		pcb->insn_state->insn_stream_valid_bytes = -1;
	}

	return KERN_SUCCESS;
}

/*
 * Machine-dependent cleanup prior to destroying a thread
 */
void
machine_thread_destroy(
	thread_t                thread)
{
	pcb_t   pcb = THREAD_TO_PCB(thread);

#if HYPERVISOR
	if (thread->hv_thread_target) {
		hv_callbacks.thread_destroy(thread->hv_thread_target);
		thread->hv_thread_target = NULL;
	}
#endif

	if (pcb->ifps != 0) {
		fpu_free(thread, pcb->ifps);
	}
	if (pcb->iss != 0) {
		zfree(iss_zone, pcb->iss);
		pcb->iss = 0;
	}
	if (pcb->ids) {
		zfree(ids_zone, pcb->ids);
		pcb->ids = NULL;
	}

	if (pcb->insn_state != 0) {
		kfree(pcb->insn_state, sizeof(x86_instruction_state_t));
		pcb->insn_state = 0;
	}
	pcb->insn_state_copyin_failure_errorcode = 0;
}

kern_return_t
machine_thread_set_tsd_base(
	thread_t                        thread,
	mach_vm_offset_t        tsd_base)
{
	if (thread->task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	if (thread_is_64bit_addr(thread)) {
		/* check for canonical address, set 0 otherwise  */
		if (!IS_USERADDR64_CANONICAL(tsd_base)) {
			tsd_base = 0ULL;
		}
	} else {
		if (tsd_base > UINT32_MAX) {
			tsd_base = 0ULL;
		}
	}

	pcb_t pcb = THREAD_TO_PCB(thread);
	pcb->cthread_self = tsd_base;

	if (!thread_is_64bit_addr(thread)) {
		/* Set up descriptor for later use */
		struct real_descriptor desc = {
			.limit_low = 1,
			.limit_high = 0,
			.base_low = tsd_base & 0xffff,
			.base_med = (tsd_base >> 16) & 0xff,
			.base_high = (tsd_base >> 24) & 0xff,
			.access = ACC_P | ACC_PL_U | ACC_DATA_W,
			.granularity = SZ_32 | SZ_G,
		};

		pcb->cthread_desc = desc;
		saved_state32(pcb->iss)->gs = USER_CTHREAD;
	}

	/* For current thread, make the TSD base active immediately */
	if (thread == current_thread()) {
		if (thread_is_64bit_addr(thread)) {
			cpu_data_t              *cdp;

			mp_disable_preemption();
			cdp = current_cpu_datap();
			if ((cdp->cpu_uber.cu_user_gs_base != pcb->cthread_self) ||
			    (pcb->cthread_self != rdmsr64(MSR_IA32_KERNEL_GS_BASE))) {
				wrmsr64(MSR_IA32_KERNEL_GS_BASE, tsd_base);
			}
			cdp->cpu_uber.cu_user_gs_base = tsd_base;
			mp_enable_preemption();
		} else {
			/* assign descriptor */
			mp_disable_preemption();
			*ldt_desc_p(USER_CTHREAD) = pcb->cthread_desc;
			mp_enable_preemption();
		}
	}

	return KERN_SUCCESS;
}

void
machine_tecs(thread_t thr)
{
	if (tecs_mode_supported) {
		thr->machine.mthr_do_segchk = 1;
	}
}

int
machine_csv(cpuvn_e cve)
{
	switch (cve) {
	case CPUVN_CI:
		return (cpuid_wa_required(CPU_INTEL_SEGCHK) & CWA_ON) != 0;

	default:
		break;
	}

	return 0;
}
