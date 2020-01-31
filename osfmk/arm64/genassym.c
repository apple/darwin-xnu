/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#include <stddef.h>

#include <mach_ldebug.h>

/*
 * Pass field offsets to assembly code.
 */
#include <kern/ast.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/locks.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <kern/syscall_sw.h>
#include <arm/thread.h>
#include <mach/arm/vm_param.h>
#include <arm/misc_protos.h>
#include <arm/pmap.h>
#include <arm/trap.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_capabilities.h>
#include <arm/cpu_internal.h>
#include <arm/rtclock.h>
#include <machine/commpage.h>
#include <vm/vm_map.h>
#include <pexpert/arm64/boot.h>
#include <arm64/proc_reg.h>
#include <prng/random.h>

/*
 * genassym.c is used to produce an
 * assembly file which, intermingled with unuseful assembly code,
 * has all the necessary definitions emitted. This assembly file is
 * then postprocessed with sed to extract only these definitions
 * and thus the final assyms.s is created.
 *
 * This convoluted means is necessary since the structure alignment
 * and packing may be different between the host machine and the
 * target so we are forced into using the cross compiler to generate
 * the values, but we cannot run anything on the target machine.
 */

#define DECLARE(SYM, VAL) \
	__asm("DEFINITION__define__" SYM ":\t .ascii \"%0\"" : : "n"  ((u_long)(VAL)))


int     main(
	int             argc,
	char            ** argv);

int
main(
	int     argc,
	char    **argv)
{
	DECLARE("T_PREFETCH_ABT", T_PREFETCH_ABT);
	DECLARE("T_DATA_ABT", T_DATA_ABT);

	DECLARE("AST_URGENT", AST_URGENT);
	DECLARE("AST_PREEMPTION", AST_PREEMPTION);

	DECLARE("TH_RECOVER", offsetof(struct thread, recover));
	DECLARE("TH_CONTINUATION", offsetof(struct thread, continuation));
	DECLARE("TH_KERNEL_STACK", offsetof(struct thread, kernel_stack));
	DECLARE("TH_KSTACKPTR", offsetof(struct thread, machine.kstackptr));
	DECLARE("THREAD_UTHREAD", offsetof(struct thread, uthread));

	DECLARE("TASK_MACH_EXC_PORT",
	    offsetof(struct task, exc_actions[EXC_MACH_SYSCALL].port));

	/* These fields are being added on demand */
	DECLARE("ACT_TASK", offsetof(struct thread, task));
	DECLARE("ACT_CONTEXT", offsetof(struct thread, machine.contextData));
	DECLARE("ACT_UPCB", offsetof(struct thread, machine.upcb));
//	DECLARE("ACT_PCBDATA",	offsetof(struct thread, machine.contextData.ss));
	DECLARE("ACT_UNEON", offsetof(struct thread, machine.uNeon));
//	DECLARE("ACT_NEONDATA", offsetof(struct thread, machine.contextData.ns));
	DECLARE("TH_CTH_SELF", offsetof(struct thread, machine.cthread_self));
	DECLARE("TH_CTH_DATA", offsetof(struct thread, machine.cthread_data));
	DECLARE("ACT_PREEMPT_CNT", offsetof(struct thread, machine.preemption_count));
	DECLARE("ACT_CPUDATAP", offsetof(struct thread, machine.CpuDatap));
	DECLARE("ACT_MAP", offsetof(struct thread, map));
	DECLARE("ACT_DEBUGDATA", offsetof(struct thread, machine.DebugData));
	DECLARE("TH_IOTIER_OVERRIDE", offsetof(struct thread, iotier_override));
	DECLARE("TH_RWLOCK_CNT", offsetof(struct thread, rwlock_count));
	DECLARE("TH_SCHED_FLAGS", offsetof(struct thread, sched_flags));
	DECLARE("TH_SFLAG_RW_PROMOTED_BIT", TH_SFLAG_RW_PROMOTED_BIT);

	DECLARE("TH_MACH_SYSCALLS", offsetof(struct thread, syscalls_mach));
	DECLARE("TH_UNIX_SYSCALLS", offsetof(struct thread, syscalls_unix));
	DECLARE("TASK_BSD_INFO", offsetof(struct task, bsd_info));

	DECLARE("MACH_TRAP_TABLE_COUNT", MACH_TRAP_TABLE_COUNT);
	DECLARE("MACH_TRAP_TABLE_ENTRY_SIZE", sizeof(mach_trap_t));

	DECLARE("MAP_PMAP", offsetof(struct _vm_map, pmap));

	DECLARE("ARM_CONTEXT_SIZE", sizeof(arm_context_t));

	DECLARE("CONTEXT_SS", offsetof(arm_context_t, ss));
	DECLARE("SS_FLAVOR", offsetof(arm_context_t, ss.ash.flavor));
	DECLARE("ARM_SAVED_STATE32", ARM_SAVED_STATE32);
	DECLARE("ARM_SAVED_STATE64", ARM_SAVED_STATE64);
	DECLARE("ARM_SAVED_STATE64_COUNT", ARM_SAVED_STATE64_COUNT);

	DECLARE("SS32_W0", offsetof(arm_context_t, ss.ss_32.r[0]));
	DECLARE("SS32_W2", offsetof(arm_context_t, ss.ss_32.r[2]));
	DECLARE("SS32_W4", offsetof(arm_context_t, ss.ss_32.r[4]));
	DECLARE("SS32_W6", offsetof(arm_context_t, ss.ss_32.r[6]));
	DECLARE("SS32_W8", offsetof(arm_context_t, ss.ss_32.r[8]));
	DECLARE("SS32_W10", offsetof(arm_context_t, ss.ss_32.r[10]));
	DECLARE("SS32_W12", offsetof(arm_context_t, ss.ss_32.r[12]));
	DECLARE("SS32_SP", offsetof(arm_context_t, ss.ss_32.sp));
	DECLARE("SS32_LR", offsetof(arm_context_t, ss.ss_32.lr));
	DECLARE("SS32_PC", offsetof(arm_context_t, ss.ss_32.pc));
	DECLARE("SS32_CPSR", offsetof(arm_context_t, ss.ss_32.cpsr));
	DECLARE("SS32_VADDR", offsetof(arm_context_t, ss.ss_32.far));
	DECLARE("SS32_STATUS", offsetof(arm_context_t, ss.ss_32.esr));

	DECLARE("SS64_X0", offsetof(arm_context_t, ss.ss_64.x[0]));
	DECLARE("SS64_X2", offsetof(arm_context_t, ss.ss_64.x[2]));
	DECLARE("SS64_X4", offsetof(arm_context_t, ss.ss_64.x[4]));
	DECLARE("SS64_X6", offsetof(arm_context_t, ss.ss_64.x[6]));
	DECLARE("SS64_X8", offsetof(arm_context_t, ss.ss_64.x[8]));
	DECLARE("SS64_X10", offsetof(arm_context_t, ss.ss_64.x[10]));
	DECLARE("SS64_X12", offsetof(arm_context_t, ss.ss_64.x[12]));
	DECLARE("SS64_X14", offsetof(arm_context_t, ss.ss_64.x[14]));
	DECLARE("SS64_X16", offsetof(arm_context_t, ss.ss_64.x[16]));
	DECLARE("SS64_X18", offsetof(arm_context_t, ss.ss_64.x[18]));
	DECLARE("SS64_X19", offsetof(arm_context_t, ss.ss_64.x[19]));
	DECLARE("SS64_X20", offsetof(arm_context_t, ss.ss_64.x[20]));
	DECLARE("SS64_X21", offsetof(arm_context_t, ss.ss_64.x[21]));
	DECLARE("SS64_X22", offsetof(arm_context_t, ss.ss_64.x[22]));
	DECLARE("SS64_X23", offsetof(arm_context_t, ss.ss_64.x[23]));
	DECLARE("SS64_X24", offsetof(arm_context_t, ss.ss_64.x[24]));
	DECLARE("SS64_X25", offsetof(arm_context_t, ss.ss_64.x[25]));
	DECLARE("SS64_X26", offsetof(arm_context_t, ss.ss_64.x[26]));
	DECLARE("SS64_X27", offsetof(arm_context_t, ss.ss_64.x[27]));
	DECLARE("SS64_X28", offsetof(arm_context_t, ss.ss_64.x[28]));
	DECLARE("SS64_FP", offsetof(arm_context_t, ss.ss_64.fp));
	DECLARE("SS64_LR", offsetof(arm_context_t, ss.ss_64.lr));
	DECLARE("SS64_SP", offsetof(arm_context_t, ss.ss_64.sp));
	DECLARE("SS64_PC", offsetof(arm_context_t, ss.ss_64.pc));
	DECLARE("SS64_CPSR", offsetof(arm_context_t, ss.ss_64.cpsr));
	DECLARE("SS64_FAR", offsetof(arm_context_t, ss.ss_64.far));
	DECLARE("SS64_ESR", offsetof(arm_context_t, ss.ss_64.esr));

	DECLARE("CONTEXT_NS", offsetof(arm_context_t, ns));
	DECLARE("NS_FLAVOR", offsetof(arm_context_t, ns.nsh.flavor));
	DECLARE("NS_COUNT", offsetof(arm_context_t, ns.nsh.count));
	DECLARE("ARM_NEON_SAVED_STATE32", ARM_NEON_SAVED_STATE32);
	DECLARE("ARM_NEON_SAVED_STATE64", ARM_NEON_SAVED_STATE64);
	DECLARE("ARM_NEON_SAVED_STATE64_COUNT", ARM_NEON_SAVED_STATE64_COUNT);

	DECLARE("NS32_Q0", offsetof(arm_context_t, ns.ns_32.v.q[0]));
	DECLARE("NS32_Q2", offsetof(arm_context_t, ns.ns_32.v.q[2]));
	DECLARE("NS32_Q4", offsetof(arm_context_t, ns.ns_32.v.q[4]));
	DECLARE("NS32_Q6", offsetof(arm_context_t, ns.ns_32.v.q[6]));
	DECLARE("NS32_Q8", offsetof(arm_context_t, ns.ns_32.v.q[8]));
	DECLARE("NS32_Q10", offsetof(arm_context_t, ns.ns_32.v.q[10]));
	DECLARE("NS32_Q12", offsetof(arm_context_t, ns.ns_32.v.q[12]));
	DECLARE("NS32_Q14", offsetof(arm_context_t, ns.ns_32.v.q[14]));
	DECLARE("NS32_FPSR", offsetof(arm_context_t, ns.ns_32.fpsr));
	DECLARE("NS32_FPCR", offsetof(arm_context_t, ns.ns_32.fpcr));

	DECLARE("NS64_D8", offsetof(arm_context_t, ns.ns_64.v.d[8]));
	DECLARE("NS64_D9", offsetof(arm_context_t, ns.ns_64.v.d[9]));
	DECLARE("NS64_D10", offsetof(arm_context_t, ns.ns_64.v.d[10]));
	DECLARE("NS64_D11", offsetof(arm_context_t, ns.ns_64.v.d[11]));
	DECLARE("NS64_D12", offsetof(arm_context_t, ns.ns_64.v.d[12]));
	DECLARE("NS64_D13", offsetof(arm_context_t, ns.ns_64.v.d[13]));
	DECLARE("NS64_D14", offsetof(arm_context_t, ns.ns_64.v.d[14]));
	DECLARE("NS64_D15", offsetof(arm_context_t, ns.ns_64.v.d[15]));

	DECLARE("NS64_Q0", offsetof(arm_context_t, ns.ns_64.v.q[0]));
	DECLARE("NS64_Q2", offsetof(arm_context_t, ns.ns_64.v.q[2]));
	DECLARE("NS64_Q4", offsetof(arm_context_t, ns.ns_64.v.q[4]));
	DECLARE("NS64_Q6", offsetof(arm_context_t, ns.ns_64.v.q[6]));
	DECLARE("NS64_Q8", offsetof(arm_context_t, ns.ns_64.v.q[8]));
	DECLARE("NS64_Q10", offsetof(arm_context_t, ns.ns_64.v.q[10]));
	DECLARE("NS64_Q12", offsetof(arm_context_t, ns.ns_64.v.q[12]));
	DECLARE("NS64_Q14", offsetof(arm_context_t, ns.ns_64.v.q[14]));
	DECLARE("NS64_Q16", offsetof(arm_context_t, ns.ns_64.v.q[16]));
	DECLARE("NS64_Q18", offsetof(arm_context_t, ns.ns_64.v.q[18]));
	DECLARE("NS64_Q20", offsetof(arm_context_t, ns.ns_64.v.q[20]));
	DECLARE("NS64_Q22", offsetof(arm_context_t, ns.ns_64.v.q[22]));
	DECLARE("NS64_Q24", offsetof(arm_context_t, ns.ns_64.v.q[24]));
	DECLARE("NS64_Q26", offsetof(arm_context_t, ns.ns_64.v.q[26]));
	DECLARE("NS64_Q28", offsetof(arm_context_t, ns.ns_64.v.q[28]));
	DECLARE("NS64_Q30", offsetof(arm_context_t, ns.ns_64.v.q[30]));
	DECLARE("NS64_FPSR", offsetof(arm_context_t, ns.ns_64.fpsr));
	DECLARE("NS64_FPCR", offsetof(arm_context_t, ns.ns_64.fpcr));

	DECLARE("PGBYTES", ARM_PGBYTES);
	DECLARE("PGSHIFT", ARM_PGSHIFT);
	DECLARE("PGMASK", ARM_PGMASK);

	DECLARE("VM_MIN_ADDRESS", VM_MIN_ADDRESS);
	DECLARE("VM_MAX_ADDRESS", VM_MAX_ADDRESS);
	DECLARE("VM_MIN_KERNEL_ADDRESS", VM_MIN_KERNEL_ADDRESS);
	DECLARE("VM_MAX_KERNEL_ADDRESS", VM_MAX_KERNEL_ADDRESS);
	DECLARE("KERNELBASE", VM_MIN_KERNEL_ADDRESS);
	DECLARE("KERNEL_STACK_SIZE", KERNEL_STACK_SIZE);
	DECLARE("TBI_MASK", TBI_MASK);

	DECLARE("KERN_INVALID_ADDRESS", KERN_INVALID_ADDRESS);


	DECLARE("MAX_CPUS", MAX_CPUS);

	DECLARE("cdeSize",
	    sizeof(struct cpu_data_entry));

	DECLARE("cdSize",
	    sizeof(struct cpu_data));

	DECLARE("CPU_ACTIVE_THREAD",
	    offsetof(cpu_data_t, cpu_active_thread));
	DECLARE("CPU_ACTIVE_STACK",
	    offsetof(cpu_data_t, cpu_active_stack));
	DECLARE("CPU_ISTACKPTR",
	    offsetof(cpu_data_t, istackptr));
	DECLARE("CPU_INTSTACK_TOP",
	    offsetof(cpu_data_t, intstack_top));
	DECLARE("CPU_EXCEPSTACKPTR",
	    offsetof(cpu_data_t, excepstackptr));
	DECLARE("CPU_EXCEPSTACK_TOP",
	    offsetof(cpu_data_t, excepstack_top));
#if __ARM_KERNEL_PROTECT__
	DECLARE("CPU_EXC_VECTORS",
	    offsetof(cpu_data_t, cpu_exc_vectors));
#endif /* __ARM_KERNEL_PROTECT__ */
	DECLARE("CPU_NUMBER_GS",
	    offsetof(cpu_data_t, cpu_number));
	DECLARE("CPU_IDENT",
	    offsetof(cpu_data_t, cpu_ident));
	DECLARE("CPU_RUNNING",
	    offsetof(cpu_data_t, cpu_running));
	DECLARE("CPU_MCOUNT_OFF",
	    offsetof(cpu_data_t, cpu_mcount_off));
	DECLARE("CPU_PENDING_AST",
	    offsetof(cpu_data_t, cpu_pending_ast));
	DECLARE("CPU_PROCESSOR",
	    offsetof(cpu_data_t, cpu_processor));
	DECLARE("CPU_CACHE_DISPATCH",
	    offsetof(cpu_data_t, cpu_cache_dispatch));
	DECLARE("CPU_BASE_TIMEBASE",
	    offsetof(cpu_data_t, cpu_base_timebase));
	DECLARE("CPU_DECREMENTER",
	    offsetof(cpu_data_t, cpu_decrementer));
	DECLARE("CPU_GET_DECREMENTER_FUNC",
	    offsetof(cpu_data_t, cpu_get_decrementer_func));
	DECLARE("CPU_SET_DECREMENTER_FUNC",
	    offsetof(cpu_data_t, cpu_set_decrementer_func));
	DECLARE("CPU_GET_FIQ_HANDLER",
	    offsetof(cpu_data_t, cpu_get_fiq_handler));
	DECLARE("CPU_TBD_HARDWARE_ADDR",
	    offsetof(cpu_data_t, cpu_tbd_hardware_addr));
	DECLARE("CPU_TBD_HARDWARE_VAL",
	    offsetof(cpu_data_t, cpu_tbd_hardware_val));
	DECLARE("CPU_INT_STATE",
	    offsetof(cpu_data_t, cpu_int_state));
	DECLARE("INTERRUPT_HANDLER",
	    offsetof(cpu_data_t, interrupt_handler));
	DECLARE("INTERRUPT_TARGET",
	    offsetof(cpu_data_t, interrupt_target));
	DECLARE("INTERRUPT_REFCON",
	    offsetof(cpu_data_t, interrupt_refCon));
	DECLARE("INTERRUPT_NUB",
	    offsetof(cpu_data_t, interrupt_nub));
	DECLARE("INTERRUPT_SOURCE",
	    offsetof(cpu_data_t, interrupt_source));
	DECLARE("CPU_USER_DEBUG",
	    offsetof(cpu_data_t, cpu_user_debug));
	DECLARE("CPU_STAT_IRQ",
	    offsetof(cpu_data_t, cpu_stat.irq_ex_cnt));
	DECLARE("CPU_STAT_IRQ_WAKE",
	    offsetof(cpu_data_t, cpu_stat.irq_ex_cnt_wake));
	DECLARE("CPU_RESET_HANDLER",
	    offsetof(cpu_data_t, cpu_reset_handler));
	DECLARE("CPU_RESET_ASSIST",
	    offsetof(cpu_data_t, cpu_reset_assist));
	DECLARE("CPU_REGMAP_PADDR",
	    offsetof(cpu_data_t, cpu_regmap_paddr));
	DECLARE("CPU_PHYS_ID",
	    offsetof(cpu_data_t, cpu_phys_id));
	DECLARE("RTCLOCK_DATAP",
	    offsetof(cpu_data_t, rtclock_datap));
	DECLARE("CLUSTER_MASTER",
	    offsetof(cpu_data_t, cluster_master));

	DECLARE("RTCLOCKDataSize",
	    sizeof(rtclock_data_t));
	DECLARE("RTCLOCK_ADJ_ABSTIME_LOW",
	    offsetof(rtclock_data_t, rtc_adj.abstime_val.low));
	DECLARE("RTCLOCK_ADJ_ABSTIME_HIGH",
	    offsetof(rtclock_data_t, rtc_adj.abstime_val.high));
	DECLARE("RTCLOCK_BASE_ABSTIME_LOW",
	    offsetof(rtclock_data_t, rtc_base.abstime_val.low));
	DECLARE("RTCLOCK_BASE_ABSTIME_HIGH",
	    offsetof(rtclock_data_t, rtc_base.abstime_val.high));

	DECLARE("SIGPdec", SIGPdec);

	DECLARE("rhdSize",
	    sizeof(struct reset_handler_data));
#if WITH_CLASSIC_S2R || !__arm64__
	DECLARE("stSize",
	    sizeof(SleepToken));
#endif

	DECLARE("CPU_DATA_ENTRIES", offsetof(struct reset_handler_data, cpu_data_entries));
	DECLARE("ASSIST_RESET_HANDLER", offsetof(struct reset_handler_data, assist_reset_handler));

	DECLARE("CPU_DATA_PADDR", offsetof(struct cpu_data_entry, cpu_data_paddr));

	DECLARE("INTSTACK_SIZE", INTSTACK_SIZE);
	DECLARE("EXCEPSTACK_SIZE", EXCEPSTACK_SIZE);

	DECLARE("PAGE_MAX_SIZE", PAGE_MAX_SIZE);

	DECLARE("TIMER_TSTAMP",
	    offsetof(struct timer, tstamp));
	DECLARE("THREAD_TIMER",
	    offsetof(struct processor, processor_data.thread_timer));
	DECLARE("KERNEL_TIMER",
	    offsetof(struct processor, processor_data.kernel_timer));
	DECLARE("SYSTEM_STATE",
	    offsetof(struct processor, processor_data.system_state));
	DECLARE("USER_STATE",
	    offsetof(struct processor, processor_data.user_state));
	DECLARE("CURRENT_STATE",
	    offsetof(struct processor, processor_data.current_state));

	DECLARE("SYSTEM_TIMER",
	    offsetof(struct thread, system_timer));
	DECLARE("USER_TIMER",
	    offsetof(struct thread, user_timer));

#if !CONFIG_SKIP_PRECISE_USER_KERNEL_TIME
	DECLARE("PRECISE_USER_KERNEL_TIME",
	    offsetof(struct thread, precise_user_kernel_time));
#endif

	DECLARE("BA_VIRT_BASE",
	    offsetof(struct boot_args, virtBase));
	DECLARE("BA_PHYS_BASE",
	    offsetof(struct boot_args, physBase));
	DECLARE("BA_MEM_SIZE",
	    offsetof(struct boot_args, memSize));
	DECLARE("BA_TOP_OF_KERNEL_DATA",
	    offsetof(struct boot_args, topOfKernelData));
	DECLARE("BA_DEVICE_TREE",
	    offsetof(struct boot_args, deviceTreeP));
	DECLARE("BA_DEVICE_TREE_LENGTH",
	    offsetof(struct boot_args, deviceTreeLength));
	DECLARE("BA_BOOT_FLAGS",
	    offsetof(struct boot_args, bootFlags));

	DECLARE("ENTROPY_INDEX_PTR",
	    offsetof(entropy_data_t, index_ptr));
	DECLARE("ENTROPY_BUFFER",
	    offsetof(entropy_data_t, buffer));
	DECLARE("ENTROPY_DATA_SIZE", sizeof(struct entropy_data));

	DECLARE("SR_RESTORE_TCR_EL1", offsetof(struct sysreg_restore, tcr_el1));



	return 0;
}
