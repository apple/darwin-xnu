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
#include <arm/pmap.h>
#include <arm/trap.h>
#include <arm/cpu_data_internal.h>
#include <arm/cpu_capabilities.h>
#include <arm/cpu_internal.h>
#include <arm/rtclock.h>
#include <machine/commpage.h>
#include <vm/vm_map.h>
#include <pexpert/arm/boot.h>
#include <arm/proc_reg.h>
#include <prng/random.h>

#if	CONFIG_DTRACE
#define NEED_DTRACE_DEFS
#include <../bsd/sys/lockstat.h>
#endif	/* CONFIG_DTRACE */

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

#define DECLARE(SYM,VAL) \
	__asm("DEFINITION__define__" SYM ":\t .ascii \"%0\"" : : "n"  ((u_int)(VAL)))


int	main(
		int		argc,
		char		** argv);

int
main(
	int	argc,
	char	**argv)
{

	DECLARE("T_PREFETCH_ABT",	T_PREFETCH_ABT);
	DECLARE("T_DATA_ABT",		T_DATA_ABT);

	DECLARE("AST_URGENT",		AST_URGENT);
	DECLARE("AST_PREEMPTION",	AST_PREEMPTION);

	DECLARE("TH_RECOVER",		offsetof(struct thread, recover));
	DECLARE("TH_CONTINUATION",	offsetof(struct thread, continuation));
	DECLARE("TH_KERNEL_STACK",	offsetof(struct thread, kernel_stack));
	DECLARE("TH_KSTACKPTR",		offsetof(struct thread, machine.kstackptr));
        DECLARE("TH_UTHREAD",		offsetof(struct thread, uthread));

	DECLARE("TASK_MACH_EXC_PORT",
		offsetof(struct task, exc_actions[EXC_MACH_SYSCALL].port));

	/* These fields are being added on demand */
	DECLARE("ACT_TASK",	offsetof(struct thread, task));
	DECLARE("ACT_PCBDATA",	offsetof(struct thread, machine.PcbData));
#if __ARM_VFP__
	DECLARE("ACT_UVFP",     offsetof(struct thread, machine.uVFPdata));
	DECLARE("ACT_KVFP",     offsetof(struct thread, machine.kVFPdata));
#endif
	DECLARE("TH_CTH_SELF",	offsetof(struct thread, machine.cthread_self));
	DECLARE("TH_CTH_DATA",	offsetof(struct thread, machine.cthread_data));
	DECLARE("ACT_PCBDATA_PC",	offsetof(struct thread, machine.PcbData.pc));
	DECLARE("ACT_PCBDATA_R0",	offsetof(struct thread, machine.PcbData.r[0]));
	DECLARE("ACT_PREEMPT_CNT",	offsetof(struct thread, machine.preemption_count));
	DECLARE("ACT_CPUDATAP",	offsetof(struct thread, machine.CpuDatap));
	DECLARE("ACT_MAP",	offsetof(struct thread, map));
#if __ARM_USER_PROTECT__
	DECLARE("ACT_UPTW_TTC", offsetof(struct thread, machine.uptw_ttc));
	DECLARE("ACT_UPTW_TTB", offsetof(struct thread, machine.uptw_ttb));
	DECLARE("ACT_KPTW_TTB", offsetof(struct thread, machine.kptw_ttb));
	DECLARE("ACT_ASID", offsetof(struct thread, machine.asid));
#endif
	DECLARE("ACT_DEBUGDATA",	offsetof(struct thread, machine.DebugData));
	DECLARE("TH_IOTIER_OVERRIDE",	offsetof(struct thread, iotier_override));
	DECLARE("TH_RWLOCK_CNT",	offsetof(struct thread, rwlock_count));	
	DECLARE("TH_SCHED_FLAGS",	offsetof(struct thread, sched_flags));
	DECLARE("TH_SFLAG_RW_PROMOTED",	TH_SFLAG_RW_PROMOTED);

	DECLARE("TH_MACH_SYSCALLS", offsetof(struct thread, syscalls_mach));
	DECLARE("TH_UNIX_SYSCALLS", offsetof(struct thread, syscalls_unix));
	DECLARE("TASK_BSD_INFO", offsetof(struct task, bsd_info));

	DECLARE("MACH_TRAP_TABLE_COUNT", MACH_TRAP_TABLE_COUNT);
	DECLARE("MACH_TRAP_TABLE_ENTRY_SIZE", sizeof(mach_trap_t));

	DECLARE("MAP_PMAP",	offsetof(struct _vm_map, pmap));

	DECLARE("SS_SIZE", 	sizeof(struct arm_saved_state));
	DECLARE("SS_LR", offsetof(struct arm_saved_state, lr));
	DECLARE("SS_CPSR", offsetof(struct arm_saved_state, cpsr));
	DECLARE("SS_PC", offsetof(struct arm_saved_state, pc));
	DECLARE("SS_R0", offsetof(struct arm_saved_state, r[0]));
	DECLARE("SS_R4", offsetof(struct arm_saved_state, r[4]));
	DECLARE("SS_R9", offsetof(struct arm_saved_state, r[9]));
	DECLARE("SS_R12", offsetof(struct arm_saved_state, r[12]));
	DECLARE("SS_SP", offsetof(struct arm_saved_state, sp));
	DECLARE("SS_STATUS", offsetof(struct arm_saved_state, fsr));
	DECLARE("SS_VADDR", offsetof(struct arm_saved_state, far));
	DECLARE("SS_EXC", offsetof(struct arm_saved_state, exception));

#if __ARM_VFP__
	DECLARE("VSS_SIZE", sizeof(struct arm_vfpsaved_state));
	DECLARE("VSS_FPSCR", offsetof(struct arm_vfpsaved_state, fpscr));
	DECLARE("VSS_FPEXC", offsetof(struct arm_vfpsaved_state, fpexc));

	DECLARE("EXC_CTX_SIZE", sizeof(struct arm_saved_state) +
                            sizeof(struct arm_vfpsaved_state) +
                            VFPSAVE_ALIGN);
	DECLARE("VSS_ALIGN", VFPSAVE_ALIGN);
#else
	DECLARE("EXC_CTX_SIZE", sizeof(struct arm_saved_state));
#endif


	DECLARE("PGBYTES", ARM_PGBYTES);
	DECLARE("PGSHIFT", ARM_PGSHIFT);
	DECLARE("PGMASK", ARM_PGMASK);

	DECLARE("VM_MIN_ADDRESS",	VM_MIN_ADDRESS);
	DECLARE("VM_MAX_ADDRESS",	VM_MAX_ADDRESS);
	DECLARE("KERNELBASE",		VM_MIN_KERNEL_ADDRESS);
	DECLARE("KERNEL_STACK_SIZE",	KERNEL_STACK_SIZE);

	DECLARE("KERN_INVALID_ADDRESS",	KERN_INVALID_ADDRESS);

	DECLARE("MAX_CPUS",	MAX_CPUS);

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
        DECLARE("CPU_FIQSTACKPTR",
		offsetof(cpu_data_t, fiqstackptr));
        DECLARE("CPU_FIQSTACK_TOP",
		offsetof(cpu_data_t, fiqstack_top));
        DECLARE("CPU_NUMBER_GS",
		offsetof(cpu_data_t,cpu_number));
        DECLARE("CPU_IDENT",
		offsetof(cpu_data_t,cpu_ident));
        DECLARE("CPU_RUNNING",
		offsetof(cpu_data_t,cpu_running));
        DECLARE("CPU_MCOUNT_OFF",
		offsetof(cpu_data_t,cpu_mcount_off));
	DECLARE("CPU_PENDING_AST",
		offsetof(cpu_data_t,cpu_pending_ast));
	DECLARE("CPU_PROCESSOR",
		offsetof(cpu_data_t,cpu_processor));
	DECLARE("CPU_CACHE_DISPATCH",
		offsetof(cpu_data_t,cpu_cache_dispatch));
        DECLARE("CPU_BASE_TIMEBASE_LOW",
		offsetof(cpu_data_t,cpu_base_timebase_low));
        DECLARE("CPU_BASE_TIMEBASE_HIGH",
		offsetof(cpu_data_t,cpu_base_timebase_high));
        DECLARE("CPU_TIMEBASE_LOW",
		offsetof(cpu_data_t,cpu_timebase_low));
        DECLARE("CPU_TIMEBASE_HIGH",
		offsetof(cpu_data_t,cpu_timebase_high));
	DECLARE("CPU_DECREMENTER",
		offsetof(cpu_data_t,cpu_decrementer));
	DECLARE("CPU_GET_DECREMENTER_FUNC",
		offsetof(cpu_data_t,cpu_get_decrementer_func));
	DECLARE("CPU_SET_DECREMENTER_FUNC",
		offsetof(cpu_data_t,cpu_set_decrementer_func));
	DECLARE("CPU_GET_FIQ_HANDLER",
		offsetof(cpu_data_t,cpu_get_fiq_handler));
	DECLARE("CPU_TBD_HARDWARE_ADDR",
		offsetof(cpu_data_t,cpu_tbd_hardware_addr));
	DECLARE("CPU_TBD_HARDWARE_VAL",
		offsetof(cpu_data_t,cpu_tbd_hardware_val));
	DECLARE("CPU_INT_STATE",
		offsetof(cpu_data_t,cpu_int_state));
	DECLARE("INTERRUPT_HANDLER",
		offsetof(cpu_data_t,interrupt_handler));
	DECLARE("INTERRUPT_TARGET",
		offsetof(cpu_data_t,interrupt_target));
	DECLARE("INTERRUPT_REFCON",
		offsetof(cpu_data_t,interrupt_refCon));
	DECLARE("INTERRUPT_NUB",
		offsetof(cpu_data_t,interrupt_nub));
	DECLARE("INTERRUPT_SOURCE",
		offsetof(cpu_data_t,interrupt_source));
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
	DECLARE("RTCLOCK_DATAP",
		offsetof(cpu_data_t, rtclock_datap));
#ifdef	__arm__
	DECLARE("CPU_EXC_VECTORS",
		offsetof(cpu_data_t, cpu_exc_vectors));
#endif

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
	DECLARE("RTCLOCK_TB_FUNC",
		offsetof(rtclock_data_t, rtc_timebase_func));
	DECLARE("RTCLOCK_TB_ADDR",
		offsetof(rtclock_data_t, rtc_timebase_addr));
	DECLARE("RTCLOCK_TB_VAL",
		offsetof(rtclock_data_t, rtc_timebase_val));

	DECLARE("SIGPdec",	SIGPdec);

	DECLARE("rhdSize",
		sizeof(struct reset_handler_data));

	DECLARE("CPU_DATA_ENTRIES",	offsetof(struct reset_handler_data, cpu_data_entries));
	DECLARE("BOOT_ARGS",	offsetof(struct reset_handler_data, boot_args));
	DECLARE("ASSIST_RESET_HANDLER",	offsetof(struct reset_handler_data, assist_reset_handler));

	DECLARE("CPU_DATA_PADDR",	offsetof(struct cpu_data_entry, cpu_data_paddr));


	DECLARE("INTSTACK_SIZE",	INTSTACK_SIZE);

	/* values from kern/timer.h */
	DECLARE("TIMER_LOW",
		offsetof(struct timer, low_bits));
	DECLARE("TIMER_HIGH",
		offsetof(struct timer, high_bits));
	DECLARE("TIMER_HIGHCHK",
		offsetof(struct timer, high_bits_check));
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

	DECLARE("ENTROPY_INDEX_PTR",
		offsetof(entropy_data_t, index_ptr));
	DECLARE("ENTROPY_BUFFER",
		offsetof(entropy_data_t, buffer));
	DECLARE("ENTROPY_DATA_SIZE", sizeof(struct entropy_data));

	return (0);
}
