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
#if HIBERNATION
#include <IOKit/IOHibernatePrivate.h>
#include <machine/pal_hibernate.h>
#endif /* HIBERNATION */

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
	__asm("DEFINITION__define__" SYM ":\t .ascii \"%0\"" : : "i"  ((u_long)(VAL)))


int main(int     argc,
    char ** argv);

int
main(int     argc,
    char ** argv)
{
	DECLARE("AST_URGENT", AST_URGENT);

	DECLARE("TH_RECOVER", offsetof(struct thread, recover));
	DECLARE("TH_KSTACKPTR", offsetof(struct thread, machine.kstackptr));
	DECLARE("TH_THREAD_ID", offsetof(struct thread, thread_id));
#if defined(HAS_APPLE_PAC)
	DECLARE("TH_ROP_PID", offsetof(struct thread, machine.rop_pid));
	DECLARE("TH_JOP_PID", offsetof(struct thread, machine.jop_pid));
	DECLARE("TH_DISABLE_USER_JOP", offsetof(struct thread, machine.disable_user_jop));
#endif /* defined(HAS_APPLE_PAC) */

	/* These fields are being added on demand */
	DECLARE("ACT_CONTEXT", offsetof(struct thread, machine.contextData));
	DECLARE("TH_CTH_SELF", offsetof(struct thread, machine.cthread_self));
	DECLARE("ACT_PREEMPT_CNT", offsetof(struct thread, machine.preemption_count));
	DECLARE("ACT_CPUDATAP", offsetof(struct thread, machine.CpuDatap));
	DECLARE("ACT_DEBUGDATA", offsetof(struct thread, machine.DebugData));
	DECLARE("TH_IOTIER_OVERRIDE", offsetof(struct thread, iotier_override));
	DECLARE("TH_RWLOCK_CNT", offsetof(struct thread, rwlock_count));
	DECLARE("TH_TMP_ALLOC_CNT", offsetof(struct thread, t_temp_alloc_count));
	DECLARE("TH_TASK", offsetof(struct thread, task));

#if defined(HAS_APPLE_PAC)
	DECLARE("TASK_ROP_PID", offsetof(struct task, rop_pid));
	DECLARE("TASK_JOP_PID", offsetof(struct task, jop_pid));
#endif /* defined(HAS_APPLE_PAC) */


	DECLARE("ARM_CONTEXT_SIZE", sizeof(arm_context_t));

	DECLARE("SS_FLAVOR", offsetof(arm_context_t, ss.ash.flavor));
	DECLARE("ARM_SAVED_STATE64", ARM_SAVED_STATE64);
	DECLARE("ARM_SAVED_STATE64_COUNT", ARM_SAVED_STATE64_COUNT);

	DECLARE("SS64_X0", offsetof(arm_context_t, ss.ss_64.x[0]));
	DECLARE("SS64_X2", offsetof(arm_context_t, ss.ss_64.x[2]));
	DECLARE("SS64_X4", offsetof(arm_context_t, ss.ss_64.x[4]));
	DECLARE("SS64_X6", offsetof(arm_context_t, ss.ss_64.x[6]));
	DECLARE("SS64_X8", offsetof(arm_context_t, ss.ss_64.x[8]));
	DECLARE("SS64_X10", offsetof(arm_context_t, ss.ss_64.x[10]));
	DECLARE("SS64_X12", offsetof(arm_context_t, ss.ss_64.x[12]));
	DECLARE("SS64_X14", offsetof(arm_context_t, ss.ss_64.x[14]));
	DECLARE("SS64_X15", offsetof(arm_context_t, ss.ss_64.x[15]));
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
#if defined(HAS_APPLE_PAC)
	DECLARE("SS64_JOPHASH", offsetof(arm_context_t, ss.ss_64.jophash));
#endif /* defined(HAS_APPLE_PAC) */

	DECLARE("NS_FLAVOR", offsetof(arm_context_t, ns.nsh.flavor));
	DECLARE("NS_COUNT", offsetof(arm_context_t, ns.nsh.count));
	DECLARE("ARM_NEON_SAVED_STATE64", ARM_NEON_SAVED_STATE64);
	DECLARE("ARM_NEON_SAVED_STATE64_COUNT", ARM_NEON_SAVED_STATE64_COUNT);

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

	DECLARE("ARM_KERNEL_CONTEXT_SIZE", sizeof(arm_kernel_context_t));

	DECLARE("SS64_KERNEL_X16", offsetof(arm_kernel_context_t, ss.x[0]));
	DECLARE("SS64_KERNEL_X17", offsetof(arm_kernel_context_t, ss.x[1]));
	DECLARE("SS64_KERNEL_X19", offsetof(arm_kernel_context_t, ss.x[2]));
	DECLARE("SS64_KERNEL_X20", offsetof(arm_kernel_context_t, ss.x[3]));
	DECLARE("SS64_KERNEL_X21", offsetof(arm_kernel_context_t, ss.x[4]));
	DECLARE("SS64_KERNEL_X22", offsetof(arm_kernel_context_t, ss.x[5]));
	DECLARE("SS64_KERNEL_X23", offsetof(arm_kernel_context_t, ss.x[6]));
	DECLARE("SS64_KERNEL_X24", offsetof(arm_kernel_context_t, ss.x[7]));
	DECLARE("SS64_KERNEL_X25", offsetof(arm_kernel_context_t, ss.x[8]));
	DECLARE("SS64_KERNEL_X26", offsetof(arm_kernel_context_t, ss.x[9]));
	DECLARE("SS64_KERNEL_X27", offsetof(arm_kernel_context_t, ss.x[10]));
	DECLARE("SS64_KERNEL_X28", offsetof(arm_kernel_context_t, ss.x[11]));
	DECLARE("SS64_KERNEL_FP", offsetof(arm_kernel_context_t, ss.fp));
	DECLARE("SS64_KERNEL_LR", offsetof(arm_kernel_context_t, ss.lr));
	DECLARE("SS64_KERNEL_SP", offsetof(arm_kernel_context_t, ss.sp));
	DECLARE("SS64_KERNEL_PC", offsetof(arm_kernel_context_t, ss.pc));
	DECLARE("SS64_KERNEL_CPSR", offsetof(arm_kernel_context_t, ss.cpsr));
#if defined(HAS_APPLE_PAC)
	DECLARE("SS64_KERNEL_JOPHASH", offsetof(arm_kernel_context_t, ss.jophash));
#endif /* defined(HAS_APPLE_PAC) */

	DECLARE("NS64_KERNEL_D8", offsetof(arm_kernel_context_t, ns.d[0]));
	DECLARE("NS64_KERNEL_D9", offsetof(arm_kernel_context_t, ns.d[1]));
	DECLARE("NS64_KERNEL_D10", offsetof(arm_kernel_context_t, ns.d[2]));
	DECLARE("NS64_KERNEL_D11", offsetof(arm_kernel_context_t, ns.d[3]));
	DECLARE("NS64_KERNEL_D12", offsetof(arm_kernel_context_t, ns.d[4]));
	DECLARE("NS64_KERNEL_D13", offsetof(arm_kernel_context_t, ns.d[5]));
	DECLARE("NS64_KERNEL_D14", offsetof(arm_kernel_context_t, ns.d[6]));
	DECLARE("NS64_KERNEL_D15", offsetof(arm_kernel_context_t, ns.d[7]));

	DECLARE("NS64_KERNEL_FPCR", offsetof(arm_kernel_context_t, ns.fpcr));



	DECLARE("PGBYTES", ARM_PGBYTES);
	DECLARE("PGSHIFT", ARM_PGSHIFT);

	DECLARE("VM_MIN_KERNEL_ADDRESS", VM_MIN_KERNEL_ADDRESS);
	DECLARE("KERNEL_STACK_SIZE", KERNEL_STACK_SIZE);
	DECLARE("TBI_MASK", TBI_MASK);

	DECLARE("cdeSize", sizeof(struct cpu_data_entry));

	DECLARE("cdSize", sizeof(struct cpu_data));

	DECLARE("CPU_ACTIVE_THREAD", offsetof(cpu_data_t, cpu_active_thread));
	DECLARE("CPU_ISTACKPTR", offsetof(cpu_data_t, istackptr));
	DECLARE("CPU_INTSTACK_TOP", offsetof(cpu_data_t, intstack_top));
	DECLARE("CPU_EXCEPSTACK_TOP", offsetof(cpu_data_t, excepstack_top));
#if __ARM_KERNEL_PROTECT__
	DECLARE("CPU_EXC_VECTORS", offsetof(cpu_data_t, cpu_exc_vectors));
#endif /* __ARM_KERNEL_PROTECT__ */
	DECLARE("CPU_NUMBER_GS", offsetof(cpu_data_t, cpu_number));
	DECLARE("CPU_PENDING_AST", offsetof(cpu_data_t, cpu_pending_ast));
	DECLARE("CPU_INT_STATE", offsetof(cpu_data_t, cpu_int_state));
	DECLARE("CPU_USER_DEBUG", offsetof(cpu_data_t, cpu_user_debug));
	DECLARE("CPU_STAT_IRQ", offsetof(cpu_data_t, cpu_stat.irq_ex_cnt));
	DECLARE("CPU_STAT_IRQ_WAKE", offsetof(cpu_data_t, cpu_stat.irq_ex_cnt_wake));
	DECLARE("CPU_RESET_HANDLER", offsetof(cpu_data_t, cpu_reset_handler));
	DECLARE("CPU_PHYS_ID", offsetof(cpu_data_t, cpu_phys_id));

	DECLARE("RTCLOCKDataSize", sizeof(rtclock_data_t));

	DECLARE("rhdSize", sizeof(struct reset_handler_data));
#if WITH_CLASSIC_S2R || !__arm64__
	DECLARE("stSize", sizeof(SleepToken));
#endif /* WITH_CLASSIC_S2R || !__arm64__ */

	DECLARE("CPU_DATA_ENTRIES", offsetof(struct reset_handler_data, cpu_data_entries));

	DECLARE("CPU_DATA_PADDR", offsetof(struct cpu_data_entry, cpu_data_paddr));

	DECLARE("INTSTACK_SIZE", INTSTACK_SIZE);
	DECLARE("EXCEPSTACK_SIZE", EXCEPSTACK_SIZE);

	DECLARE("PAGE_MAX_SHIFT", PAGE_MAX_SHIFT);
	DECLARE("PAGE_MAX_SIZE", PAGE_MAX_SIZE);

	DECLARE("BA_VIRT_BASE", offsetof(struct boot_args, virtBase));
	DECLARE("BA_PHYS_BASE", offsetof(struct boot_args, physBase));
	DECLARE("BA_MEM_SIZE", offsetof(struct boot_args, memSize));
	DECLARE("BA_TOP_OF_KERNEL_DATA", offsetof(struct boot_args, topOfKernelData));
	DECLARE("BA_BOOT_FLAGS", offsetof(struct boot_args, bootFlags));

	DECLARE("SR_RESTORE_TCR_EL1", offsetof(struct sysreg_restore, tcr_el1));

#if XNU_MONITOR
	DECLARE("PMAP_CPU_DATA_PPL_STATE", offsetof(struct pmap_cpu_data, ppl_state));
	DECLARE("PMAP_CPU_DATA_ARRAY_ENTRY_SIZE", sizeof(struct pmap_cpu_data_array_entry));
	DECLARE("PMAP_CPU_DATA_PPL_STACK", offsetof(struct pmap_cpu_data, ppl_stack));
	DECLARE("PMAP_CPU_DATA_KERN_SAVED_SP", offsetof(struct pmap_cpu_data, ppl_kern_saved_sp));
	DECLARE("PMAP_CPU_DATA_SAVE_AREA", offsetof(struct pmap_cpu_data, save_area));
	DECLARE("PMAP_COUNT", PMAP_COUNT);
#endif /* XNU_MONITOR */


#if defined(HAS_APPLE_PAC)
	DECLARE("CPU_ROP_KEY", offsetof(cpu_data_t, rop_key));
	DECLARE("CPU_JOP_KEY", offsetof(cpu_data_t, jop_key));
#if __has_feature(ptrauth_function_pointer_type_discrimination)
	DECLARE("THREAD_CONTINUE_T_DISC", __builtin_ptrauth_type_discriminator(thread_continue_t));
#else
	DECLARE("THREAD_CONTINUE_T_DISC", 0);
#endif /* __has_feature(ptrauth_function_pointer_type_discrimination) */
#endif /* defined(HAS_APPLE_PAC) */


#if __ARM_ARCH_8_5__
	DECLARE("CPU_SYNC_ON_CSWITCH", offsetof(cpu_data_t, sync_on_cswitch));
#endif /* __ARM_ARCH_8_5__ */

#if HIBERNATION
	DECLARE("HIBHDR_STACKOFFSET", offsetof(IOHibernateImageHeader, restore1StackOffset));
	DECLARE("HIBTRAMP_TTBR0", offsetof(pal_hib_tramp_result_t, ttbr0));
	DECLARE("HIBTRAMP_TTBR1", offsetof(pal_hib_tramp_result_t, ttbr1));
	DECLARE("HIBTRAMP_MEMSLIDE", offsetof(pal_hib_tramp_result_t, memSlide));
	DECLARE("HIBGLOBALS_KERNELSLIDE", offsetof(pal_hib_globals_t, kernelSlide));
#endif /* HIBERNATION */

	return 0;
}
