/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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

#include <platforms.h>
#include <mach_kdb.h>
#include <mach_ldebug.h>
#include <stat_time.h>

/*
 * Pass field offsets to assembly code.
 */
#include <kern/ast.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/lock.h>
#include <kern/locks.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <i386/thread.h>
#include <mach/i386/vm_param.h>
#include <i386/seg.h>
#include <i386/pmap.h>
#include <i386/tss.h>
#include <i386/cpu_capabilities.h>
#include <machine/commpage.h>
#include <vm/vm_map.h>
#include <i386/mp_desc.h>
#include <i386/cpuid.h>
#include <pexpert/i386/boot.h>

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

#undef	offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE)0)->MEMBER)

#if  0
#define DECLARE(SYM,VAL) \
	__asm("#DEFINITION#\t.set\t" SYM ",\t%0" : : "n" ((u_int)(VAL)))
#else
#define DECLARE(SYM,VAL) \
	__asm("#DEFINITION##define " SYM "\t%0" : : "n" ((u_int)(VAL)))
#endif

int	main(
		int		argc,
		char		** argv);

int
main(
	int	argc,
	char	**argv)
{

	DECLARE("AST_URGENT",		AST_URGENT);

	/* Simple Lock structure */
	DECLARE("SLOCK_ILK",	offsetof(usimple_lock_t, interlock));
#if	MACH_LDEBUG
	DECLARE("SLOCK_TYPE",	offsetof(usimple_lock_t, lock_type));
	DECLARE("SLOCK_PC",	offsetof(usimple_lock_t, debug.lock_pc));
	DECLARE("SLOCK_THREAD",	offsetof(usimple_lock_t, debug.lock_thread));
	DECLARE("SLOCK_DURATIONH",offsetof(usimple_lock_t, debug.duration[0]));
	DECLARE("SLOCK_DURATIONL",offsetof(usimple_lock_t, debug.duration[1]));
	DECLARE("USLOCK_TAG",	USLOCK_TAG);
#endif	/* MACH_LDEBUG */

	/* Mutex structure */
	DECLARE("MUTEX_LOCKED",	offsetof(mutex_t *, lck_mtx.lck_mtx_locked));
	DECLARE("MUTEX_WAITERS",offsetof(mutex_t *, lck_mtx.lck_mtx_waiters));
	DECLARE("MUTEX_PROMOTED_PRI",offsetof(mutex_t *, lck_mtx.lck_mtx_pri));
#if	MACH_LDEBUG
	DECLARE("MUTEX_TYPE",	offsetof(mutex_t *, type));
	DECLARE("MUTEX_PC",	offsetof(mutex_t *, pc));
	DECLARE("MUTEX_THREAD",	offsetof(mutex_t *, thread));
	DECLARE("MUTEX_TAG",	MUTEX_TAG);
#endif	/* MACH_LDEBUG */
	DECLARE("MUTEX_IND",	LCK_MTX_TAG_INDIRECT);
	DECLARE("MUTEX_ITAG",	offsetof(lck_mtx_t *, lck_mtx_tag));
	DECLARE("MUTEX_PTR",	offsetof(lck_mtx_t *, lck_mtx_ptr));

	DECLARE("TH_RECOVER",		offsetof(thread_t, recover));
	DECLARE("TH_CONTINUATION",	offsetof(thread_t, continuation));
	DECLARE("TH_KERNEL_STACK",	offsetof(thread_t, kernel_stack));

	DECLARE("TASK_MACH_EXC_PORT",
		offsetof(task_t, exc_actions[EXC_MACH_SYSCALL].port));

	/* These fields are being added on demand */
	DECLARE("ACT_MACH_EXC_PORT",
		offsetof(thread_t, exc_actions[EXC_MACH_SYSCALL].port));

	DECLARE("ACT_TASK",	offsetof(thread_t, task));
	DECLARE("ACT_PCB",	offsetof(thread_t, machine.pcb));
	DECLARE("ACT_MAP",	offsetof(thread_t, map));

	DECLARE("MAP_PMAP",	offsetof(vm_map_t, pmap));

#define IKS ((size_t) (STACK_IKS(0)))

	DECLARE("KSS_EBX", IKS + offsetof(struct i386_kernel_state *, k_ebx));
	DECLARE("KSS_ESP", IKS + offsetof(struct i386_kernel_state *, k_esp));
	DECLARE("KSS_EBP", IKS + offsetof(struct i386_kernel_state *, k_ebp));
	DECLARE("KSS_EDI", IKS + offsetof(struct i386_kernel_state *, k_edi));
	DECLARE("KSS_ESI", IKS + offsetof(struct i386_kernel_state *, k_esi));
	DECLARE("KSS_EIP", IKS + offsetof(struct i386_kernel_state *, k_eip));

	DECLARE("IKS_SIZE",	sizeof(struct i386_kernel_state));
	DECLARE("IEL_SIZE",	sizeof(struct i386_exception_link));

	DECLARE("PCB_FPS",	offsetof(pcb_t, ims.ifps));
	DECLARE("PCB_ISS",	offsetof(pcb_t, iss));

	DECLARE("FP_VALID",	offsetof(struct i386_fpsave_state *,fp_valid));
	DECLARE("FP_SAVE_STATE",
		offsetof(struct i386_fpsave_state *, fp_save_state));

	DECLARE("R_CS",		offsetof(struct i386_saved_state *, cs));
	DECLARE("R_SS",		offsetof(struct i386_saved_state *, ss));
	DECLARE("R_UESP",	offsetof(struct i386_saved_state *, uesp));
	DECLARE("R_EBP",	offsetof(struct i386_saved_state *, ebp));
	DECLARE("R_EAX",	offsetof(struct i386_saved_state *, eax));
	DECLARE("R_EBX",	offsetof(struct i386_saved_state *, ebx));
	DECLARE("R_ECX",	offsetof(struct i386_saved_state *, ecx));
	DECLARE("R_EDX",	offsetof(struct i386_saved_state *, edx));
	DECLARE("R_ESI",	offsetof(struct i386_saved_state *, esi));
	DECLARE("R_EDI",	offsetof(struct i386_saved_state *, edi));
	DECLARE("R_TRAPNO",	offsetof(struct i386_saved_state *, trapno));
	DECLARE("R_ERR",	offsetof(struct i386_saved_state *, err));
	DECLARE("R_EFLAGS",	offsetof(struct i386_saved_state *, efl));
	DECLARE("R_EIP",	offsetof(struct i386_saved_state *, eip));
	DECLARE("R_CR2",	offsetof(struct i386_saved_state *, cr2));
	DECLARE("ISS_SIZE",	sizeof (struct i386_saved_state));

        DECLARE("I_ECX",	offsetof(struct i386_interrupt_state *, ecx));
	DECLARE("I_EIP",	offsetof(struct i386_interrupt_state *, eip));
	DECLARE("I_CS",		offsetof(struct i386_interrupt_state *, cs));
	DECLARE("I_EFL",	offsetof(struct i386_interrupt_state *, efl));

	DECLARE("NBPG",			I386_PGBYTES);
	DECLARE("PAGE_SIZE",            I386_PGBYTES);
	DECLARE("PAGE_MASK",            I386_PGBYTES-1);
	DECLARE("PAGE_SHIFT",           12);
	DECLARE("NKPT",                 NKPT);
	DECLARE("KPTDI",                KPTDI);
	DECLARE("VM_MIN_ADDRESS",	VM_MIN_ADDRESS);
	DECLARE("VM_MAX_ADDRESS",	VM_MAX_ADDRESS);
	DECLARE("KERNELBASE",		VM_MIN_KERNEL_ADDRESS);
	DECLARE("LINEAR_KERNELBASE",	LINEAR_KERNEL_ADDRESS);
	DECLARE("KERNEL_STACK_SIZE",	KERNEL_STACK_SIZE);

	DECLARE("COMM_PAGE_BASE_ADDR",  _COMM_PAGE_BASE_ADDRESS);

	DECLARE("PDESHIFT",	PDESHIFT);
	DECLARE("PTEMASK",	PTEMASK);
	DECLARE("PTEINDX",      PTEINDX);
	DECLARE("PTE_PFN",	INTEL_PTE_PFN);
	DECLARE("PTE_V",	INTEL_PTE_VALID);
	DECLARE("PTE_W",	INTEL_PTE_WRITE);
        DECLARE("PTE_PS",       INTEL_PTE_PS);
	DECLARE("PTE_U",        INTEL_PTE_USER);
	DECLARE("PTE_INVALID",	~INTEL_PTE_VALID);
	DECLARE("CR4_PAE",      CR4_PAE);
	DECLARE("NPGPTD", NPGPTD);

	DECLARE("IDTSZ",	IDTSZ);
	DECLARE("GDTSZ",	GDTSZ);
	DECLARE("LDTSZ",	LDTSZ);

	DECLARE("KERNEL_CS",	KERNEL_CS);
	DECLARE("KERNEL_DS",	KERNEL_DS);
	DECLARE("USER_CS",	USER_CS);
	DECLARE("USER_DS",	USER_DS);
	DECLARE("KERNEL_TSS",	KERNEL_TSS);
	DECLARE("KERNEL_LDT",	KERNEL_LDT);
#if	MACH_KDB
	DECLARE("DEBUG_TSS",	DEBUG_TSS);
#endif	/* MACH_KDB */
        DECLARE("CPU_DATA_GS",	CPU_DATA_GS);

        DECLARE("CPU_THIS",
		offsetof(cpu_data_t *, cpu_this));
        DECLARE("CPU_ACTIVE_THREAD",
		offsetof(cpu_data_t *, cpu_active_thread));
        DECLARE("CPU_ACTIVE_KLOADED",
		offsetof(cpu_data_t *, cpu_active_kloaded));
        DECLARE("CPU_ACTIVE_STACK",
		offsetof(cpu_data_t *, cpu_active_stack));
        DECLARE("CPU_KERNEL_STACK",
		offsetof(cpu_data_t *, cpu_kernel_stack));
        DECLARE("CPU_INT_STACK_TOP",
		offsetof(cpu_data_t *, cpu_int_stack_top));
#if	MACH_RT
        DECLARE("CPU_PREEMPTION_LEVEL",
		offsetof(cpu_data_t *, cpu_preemption_level));
#endif	/* MACH_RT */
        DECLARE("CPU_INTERRUPT_LEVEL",
		offsetof(cpu_data_t *, cpu_interrupt_level));
        DECLARE("CPU_SIMPLE_LOCK_COUNT",
		offsetof(cpu_data_t *,cpu_simple_lock_count));
        DECLARE("CPU_NUMBER_GS",
		offsetof(cpu_data_t *,cpu_number));
        DECLARE("CPU_RUNNING",
		offsetof(cpu_data_t *,cpu_running));
        DECLARE("CPU_MCOUNT_OFF",
		offsetof(cpu_data_t *,cpu_mcount_off));
	DECLARE("CPU_PENDING_AST",
		offsetof(cpu_data_t *,cpu_pending_ast));
	DECLARE("CPU_DESC_TABLEP",
		offsetof(cpu_data_t *,cpu_desc_tablep));
	DECLARE("CPU_PROCESSOR",
		offsetof(cpu_data_t *,cpu_processor));
	DECLARE("CPU_RTC_NANOTIME",
		offsetof(cpu_data_t *,cpu_rtc_nanotime));

	DECLARE("INTEL_PTE_KERNEL",	INTEL_PTE_VALID|INTEL_PTE_WRITE);
	DECLARE("PTDPTDI",     PTDPTDI);
	DECLARE("PDESHIFT",     PDESHIFT);
	DECLARE("PDESIZE",     PDESIZE);
	DECLARE("PTESIZE",     PTESIZE);
	DECLARE("APTDPTDI",     APTDPTDI);

	DECLARE("KERNELBASEPDE",
		(LINEAR_KERNEL_ADDRESS >> PDESHIFT) *
		sizeof(pt_entry_t));

	DECLARE("TSS_ESP0",	offsetof(struct i386_tss *, esp0));
	DECLARE("TSS_SS0",	offsetof(struct i386_tss *, ss0));
	DECLARE("TSS_LDT",	offsetof(struct i386_tss *, ldt));
	DECLARE("TSS_PDBR",	offsetof(struct i386_tss *, cr3));
	DECLARE("TSS_LINK",	offsetof(struct i386_tss *, back_link));

	DECLARE("K_TASK_GATE",	ACC_P|ACC_PL_K|ACC_TASK_GATE);
	DECLARE("K_TRAP_GATE",	ACC_P|ACC_PL_K|ACC_TRAP_GATE);
	DECLARE("U_TRAP_GATE",	ACC_P|ACC_PL_U|ACC_TRAP_GATE);
	DECLARE("K_INTR_GATE",	ACC_P|ACC_PL_K|ACC_INTR_GATE);
	DECLARE("K_TSS",	ACC_P|ACC_PL_K|ACC_TSS);

	/*
	 *	usimple_lock fields
	 */
	DECLARE("USL_INTERLOCK",	offsetof(usimple_lock_t, interlock));

	DECLARE("INTSTACK_SIZE",	INTSTACK_SIZE);
	DECLARE("MP_GDT",	   offsetof(struct mp_desc_table *, gdt[0]));
	DECLARE("MP_IDT",	   offsetof(struct mp_desc_table *, idt[0]));
	DECLARE("TIMER_LOW",	 	offsetof(struct timer *, low_bits));
	DECLARE("TIMER_HIGH",		offsetof(struct timer *, high_bits));
	DECLARE("TIMER_HIGHCHK",	offsetof(struct timer *, high_bits_check));
	DECLARE("KADDR", offsetof(struct KernelBootArgs *, kaddr));
	DECLARE("KSIZE", offsetof(struct KernelBootArgs *, ksize));

	DECLARE("NANOTIME_BASE_TSC",
		offsetof(commpage_nanotime_t*, nt_base_tsc));
	DECLARE("NANOTIME_BASE_NS",
		offsetof(commpage_nanotime_t*, nt_base_ns));
	DECLARE("NANOTIME_SCALE",
		offsetof(commpage_nanotime_t*, nt_scale));
	DECLARE("NANOTIME_SHIFT",
		offsetof(commpage_nanotime_t*, nt_shift));
	DECLARE("NANOTIME_CHECK_TSC",
		offsetof(commpage_nanotime_t*, nt_check_tsc));

	DECLARE("RTN_TSC",
		offsetof(rtc_nanotime_t *, rnt_tsc));
	DECLARE("RTN_NANOS",
		offsetof(rtc_nanotime_t *, rnt_nanos));
	DECLARE("RTN_SCALE",
		offsetof(rtc_nanotime_t *, rnt_scale));
	DECLARE("RTN_SHIFT",
		offsetof(rtc_nanotime_t *, rnt_shift));

	/* values from kern/timer.h */
	DECLARE("TIMER_LOW",
		offsetof(struct timer *, low_bits));
	DECLARE("TIMER_HIGH",
		offsetof(struct timer *, high_bits));
	DECLARE("TIMER_HIGHCHK",
		offsetof(struct timer *, high_bits_check));
#if !STAT_TIME
	DECLARE("TIMER_TSTAMP",
		offsetof(struct timer *, tstamp));

	DECLARE("CURRENT_TIMER",
		offsetof(struct processor *, processor_data.current_timer));
#endif
	DECLARE("SYSTEM_TIMER",
		offsetof(struct thread *, system_timer));
	DECLARE("USER_TIMER",
		offsetof(struct thread *, user_timer));

	return (0);
}

