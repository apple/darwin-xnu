/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#include <cpus.h>
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
#include <kern/thread_act.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <kern/syscall_emulation.h>
#include <i386/thread.h>
#include <mach/i386/vm_param.h>
#include <i386/seg.h>
#include <i386/pmap.h>
#include <i386/tss.h>
#include <vm/vm_map.h>
#if	NCPUS > 1
#include <i386/mp_desc.h>
#endif

extern void   kernel_preempt_check(void);
cpu_data_t    cpu_data[NCPUS];

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
	DECLARE("MUTEX_LOCKED",	offsetof(mutex_t *, locked));
	DECLARE("MUTEX_WAITERS",offsetof(mutex_t *, waiters));
	DECLARE("MUTEX_PROMOTED_PRI",offsetof(mutex_t *, promoted_pri));
#if	MACH_LDEBUG
	DECLARE("MUTEX_TYPE",	offsetof(mutex_t *, type));
	DECLARE("MUTEX_PC",	offsetof(mutex_t *, pc));
	DECLARE("MUTEX_THREAD",	offsetof(mutex_t *, thread));
	DECLARE("MUTEX_TAG",	MUTEX_TAG);
#endif	/* MACH_LDEBUG */
						 
#if	MACH_LDEBUG
	DECLARE("TH_MUTEX_COUNT",	offsetof(thread_t, mutex_count));
#endif	/* MACH_LDEBUG */
	DECLARE("TH_RECOVER",		offsetof(thread_t, recover));
	DECLARE("TH_CONTINUATION",	offsetof(thread_t, continuation));
	DECLARE("TH_TOP_ACT",		offsetof(thread_t, top_act));
	DECLARE("TH_KERNEL_STACK",	offsetof(thread_t, kernel_stack));

	DECLARE("TASK_EMUL", 		offsetof(task_t, eml_dispatch));
	DECLARE("TASK_MACH_EXC_PORT",
		offsetof(task_t, exc_actions[EXC_MACH_SYSCALL].port));

	/* These fields are being added on demand */
	DECLARE("ACT_MACH_EXC_PORT",
		offsetof(thread_act_t, exc_actions[EXC_MACH_SYSCALL].port));

        DECLARE("ACT_THREAD",	offsetof(thread_act_t, thread));
	DECLARE("ACT_TASK",	offsetof(thread_act_t, task));
	DECLARE("ACT_PCB",	offsetof(thread_act_t, mact.pcb));
	DECLARE("ACT_LOWER",	offsetof(thread_act_t, lower));
	DECLARE("ACT_MAP",	offsetof(thread_act_t, map));

	DECLARE("MAP_PMAP",	offsetof(vm_map_t, pmap));

	DECLARE("DISP_MIN",	offsetof(eml_dispatch_t, disp_min));
	DECLARE("DISP_COUNT",	offsetof(eml_dispatch_t, disp_count));
	DECLARE("DISP_VECTOR",	offsetof(eml_dispatch_t, disp_vector[0]));

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
	DECLARE("VM_MIN_ADDRESS",	VM_MIN_ADDRESS);
	DECLARE("VM_MAX_ADDRESS",	VM_MAX_ADDRESS);
	DECLARE("KERNELBASE",		VM_MIN_KERNEL_ADDRESS);
	DECLARE("LINEAR_KERNELBASE",	LINEAR_KERNEL_ADDRESS);
	DECLARE("KERNEL_STACK_SIZE",	KERNEL_STACK_SIZE);

	DECLARE("PDESHIFT",	PDESHIFT);
	DECLARE("PTESHIFT",	PTESHIFT);
	DECLARE("PTEMASK",	PTEMASK);

	DECLARE("PTE_PFN",	INTEL_PTE_PFN);
	DECLARE("PTE_V",	INTEL_PTE_VALID);
	DECLARE("PTE_W",	INTEL_PTE_WRITE);
	DECLARE("PTE_INVALID",	~INTEL_PTE_VALID);

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

        DECLARE("CPU_DATA",	CPU_DATA);
        DECLARE("CPD_ACTIVE_THREAD",
		offsetof(cpu_data_t *, active_thread));
#if	MACH_RT
        DECLARE("CPD_PREEMPTION_LEVEL",
		offsetof(cpu_data_t *, preemption_level));
#endif	/* MACH_RT */
        DECLARE("CPD_INTERRUPT_LEVEL",
		offsetof(cpu_data_t *, interrupt_level));
        DECLARE("CPD_SIMPLE_LOCK_COUNT",
		offsetof(cpu_data_t *,simple_lock_count));
        DECLARE("CPD_CPU_NUMBER",
		offsetof(cpu_data_t *,cpu_number));
        DECLARE("CPD_CPU_PHYS_NUMBER",
		offsetof(cpu_data_t *,cpu_phys_number));
        DECLARE("CPD_CPU_STATUS",
		offsetof(cpu_data_t *,cpu_status));
        DECLARE("CPD_MCOUNT_OFF",
		offsetof(cpu_data_t *,mcount_off));

	DECLARE("PTES_PER_PAGE",	NPTES);
	DECLARE("INTEL_PTE_KERNEL",	INTEL_PTE_VALID|INTEL_PTE_WRITE);

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
#if	NCPUS > 1
	DECLARE("MP_GDT",	   offsetof(struct mp_desc_table *, gdt[0]));
	DECLARE("MP_IDT",	   offsetof(struct mp_desc_table *, idt[0]));
#endif	/* NCPUS > 1 */
#if	!STAT_TIME
	DECLARE("LOW_BITS",	   offsetof(struct timer *, low_bits));
	DECLARE("HIGH_BITS",	   offsetof(struct timer *, high_bits));
	DECLARE("HIGH_BITS_CHECK", offsetof(struct timer *, high_bits_check));
	DECLARE("TIMER_HIGH_UNIT", TIMER_HIGH_UNIT);
	DECLARE("TH_SYS_TIMER",    offsetof(struct timer *, system_timer));
	DECLARE("TH_USER_TIMER",   offsetof(struct timer *, user_timer));
#endif

	return (0);
}


/* Dummy to keep linker quiet */
void
kernel_preempt_check(void)
{
}
