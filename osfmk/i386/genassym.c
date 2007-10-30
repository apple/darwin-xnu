/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <vm/vm_map.h>
#include <i386/cpu_data.h>
#include <i386/thread.h>
#include <i386/seg.h>
#include <i386/pmap.h>
#include <i386/tss.h>
#include <i386/cpu_capabilities.h>
#include <i386/cpuid.h>
#include <i386/Diagnostics.h>
#include <i386/pmCPU.h>
#include <i386/hpet.h>
#include <mach/i386/vm_param.h>
#include <mach/i386/thread_status.h>
#include <machine/commpage.h>
#include <i386/mp_desc.h>
#include <pexpert/i386/boot.h>

#if	CONFIG_DTRACE
#define NEED_DTRACE_DEFS
#include <../bsd/sys/lockstat.h>
#endif

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
	DECLARE("AST_BSD",			AST_BSD);

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
	DECLARE("MUTEX_DESTROYED", LCK_MTX_TAG_DESTROYED);
	DECLARE("MUTEX_LOCKED_AS_SPIN",	MUTEX_LOCKED_AS_SPIN);
	DECLARE("MUTEX_ITAG",	offsetof(lck_mtx_t *, lck_mtx_tag));
	DECLARE("MUTEX_PTR",	offsetof(lck_mtx_t *, lck_mtx_ptr));
	DECLARE("MUTEX_ASSERT_OWNED",	LCK_MTX_ASSERT_OWNED);
	DECLARE("MUTEX_ASSERT_NOTOWNED",LCK_MTX_ASSERT_NOTOWNED);
	/* Per-mutex statistic element */
	DECLARE("MTX_ACQ_TSC",	offsetof(lck_mtx_ext_t *, lck_mtx_stat));

	/* Mutex group statistics elements */
	DECLARE("MUTEX_GRP",	offsetof(lck_mtx_ext_t *, lck_mtx_grp));
	
	DECLARE("GRP_MTX_STAT_UTIL",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_util_cnt));
	DECLARE("GRP_MTX_STAT_MISS",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_miss_cnt));
	DECLARE("GRP_MTX_STAT_WAIT",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cnt));
	/*
	 * The use of this field is somewhat at variance with the alias.
	 */
	DECLARE("GRP_MTX_STAT_DIRECT_WAIT",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_cnt));

	DECLARE("GRP_MTX_STAT_HELD_MAX",	offsetof(lck_grp_t *, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_max));
	/* Reader writer lock types */
	DECLARE("RW_SHARED",    LCK_RW_TYPE_SHARED);
	DECLARE("RW_EXCL",      LCK_RW_TYPE_EXCLUSIVE);

	DECLARE("TH_RECOVER",		offsetof(thread_t, recover));
	DECLARE("TH_CONTINUATION",	offsetof(thread_t, continuation));
	DECLARE("TH_KERNEL_STACK",	offsetof(thread_t, kernel_stack));

	DECLARE("TASK_MACH_EXC_PORT",
		offsetof(task_t, exc_actions[EXC_MACH_SYSCALL].port));
	DECLARE("TASK_SYSCALLS_MACH",	offsetof(struct task *, syscalls_mach));
	DECLARE("TASK_SYSCALLS_UNIX",	offsetof(struct task *, syscalls_unix));

	DECLARE("TASK_VTIMERS",			offsetof(struct task *, vtimers));

	/* These fields are being added on demand */
	DECLARE("ACT_MACH_EXC_PORT",
		offsetof(thread_t, exc_actions[EXC_MACH_SYSCALL].port));

	DECLARE("ACT_TASK",	offsetof(thread_t, task));
	DECLARE("ACT_AST",	offsetof(thread_t, ast));
	DECLARE("ACT_PCB",	offsetof(thread_t, machine.pcb));
	DECLARE("ACT_SPF",	offsetof(thread_t, machine.specFlags));
	DECLARE("ACT_MAP",	offsetof(thread_t, map));
	DECLARE("ACT_COPYIO_STATE", offsetof(thread_t, machine.copyio_state));
	DECLARE("ACT_PCB_ISS", 	offsetof(thread_t, machine.xxx_pcb.iss));
	DECLARE("ACT_PCB_IDS", 	offsetof(thread_t, machine.xxx_pcb.ids));

	DECLARE("WINDOWS_CLEAN", WINDOWS_CLEAN);

	DECLARE("MAP_PMAP",	offsetof(vm_map_t, pmap));

#define IKS ((size_t) (STACK_IKS(0)))

	DECLARE("KSS_EBX", IKS + offsetof(struct x86_kernel_state32 *, k_ebx));
	DECLARE("KSS_ESP", IKS + offsetof(struct x86_kernel_state32 *, k_esp));
	DECLARE("KSS_EBP", IKS + offsetof(struct x86_kernel_state32 *, k_ebp));
	DECLARE("KSS_EDI", IKS + offsetof(struct x86_kernel_state32 *, k_edi));
	DECLARE("KSS_ESI", IKS + offsetof(struct x86_kernel_state32 *, k_esi));
	DECLARE("KSS_EIP", IKS + offsetof(struct x86_kernel_state32 *, k_eip));

	DECLARE("IKS_SIZE",	sizeof(struct x86_kernel_state32));
	DECLARE("IEL_SIZE",	sizeof(struct i386_exception_link));

	DECLARE("PCB_FPS",	offsetof(pcb_t, ifps));
	DECLARE("PCB_ISS",	offsetof(pcb_t, iss));

	DECLARE("DS_DR0",	offsetof(struct x86_debug_state32 *, dr0));
	DECLARE("DS_DR1",	offsetof(struct x86_debug_state32 *, dr1));
	DECLARE("DS_DR2",	offsetof(struct x86_debug_state32 *, dr2));
	DECLARE("DS_DR3",	offsetof(struct x86_debug_state32 *, dr3));
	DECLARE("DS_DR4",	offsetof(struct x86_debug_state32 *, dr4));
	DECLARE("DS_DR5",	offsetof(struct x86_debug_state32 *, dr5));
	DECLARE("DS_DR6",	offsetof(struct x86_debug_state32 *, dr6));
	DECLARE("DS_DR7",	offsetof(struct x86_debug_state32 *, dr7));

	DECLARE("DS64_DR0",	offsetof(struct x86_debug_state64 *, dr0));
	DECLARE("DS64_DR1",	offsetof(struct x86_debug_state64 *, dr1));
	DECLARE("DS64_DR2",	offsetof(struct x86_debug_state64 *, dr2));
	DECLARE("DS64_DR3",	offsetof(struct x86_debug_state64 *, dr3));
	DECLARE("DS64_DR4",	offsetof(struct x86_debug_state64 *, dr4));
	DECLARE("DS64_DR5",	offsetof(struct x86_debug_state64 *, dr5));
	DECLARE("DS64_DR6",	offsetof(struct x86_debug_state64 *, dr6));
	DECLARE("DS64_DR7",	offsetof(struct x86_debug_state64 *, dr7));

	DECLARE("FP_VALID",	offsetof(struct x86_fpsave_state *,fp_valid));

	DECLARE("SS_FLAVOR",	offsetof(x86_saved_state_t *, flavor));
	DECLARE("SS_32",	x86_SAVED_STATE32);
	DECLARE("SS_64",	x86_SAVED_STATE64);

#define R_(x)  offsetof(x86_saved_state_t *, ss_32.x)
	DECLARE("R_CS",		R_(cs));
	DECLARE("R_SS",		R_(ss));
	DECLARE("R_DS",		R_(ds));
	DECLARE("R_ES",		R_(es));
	DECLARE("R_FS",		R_(fs));
	DECLARE("R_GS",		R_(gs));
	DECLARE("R_UESP",	R_(uesp));
	DECLARE("R_EBP",	R_(ebp));
	DECLARE("R_EAX",	R_(eax));
	DECLARE("R_EBX",	R_(ebx));
	DECLARE("R_ECX",	R_(ecx));
	DECLARE("R_EDX",	R_(edx));
	DECLARE("R_ESI",	R_(esi));
	DECLARE("R_EDI",	R_(edi));
	DECLARE("R_TRAPNO",	R_(trapno));
	DECLARE("R_ERR",	R_(err));
	DECLARE("R_EFLAGS",	R_(efl));
	DECLARE("R_EIP",	R_(eip));
	DECLARE("R_CR2",	R_(cr2));
	DECLARE("ISS32_SIZE",	sizeof (x86_saved_state32_t));

#define R64_(x)  offsetof(x86_saved_state_t *, ss_64.x)
	DECLARE("R64_FS",	R64_(fs));
	DECLARE("R64_GS",	R64_(gs));
	DECLARE("R64_R8",	R64_(r8));
	DECLARE("R64_R9",	R64_(r9));
	DECLARE("R64_R10",	R64_(r10));
	DECLARE("R64_R11",	R64_(r11));
	DECLARE("R64_R12",	R64_(r12));
	DECLARE("R64_R13",	R64_(r13));
	DECLARE("R64_R14",	R64_(r14));
	DECLARE("R64_R15",	R64_(r15));
	DECLARE("R64_RBP",	R64_(rbp));
	DECLARE("R64_RAX",	R64_(rax));
	DECLARE("R64_RBX",	R64_(rbx));
	DECLARE("R64_RCX",	R64_(rcx));
	DECLARE("R64_RDX",	R64_(rdx));
	DECLARE("R64_RSI",	R64_(rsi));
	DECLARE("R64_RDI",	R64_(rdi));
	DECLARE("R64_V_ARG6",	R64_(v_arg6));
	DECLARE("R64_V_ARG7",	R64_(v_arg7));
	DECLARE("R64_V_ARG8",	R64_(v_arg8));
	DECLARE("R64_CS",	R64_(isf.cs));
	DECLARE("R64_SS",	R64_(isf.ss));
	DECLARE("R64_RSP",	R64_(isf.rsp));
	DECLARE("R64_TRAPNO",	R64_(isf.trapno));
	DECLARE("R64_TRAPFN",	R64_(isf.trapfn));
	DECLARE("R64_ERR",	R64_(isf.err));
	DECLARE("R64_RFLAGS",	R64_(isf.rflags));
	DECLARE("R64_RIP",	R64_(isf.rip));
	DECLARE("R64_CR2",	R64_(cr2));
	DECLARE("ISS64_OFFSET",	R64_(isf));
	DECLARE("ISS64_SIZE",	sizeof (x86_saved_state64_t));

#define ISF64_(x)  offsetof(x86_64_intr_stack_frame_t *, x)
	DECLARE("ISF64_TRAPNO",	ISF64_(trapno));
	DECLARE("ISF64_TRAPFN",	ISF64_(trapfn));
	DECLARE("ISF64_ERR",	ISF64_(err));
	DECLARE("ISF64_RIP",	ISF64_(rip));
	DECLARE("ISF64_CS",	ISF64_(cs));
	DECLARE("ISF64_RFLAGS",	ISF64_(rflags));
	DECLARE("ISF64_RSP",	ISF64_(rsp));
	DECLARE("ISF64_SS",	ISF64_(ss));
	DECLARE("ISF64_SIZE",	sizeof(x86_64_intr_stack_frame_t));

	DECLARE("ISC32_OFFSET",	offsetof(x86_saved_state_compat32_t *, isf64));
#define ISC32_(x)  offsetof(x86_saved_state_compat32_t *, isf64.x)
	DECLARE("ISC32_TRAPNO", ISC32_(trapno));
	DECLARE("ISC32_TRAPFN",	ISC32_(trapfn));
	DECLARE("ISC32_ERR",	ISC32_(err));
	DECLARE("ISC32_RIP",	ISC32_(rip));
	DECLARE("ISC32_CS",	ISC32_(cs));
	DECLARE("ISC32_RFLAGS",	ISC32_(rflags));
	DECLARE("ISC32_RSP",	ISC32_(rsp));
	DECLARE("ISC32_SS",	ISC32_(ss));

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
	DECLARE("KERNEL_UBER_BASE_HI32", KERNEL_UBER_BASE_HI32);

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
	DECLARE("NPGPTD", NPGPTD);

	DECLARE("IDTSZ",	IDTSZ);
	DECLARE("GDTSZ",	GDTSZ);
	DECLARE("LDTSZ",	LDTSZ);

	DECLARE("KERNEL_CS",	KERNEL_CS);
	DECLARE("KERNEL_DS",	KERNEL_DS);
	DECLARE("USER_CS",	USER_CS);
	DECLARE("USER_DS",	USER_DS);
	DECLARE("KERNEL64_CS",  KERNEL64_CS);
	DECLARE("USER64_CS",	USER64_CS);
	DECLARE("KERNEL_TSS",	KERNEL_TSS);
	DECLARE("KERNEL_LDT",	KERNEL_LDT);
	DECLARE("DF_TSS",	DF_TSS);
	DECLARE("MC_TSS",	MC_TSS);
#if	MACH_KDB
	DECLARE("DEBUG_TSS",	DEBUG_TSS);
#endif	/* MACH_KDB */
        DECLARE("CPU_DATA_GS",	CPU_DATA_GS);
	DECLARE("SYSENTER_CS",	SYSENTER_CS);
	DECLARE("SYSENTER_TF_CS",SYSENTER_TF_CS);
	DECLARE("SYSENTER_DS",	SYSENTER_DS);
	DECLARE("SYSCALL_CS",	SYSCALL_CS);
	DECLARE("USER_WINDOW_SEL",	USER_WINDOW_SEL);
	DECLARE("PHYS_WINDOW_SEL",	PHYS_WINDOW_SEL);

        DECLARE("CPU_THIS",
		offsetof(cpu_data_t *, cpu_this));
        DECLARE("CPU_ACTIVE_THREAD",
		offsetof(cpu_data_t *, cpu_active_thread));
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
	DECLARE("CPU_DESC_INDEX",
		offsetof(cpu_data_t *,cpu_desc_index));
	DECLARE("CDI_GDT",
		offsetof(cpu_desc_index_t *,cdi_gdt));
	DECLARE("CDI_IDT",
		offsetof(cpu_desc_index_t *,cdi_idt));
	DECLARE("CPU_PROCESSOR",
		offsetof(cpu_data_t *,cpu_processor));
        DECLARE("CPU_INT_STATE",
		offsetof(cpu_data_t *, cpu_int_state));
        DECLARE("CPU_INT_EVENT_TIME",
		offsetof(cpu_data_t *, cpu_int_event_time));

        DECLARE("CPU_HI_ISS",
		offsetof(cpu_data_t *, cpu_hi_iss));
        DECLARE("CPU_TASK_CR3",
		offsetof(cpu_data_t *, cpu_task_cr3));
        DECLARE("CPU_ACTIVE_CR3",
		offsetof(cpu_data_t *, cpu_active_cr3));
        DECLARE("CPU_KERNEL_CR3",
		offsetof(cpu_data_t *, cpu_kernel_cr3));

	DECLARE("CPU_IS64BIT",
		offsetof(cpu_data_t *, cpu_is64bit));
	DECLARE("CPU_TASK_MAP",
		offsetof(cpu_data_t *, cpu_task_map));
	DECLARE("TASK_MAP_32BIT",		TASK_MAP_32BIT); 
	DECLARE("TASK_MAP_64BIT",		TASK_MAP_64BIT); 
	DECLARE("TASK_MAP_64BIT_SHARED",	TASK_MAP_64BIT_SHARED); 
	DECLARE("CPU_UBER_USER_GS_BASE",
		offsetof(cpu_data_t *, cpu_uber.cu_user_gs_base));
	DECLARE("CPU_UBER_ISF",
		offsetof(cpu_data_t *, cpu_uber.cu_isf));
	DECLARE("CPU_UBER_TMP",
		offsetof(cpu_data_t *, cpu_uber.cu_tmp));
	DECLARE("CPU_UBER_ARG_STORE",
		offsetof(cpu_data_t *, cpu_uber_arg_store));
	DECLARE("CPU_UBER_ARG_STORE_VALID",
		offsetof(cpu_data_t *, cpu_uber_arg_store_valid));

	DECLARE("CPU_DR7",
		offsetof(cpu_data_t *, cpu_dr7));

	DECLARE("hwIntCnt", 	offsetof(cpu_data_t *,cpu_hwIntCnt));

	DECLARE("enaExpTrace",	enaExpTrace);
	DECLARE("enaExpTraceb",	enaExpTraceb);
	DECLARE("enaUsrFCall",	enaUsrFCall);
	DECLARE("enaUsrFCallb",	enaUsrFCallb);
	DECLARE("enaUsrPhyMp",	enaUsrPhyMp);
	DECLARE("enaUsrPhyMpb",	enaUsrPhyMpb);
	DECLARE("enaDiagSCs",	enaDiagSCs);
	DECLARE("enaDiagSCsb",	enaDiagSCsb);
	DECLARE("enaDiagEM",	enaDiagEM);
	DECLARE("enaDiagEMb",	enaDiagEMb);
	DECLARE("enaNotifyEM",	enaNotifyEM);
	DECLARE("enaNotifyEMb",	enaNotifyEMb);
	DECLARE("dgLock",		offsetof(struct diagWork *, dgLock));
	DECLARE("dgFlags",		offsetof(struct diagWork *, dgFlags));
	DECLARE("dgMisc1",		offsetof(struct diagWork *, dgMisc1));
	DECLARE("dgMisc2",		offsetof(struct diagWork *, dgMisc2));
	DECLARE("dgMisc3",		offsetof(struct diagWork *, dgMisc3));
	DECLARE("dgMisc4",		offsetof(struct diagWork *, dgMisc4));
	DECLARE("dgMisc5",		offsetof(struct diagWork *, dgMisc5));

	DECLARE("INTEL_PTE_KERNEL",	INTEL_PTE_VALID|INTEL_PTE_WRITE);
	DECLARE("PTDPTDI",     PTDPTDI);
	DECLARE("PDESHIFT",     PDESHIFT);
	DECLARE("PDESIZE",     PDESIZE);
	DECLARE("PTESIZE",     PTESIZE);
	DECLARE("APTDPTDI",     APTDPTDI);
	DECLARE("HIGH_MEM_BASE", HIGH_MEM_BASE);
	DECLARE("HIGH_IDT_BASE", pmap_index_to_virt(HIGH_FIXED_IDT));

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
	DECLARE("U_INTR_GATE",  ACC_P|ACC_PL_U|ACC_INTR_GATE);
	DECLARE("K_TSS",	ACC_P|ACC_PL_K|ACC_TSS);

	/*
	 *	usimple_lock fields
	 */
	DECLARE("USL_INTERLOCK",	offsetof(usimple_lock_t, interlock));

	DECLARE("INTSTACK_SIZE",	INTSTACK_SIZE);
	DECLARE("TIMER_LOW",	 	offsetof(struct timer *, low_bits));
	DECLARE("TIMER_HIGH",		offsetof(struct timer *, high_bits));
	DECLARE("TIMER_HIGHCHK",	offsetof(struct timer *, high_bits_check));
	DECLARE("KADDR", offsetof(struct boot_args *, kaddr));
	DECLARE("KSIZE", offsetof(struct boot_args *, ksize));
	DECLARE("MEMORYMAP", offsetof(struct boot_args *, MemoryMap));
	DECLARE("DEVICETREEP", offsetof(struct boot_args *, deviceTreeP));

	DECLARE("RNT_TSC_BASE",
		offsetof(rtc_nanotime_t *, tsc_base));
	DECLARE("RNT_NS_BASE",
		offsetof(rtc_nanotime_t *, ns_base));
	DECLARE("RNT_SCALE",
		offsetof(rtc_nanotime_t *, scale));
	DECLARE("RNT_SHIFT",
		offsetof(rtc_nanotime_t *, shift));
	DECLARE("RNT_GENERATION",
		offsetof(rtc_nanotime_t *, generation));

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

	DECLARE("THREAD_TIMER",
		offsetof(struct processor *, processor_data.thread_timer));
#endif
	DECLARE("KERNEL_TIMER",
		offsetof(struct processor *, processor_data.kernel_timer));
	DECLARE("SYSTEM_TIMER",
		offsetof(struct thread *, system_timer));
	DECLARE("USER_TIMER",
		offsetof(struct thread *, user_timer));
	DECLARE("SYSTEM_STATE",
			offsetof(struct processor *, processor_data.system_state));
	DECLARE("USER_STATE",
			offsetof(struct processor *, processor_data.user_state));
	DECLARE("IDLE_STATE",
			offsetof(struct processor *, processor_data.idle_state));
	DECLARE("CURRENT_STATE",
			offsetof(struct processor *, processor_data.current_state));

	DECLARE("OnProc", OnProc);


	DECLARE("GCAP_ID",		offsetof(hpetReg_t *, GCAP_ID));
	DECLARE("GEN_CONF",		offsetof(hpetReg_t *, GEN_CONF));
	DECLARE("GINTR_STA",	offsetof(hpetReg_t *, GINTR_STA));
	DECLARE("MAIN_CNT",		offsetof(hpetReg_t *, MAIN_CNT));
	DECLARE("TIM0_CONF",	offsetof(hpetReg_t *, TIM0_CONF));
	DECLARE("TIM_CONF",		TIM_CONF);
	DECLARE("Tn_INT_ENB_CNF",	Tn_INT_ENB_CNF);
	DECLARE("TIM0_COMP",	offsetof(hpetReg_t *, TIM0_COMP));
	DECLARE("TIM_COMP",		TIM_COMP);
	DECLARE("TIM1_CONF",	offsetof(hpetReg_t *, TIM1_CONF));
	DECLARE("TIM1_COMP",	offsetof(hpetReg_t *, TIM1_COMP));
	DECLARE("TIM2_CONF",	offsetof(hpetReg_t *, TIM2_CONF));
	DECLARE("TIM2_COMP",	offsetof(hpetReg_t *, TIM2_COMP));

#if	CONFIG_DTRACE
	DECLARE("LS_LCK_MTX_LOCK_ACQUIRE", LS_LCK_MTX_LOCK_ACQUIRE);
	DECLARE("LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE", LS_LCK_MTX_TRY_SPIN_LOCK_ACQUIRE);
	DECLARE("LS_LCK_MTX_UNLOCK_RELEASE", LS_LCK_MTX_UNLOCK_RELEASE);
	DECLARE("LS_LCK_MTX_TRY_LOCK_ACQUIRE", LS_LCK_MTX_TRY_LOCK_ACQUIRE);
	DECLARE("LS_LCK_RW_LOCK_SHARED_ACQUIRE", LS_LCK_RW_LOCK_SHARED_ACQUIRE);
	DECLARE("LS_LCK_RW_DONE_RELEASE", LS_LCK_RW_DONE_RELEASE);
	DECLARE("LS_LCK_MTX_EXT_LOCK_ACQUIRE", LS_LCK_MTX_EXT_LOCK_ACQUIRE);
	DECLARE("LS_LCK_MTX_TRY_EXT_LOCK_ACQUIRE", LS_LCK_MTX_TRY_EXT_LOCK_ACQUIRE);
	DECLARE("LS_LCK_MTX_EXT_UNLOCK_RELEASE", LS_LCK_MTX_EXT_UNLOCK_RELEASE);

	DECLARE("LS_MUTEX_LOCK_ACQUIRE", LS_MUTEX_LOCK_ACQUIRE);
	DECLARE("LS_MUTEX_TRY_SPIN_ACQUIRE", LS_MUTEX_TRY_SPIN_ACQUIRE);
	DECLARE("LS_MUTEX_TRY_LOCK_ACQUIRE", LS_MUTEX_TRY_LOCK_ACQUIRE);
	DECLARE("LS_MUTEX_UNLOCK_RELEASE", LS_MUTEX_UNLOCK_RELEASE);
	DECLARE("LS_MUTEX_LOCK_SPIN_ACQUIRE", LS_MUTEX_LOCK_SPIN_ACQUIRE);
	DECLARE("LS_MUTEX_CONVERT_SPIN_ACQUIRE", LS_MUTEX_CONVERT_SPIN_ACQUIRE);
#endif

	return (0);
}
