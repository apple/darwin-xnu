/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <mach_ldebug.h>

/*
 * Pass field offsets to assembly code.
 */
#include <kern/ast.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/locks.h>
#include <kern/host.h>
#include <kern/misc_protos.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <vm/vm_map.h>
#include <i386/pmap.h>
#include <i386/Diagnostics.h>
#include <i386/mp_desc.h>
#include <i386/seg.h>
#include <i386/thread.h>
#include <i386/cpu_data.h>
#include <i386/tss.h>
#include <i386/cpu_capabilities.h>
#include <i386/cpuid.h>
#include <i386/pmCPU.h>
#include <mach/i386/vm_param.h>
#include <mach/i386/thread_status.h>
#include <machine/commpage.h>
#include <pexpert/i386/boot.h>

#undef offsetof
#include <stddef.h>

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

	DECLARE("AST_URGENT",		AST_URGENT);
	DECLARE("AST_BSD",			AST_BSD);

	DECLARE("MAX_CPUS",			MAX_CPUS);

	/* Simple Lock structure */
	DECLARE("SLOCK_ILK",	offsetof(usimple_lock_data_t, interlock));
#if	MACH_LDEBUG
	DECLARE("SLOCK_TYPE",	offsetof(usimple_lock_data_t, lock_type));
	DECLARE("SLOCK_PC",	offsetof(usimple_lock_data_t, debug.lock_pc));
	DECLARE("SLOCK_THREAD",	offsetof(usimple_lock_data_t, debug.lock_thread));
	DECLARE("SLOCK_DURATIONH",offsetof(usimple_lock_data_t, debug.duration[0]));
	DECLARE("SLOCK_DURATIONL",offsetof(usimple_lock_data_t, debug.duration[1]));
	DECLARE("USLOCK_TAG",	USLOCK_TAG);
#endif	/* MACH_LDEBUG */

	/* Mutex structure */
	DECLARE("MUTEX_OWNER", offsetof(lck_mtx_t, lck_mtx_owner));
	DECLARE("MUTEX_PTR",   offsetof(lck_mtx_t, lck_mtx_ptr));
	DECLARE("MUTEX_STATE", offsetof(lck_mtx_t, lck_mtx_state));
	DECLARE("MUTEX_IND",	LCK_MTX_TAG_INDIRECT);
	DECLARE("MUTEX_ASSERT_OWNED",	LCK_MTX_ASSERT_OWNED);
	DECLARE("MUTEX_ASSERT_NOTOWNED",LCK_MTX_ASSERT_NOTOWNED);
	DECLARE("GRP_MTX_STAT_UTIL",	offsetof(lck_grp_t, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_util_cnt));
	DECLARE("GRP_MTX_STAT_MISS",	offsetof(lck_grp_t, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_miss_cnt));
	DECLARE("GRP_MTX_STAT_WAIT",	offsetof(lck_grp_t, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_wait_cnt));
	
	/* x86 only */
	DECLARE("MUTEX_DESTROYED", LCK_MTX_TAG_DESTROYED);

	/* Per-mutex statistic element */
	DECLARE("MTX_ACQ_TSC",	offsetof(lck_mtx_ext_t, lck_mtx_stat));

	/* Mutex group statistics elements */
	DECLARE("MUTEX_GRP",	offsetof(lck_mtx_ext_t, lck_mtx_grp));
	
	/*
	 * The use of this field is somewhat at variance with the alias.
	 */
	DECLARE("GRP_MTX_STAT_DIRECT_WAIT",	offsetof(lck_grp_t, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_cnt));

	DECLARE("GRP_MTX_STAT_HELD_MAX",	offsetof(lck_grp_t, lck_grp_stat.lck_grp_mtx_stat.lck_grp_mtx_held_max));
	/* Reader writer lock types */
	DECLARE("RW_SHARED",    LCK_RW_TYPE_SHARED);
	DECLARE("RW_EXCL",      LCK_RW_TYPE_EXCLUSIVE);

	DECLARE("TH_RECOVER",		offsetof(struct thread, recover));
	DECLARE("TH_CONTINUATION",	offsetof(struct thread, continuation));
	DECLARE("TH_KERNEL_STACK",	offsetof(struct thread, kernel_stack));
	DECLARE("TH_MUTEX_COUNT",	offsetof(struct thread, mutex_count));
	DECLARE("TH_WAS_PROMOTED_ON_WAKEUP", offsetof(struct thread, was_promoted_on_wakeup));
	DECLARE("TH_IOTIER_OVERRIDE",	offsetof(struct thread, iotier_override));

	DECLARE("TH_SYSCALLS_MACH",	offsetof(struct thread, syscalls_mach));
	DECLARE("TH_SYSCALLS_UNIX",	offsetof(struct thread, syscalls_unix));

	DECLARE("TASK_VTIMERS",			offsetof(struct task, vtimers));

	/* These fields are being added on demand */
	DECLARE("TH_TASK",	offsetof(struct thread, task));
	DECLARE("TH_AST",	offsetof(struct thread, ast));
	DECLARE("TH_MAP",	offsetof(struct thread, map));
	DECLARE("TH_SPF",	offsetof(struct thread, machine.specFlags));
	DECLARE("TH_PCB_ISS", 	offsetof(struct thread, machine.iss));
	DECLARE("TH_PCB_IDS", 	offsetof(struct thread, machine.ids));
	DECLARE("TH_PCB_FPS",	offsetof(struct thread, machine.ifps));
#if NCOPY_WINDOWS > 0
	DECLARE("TH_COPYIO_STATE", offsetof(struct thread, machine.copyio_state));
	DECLARE("WINDOWS_CLEAN", WINDOWS_CLEAN);
#endif
	DECLARE("TH_RWLOCK_COUNT",	offsetof(struct thread, rwlock_count));

	DECLARE("MAP_PMAP",	offsetof(struct _vm_map, pmap));

#define IEL_SIZE		(sizeof(struct i386_exception_link *))
	DECLARE("IKS_SIZE",	sizeof(struct x86_kernel_state));

	/*
	 * KSS_* are offsets from the top of the kernel stack (cpu_kernel_stack)
	 */
	DECLARE("KSS_RBX",	offsetof(struct x86_kernel_state, k_rbx));
	DECLARE("KSS_RSP",	offsetof(struct x86_kernel_state, k_rsp));
	DECLARE("KSS_RBP",	offsetof(struct x86_kernel_state, k_rbp));
	DECLARE("KSS_R12",	offsetof(struct x86_kernel_state, k_r12));
	DECLARE("KSS_R13",	offsetof(struct x86_kernel_state, k_r13));
	DECLARE("KSS_R14",	offsetof(struct x86_kernel_state, k_r14));
	DECLARE("KSS_R15",	offsetof(struct x86_kernel_state, k_r15));
	DECLARE("KSS_RIP",	offsetof(struct x86_kernel_state, k_rip));	
	
	DECLARE("DS_DR0",	offsetof(struct x86_debug_state32, dr0));
	DECLARE("DS_DR1",	offsetof(struct x86_debug_state32, dr1));
	DECLARE("DS_DR2",	offsetof(struct x86_debug_state32, dr2));
	DECLARE("DS_DR3",	offsetof(struct x86_debug_state32, dr3));
	DECLARE("DS_DR4",	offsetof(struct x86_debug_state32, dr4));
	DECLARE("DS_DR5",	offsetof(struct x86_debug_state32, dr5));
	DECLARE("DS_DR6",	offsetof(struct x86_debug_state32, dr6));
	DECLARE("DS_DR7",	offsetof(struct x86_debug_state32, dr7));

	DECLARE("DS64_DR0",	offsetof(struct x86_debug_state64, dr0));
	DECLARE("DS64_DR1",	offsetof(struct x86_debug_state64, dr1));
	DECLARE("DS64_DR2",	offsetof(struct x86_debug_state64, dr2));
	DECLARE("DS64_DR3",	offsetof(struct x86_debug_state64, dr3));
	DECLARE("DS64_DR4",	offsetof(struct x86_debug_state64, dr4));
	DECLARE("DS64_DR5",	offsetof(struct x86_debug_state64, dr5));
	DECLARE("DS64_DR6",	offsetof(struct x86_debug_state64, dr6));
	DECLARE("DS64_DR7",	offsetof(struct x86_debug_state64, dr7));

	DECLARE("FP_VALID",	offsetof(struct x86_fx_thread_state,fp_valid));

	DECLARE("SS_FLAVOR",	offsetof(x86_saved_state_t, flavor));
	DECLARE("SS_32",	x86_SAVED_STATE32);
	DECLARE("SS_64",	x86_SAVED_STATE64);

#define R_(x)  offsetof(x86_saved_state_t, ss_32.x)
	DECLARE("R32_CS",	R_(cs));
	DECLARE("R32_SS",	R_(ss));
	DECLARE("R32_DS",	R_(ds));
	DECLARE("R32_ES",	R_(es));
	DECLARE("R32_FS",	R_(fs));
	DECLARE("R32_GS",	R_(gs));
	DECLARE("R32_UESP",	R_(uesp));
	DECLARE("R32_EBP",	R_(ebp));
	DECLARE("R32_EAX",	R_(eax));
	DECLARE("R32_EBX",	R_(ebx));
	DECLARE("R32_ECX",	R_(ecx));
	DECLARE("R32_EDX",	R_(edx));
	DECLARE("R32_ESI",	R_(esi));
	DECLARE("R32_EDI",	R_(edi));
	DECLARE("R32_TRAPNO",	R_(trapno));
	DECLARE("R32_ERR",	R_(err));
	DECLARE("R32_EFLAGS",	R_(efl));
	DECLARE("R32_EIP",	R_(eip));
	DECLARE("R32_CR2",	R_(cr2));
	DECLARE("ISS32_SIZE",	sizeof (x86_saved_state32_t));

#define R64_(x)  offsetof(x86_saved_state_t, ss_64.x)
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

#define ISF64_(x)  offsetof(x86_64_intr_stack_frame_t, x)
	DECLARE("ISF64_TRAPNO",	ISF64_(trapno));
	DECLARE("ISF64_TRAPFN",	ISF64_(trapfn));
	DECLARE("ISF64_ERR",	ISF64_(err));
	DECLARE("ISF64_RIP",	ISF64_(rip));
	DECLARE("ISF64_CS",	ISF64_(cs));
	DECLARE("ISF64_RFLAGS",	ISF64_(rflags));
	DECLARE("ISF64_RSP",	ISF64_(rsp));
	DECLARE("ISF64_SS",	ISF64_(ss));
	DECLARE("ISF64_SIZE",	sizeof(x86_64_intr_stack_frame_t));

	DECLARE("NBPG",			I386_PGBYTES);
	DECLARE("PAGE_SIZE",            I386_PGBYTES);
	DECLARE("PAGE_MASK",            I386_PGBYTES-1);
	DECLARE("PAGE_SHIFT",           12);
	DECLARE("NKPT",                 NKPT);
	DECLARE("VM_MIN_ADDRESS",	VM_MIN_ADDRESS);
	DECLARE("VM_MAX_ADDRESS",	VM_MAX_ADDRESS);
	DECLARE("KERNELBASE",		VM_MIN_KERNEL_ADDRESS);
	DECLARE("LINEAR_KERNELBASE",	LINEAR_KERNEL_ADDRESS);
	DECLARE("KERNEL_STACK_SIZE",	KERNEL_STACK_SIZE);

	DECLARE("ASM_COMM_PAGE32_BASE_ADDRESS",  _COMM_PAGE32_BASE_ADDRESS);
	DECLARE("ASM_COMM_PAGE32_START_ADDRESS",  _COMM_PAGE32_START_ADDRESS);
	DECLARE("ASM_COMM_PAGE_SCHED_GEN",  _COMM_PAGE_SCHED_GEN);

	DECLARE("KERNEL_PML4_INDEX", KERNEL_PML4_INDEX);
	DECLARE("IDTSZ",	IDTSZ);
	DECLARE("GDTSZ",	GDTSZ);
	DECLARE("LDTSZ",	LDTSZ);

	DECLARE("KERNEL_DS",	KERNEL_DS);
	DECLARE("USER_CS",	USER_CS);
	DECLARE("USER_DS",	USER_DS);
	DECLARE("KERNEL32_CS",	KERNEL32_CS);
	DECLARE("KERNEL64_CS",  KERNEL64_CS);
	DECLARE("USER64_CS",	USER64_CS);
	DECLARE("KERNEL_TSS",	KERNEL_TSS);
	DECLARE("KERNEL_LDT",	KERNEL_LDT);
	DECLARE("SYSENTER_CS",	SYSENTER_CS);
	DECLARE("SYSENTER_TF_CS",SYSENTER_TF_CS);
	DECLARE("SYSENTER_DS",	SYSENTER_DS);
	DECLARE("SYSCALL_CS",	SYSCALL_CS);

        DECLARE("CPU_THIS",
		offsetof(cpu_data_t, cpu_this));
        DECLARE("CPU_ACTIVE_THREAD",
		offsetof(cpu_data_t, cpu_active_thread));
        DECLARE("CPU_ACTIVE_STACK",
		offsetof(cpu_data_t, cpu_active_stack));
        DECLARE("CPU_KERNEL_STACK",
		offsetof(cpu_data_t, cpu_kernel_stack));
        DECLARE("CPU_INT_STACK_TOP",
		offsetof(cpu_data_t, cpu_int_stack_top));
#if	MACH_RT
        DECLARE("CPU_PREEMPTION_LEVEL",
		offsetof(cpu_data_t, cpu_preemption_level));
#endif	/* MACH_RT */
        DECLARE("CPU_HIBERNATE",
		offsetof(cpu_data_t, cpu_hibernate));
        DECLARE("CPU_INTERRUPT_LEVEL",
		offsetof(cpu_data_t, cpu_interrupt_level));
	DECLARE("CPU_NESTED_ISTACK",
	    offsetof(cpu_data_t, cpu_nested_istack));
        DECLARE("CPU_NUMBER_GS",
		offsetof(cpu_data_t,cpu_number));
        DECLARE("CPU_RUNNING",
		offsetof(cpu_data_t,cpu_running));
	DECLARE("CPU_PENDING_AST",
		offsetof(cpu_data_t,cpu_pending_ast));
	DECLARE("CPU_DESC_TABLEP",
		offsetof(cpu_data_t,cpu_desc_tablep));
	DECLARE("CPU_DESC_INDEX",
		offsetof(cpu_data_t,cpu_desc_index));
	DECLARE("CDI_GDT",
		offsetof(cpu_desc_index_t,cdi_gdt));
	DECLARE("CDI_IDT",
		offsetof(cpu_desc_index_t,cdi_idt));
	DECLARE("CPU_PROCESSOR",
		offsetof(cpu_data_t,cpu_processor));
        DECLARE("CPU_INT_STATE",
		offsetof(cpu_data_t, cpu_int_state));
        DECLARE("CPU_INT_EVENT_TIME",
		offsetof(cpu_data_t, cpu_int_event_time));

        DECLARE("CPU_TASK_CR3",
		offsetof(cpu_data_t, cpu_task_cr3));
        DECLARE("CPU_ACTIVE_CR3",
		offsetof(cpu_data_t, cpu_active_cr3));
        DECLARE("CPU_KERNEL_CR3",
		offsetof(cpu_data_t, cpu_kernel_cr3));
	DECLARE("CPU_TLB_INVALID",
		offsetof(cpu_data_t, cpu_tlb_invalid));

	DECLARE("CPU_TASK_MAP",
		offsetof(cpu_data_t, cpu_task_map));
	DECLARE("TASK_MAP_32BIT",		TASK_MAP_32BIT); 
	DECLARE("TASK_MAP_64BIT",		TASK_MAP_64BIT);
	DECLARE("CPU_UBER_USER_GS_BASE",
		offsetof(cpu_data_t, cpu_uber.cu_user_gs_base));
	DECLARE("CPU_UBER_ISF",
		offsetof(cpu_data_t, cpu_uber.cu_isf));
	DECLARE("CPU_UBER_TMP",
		offsetof(cpu_data_t, cpu_uber.cu_tmp));

	DECLARE("CPU_NANOTIME",
		offsetof(cpu_data_t, cpu_nanotime));

	DECLARE("CPU_DR7",
		offsetof(cpu_data_t, cpu_dr7));

	DECLARE("hwIntCnt", 	offsetof(cpu_data_t,cpu_hwIntCnt));
	DECLARE("CPU_ACTIVE_PCID",
		offsetof(cpu_data_t, cpu_active_pcid));
	DECLARE("CPU_PCID_COHERENTP",
		offsetof(cpu_data_t, cpu_pmap_pcid_coherentp));
	DECLARE("CPU_PCID_COHERENTP_KERNEL",
		offsetof(cpu_data_t, cpu_pmap_pcid_coherentp_kernel));
	DECLARE("CPU_PMAP_PCID_ENABLED",
	    offsetof(cpu_data_t, cpu_pmap_pcid_enabled));

#ifdef	PCID_STATS	
	DECLARE("CPU_PMAP_USER_RETS",
	    offsetof(cpu_data_t, cpu_pmap_user_rets));
	DECLARE("CPU_PMAP_PCID_PRESERVES",
	    offsetof(cpu_data_t, cpu_pmap_pcid_preserves));
	DECLARE("CPU_PMAP_PCID_FLUSHES",
	    offsetof(cpu_data_t, cpu_pmap_pcid_flushes));
#endif
	DECLARE("CPU_TLB_INVALID_LOCAL",
	    offsetof(cpu_data_t, cpu_tlb_invalid_local));
	DECLARE("CPU_TLB_INVALID_GLOBAL",
		offsetof(cpu_data_t, cpu_tlb_invalid_global));
	DECLARE("enaExpTrace",	enaExpTrace);
	DECLARE("enaUsrFCall",	enaUsrFCall);
	DECLARE("enaUsrPhyMp",	enaUsrPhyMp);
	DECLARE("enaDiagSCs",	enaDiagSCs);
	DECLARE("enaDiagEM",	enaDiagEM);
	DECLARE("enaNotifyEM",	enaNotifyEM);
	DECLARE("dgLock",		offsetof(struct diagWork, dgLock));
	DECLARE("dgFlags",		offsetof(struct diagWork, dgFlags));
	DECLARE("dgMisc1",		offsetof(struct diagWork, dgMisc1));
	DECLARE("dgMisc2",		offsetof(struct diagWork, dgMisc2));
	DECLARE("dgMisc3",		offsetof(struct diagWork, dgMisc3));
	DECLARE("dgMisc4",		offsetof(struct diagWork, dgMisc4));
	DECLARE("dgMisc5",		offsetof(struct diagWork, dgMisc5));

	DECLARE("TSS_ESP0",	offsetof(struct i386_tss, esp0));
	DECLARE("TSS_SS0",	offsetof(struct i386_tss, ss0));
	DECLARE("TSS_LDT",	offsetof(struct i386_tss, ldt));
	DECLARE("TSS_PDBR",	offsetof(struct i386_tss, cr3));
	DECLARE("TSS_LINK",	offsetof(struct i386_tss, back_link));

	DECLARE("K_TASK_GATE",	ACC_P|ACC_PL_K|ACC_TASK_GATE);
	DECLARE("K_TRAP_GATE",	ACC_P|ACC_PL_K|ACC_TRAP_GATE);
	DECLARE("U_TRAP_GATE",	ACC_P|ACC_PL_U|ACC_TRAP_GATE);
	DECLARE("K_INTR_GATE",	ACC_P|ACC_PL_K|ACC_INTR_GATE);
	DECLARE("U_INTR_GATE",  ACC_P|ACC_PL_U|ACC_INTR_GATE);
	DECLARE("K_TSS",	ACC_P|ACC_PL_K|ACC_TSS);

	/*
	 *	usimple_lock fields
	 */
	DECLARE("USL_INTERLOCK",	offsetof(usimple_lock_data_t, interlock));

	DECLARE("INTSTACK_SIZE",	INTSTACK_SIZE);
	DECLARE("KADDR", offsetof(struct boot_args, kaddr));
	DECLARE("KSIZE", offsetof(struct boot_args, ksize));
	DECLARE("MEMORYMAP", offsetof(struct boot_args, MemoryMap));
	DECLARE("DEVICETREEP", offsetof(struct boot_args, deviceTreeP));

	DECLARE("RNT_TSC_BASE",
		offsetof(pal_rtc_nanotime_t, tsc_base));
	DECLARE("RNT_NS_BASE",
		offsetof(pal_rtc_nanotime_t, ns_base));
	DECLARE("RNT_SCALE",
		offsetof(pal_rtc_nanotime_t, scale));
	DECLARE("RNT_SHIFT",
		offsetof(pal_rtc_nanotime_t, shift));
	DECLARE("RNT_GENERATION",
		offsetof(pal_rtc_nanotime_t, generation));

	/* values from kern/timer.h */
#ifdef __LP64__
	DECLARE("TIMER_ALL", offsetof(struct timer, all_bits));
#else
	DECLARE("TIMER_LOW",	 	offsetof(struct timer, low_bits));
	DECLARE("TIMER_HIGH",		offsetof(struct timer, high_bits));
	DECLARE("TIMER_HIGHCHK",	offsetof(struct timer, high_bits_check));	
#endif
	DECLARE("TIMER_TSTAMP",
		offsetof(struct timer, tstamp));

	DECLARE("THREAD_TIMER",
		offsetof(struct processor, processor_data.thread_timer));
	DECLARE("KERNEL_TIMER",
		offsetof(struct processor, processor_data.kernel_timer));
	DECLARE("SYSTEM_TIMER",
		offsetof(struct thread, system_timer));
	DECLARE("USER_TIMER",
		offsetof(struct thread, user_timer));
	DECLARE("SYSTEM_STATE",
			offsetof(struct processor, processor_data.system_state));
	DECLARE("USER_STATE",
			offsetof(struct processor, processor_data.user_state));
	DECLARE("IDLE_STATE",
			offsetof(struct processor, processor_data.idle_state));
	DECLARE("CURRENT_STATE",
			offsetof(struct processor, processor_data.current_state));

	DECLARE("OnProc", OnProc);


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
	DECLARE("LS_LCK_RW_LOCK_EXCL_ACQUIRE", LS_LCK_RW_LOCK_EXCL_ACQUIRE);
	DECLARE("LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE", LS_LCK_RW_LOCK_SHARED_TO_EXCL_UPGRADE);
	DECLARE("LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE", LS_LCK_RW_TRY_LOCK_EXCL_ACQUIRE);
	DECLARE("LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE", LS_LCK_RW_TRY_LOCK_SHARED_ACQUIRE);
	DECLARE("LS_LCK_MTX_LOCK_SPIN_ACQUIRE", LS_LCK_MTX_LOCK_SPIN_ACQUIRE);
#endif

	return (0);
}
