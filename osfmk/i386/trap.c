/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
/*
 */
/*
 * Hardware trap/fault handler.
 */

#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>
#include <mach_ldebug.h>

#include <types.h>
#include <i386/eflags.h>
#include <i386/trap.h>
#include <i386/pmap.h>
#include <i386/fpu.h>
#include <architecture/i386/pio.h> /* inb() */

#include <mach/exception.h>
#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <mach/i386/thread_status.h>

#include <vm/vm_kern.h>
#include <vm/vm_fault.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/exception.h>
#include <kern/spl.h>
#include <kern/misc_protos.h>

#include <sys/kdebug.h>

#if	MACH_KGDB
#include <kgdb/kgdb_defs.h>
#endif	/* MACH_KGDB */

#if 	MACH_KDB
#include <debug.h>
#include <ddb/db_watch.h>
#include <ddb/db_run.h>
#include <ddb/db_break.h>
#include <ddb/db_trap.h>
#endif	/* MACH_KDB */

#include <string.h>

#include <i386/io_emulate.h>
#include <i386/postcode.h>
#include <i386/mp_desc.h>
#include <i386/proc_reg.h>
#include <mach/i386/syscall_sw.h>

/*
 * Forward declarations
 */
static void user_page_fault_continue(kern_return_t kret);
static void panic_trap(x86_saved_state32_t *saved_state);
static void set_recovery_ip(x86_saved_state32_t *saved_state, vm_offset_t ip);

perfCallback perfTrapHook = NULL; /* Pointer to CHUD trap hook routine */
perfCallback perfASTHook  = NULL; /* Pointer to CHUD AST hook routine */

void
thread_syscall_return(
        kern_return_t ret)
{
        thread_t	thr_act = current_thread();

        if (thread_is_64bit(thr_act)) {
	        x86_saved_state64_t	*regs;
		
		regs = USER_REGS64(thr_act);

		if (kdebug_enable && ((regs->rax & SYSCALL_CLASS_MASK) == (SYSCALL_CLASS_MACH << SYSCALL_CLASS_SHIFT))) {
		        /* Mach trap */
		        KERNEL_DEBUG_CONSTANT(
					      MACHDBG_CODE(DBG_MACH_EXCP_SC, ((int) (regs->rax & SYSCALL_NUMBER_MASK)))
					      | DBG_FUNC_END,
					      ret, 0, 0, 0, 0);
		}
		regs->rax = ret;

	} else {
	        x86_saved_state32_t	*regs;
		
		regs = USER_REGS32(thr_act);

		if (kdebug_enable && ((int) regs->eax < 0)) {
		        /* Mach trap */
		        KERNEL_DEBUG_CONSTANT(
					      MACHDBG_CODE(DBG_MACH_EXCP_SC, -((int) regs->eax))
					      | DBG_FUNC_END,
					      ret, 0, 0, 0, 0);
		}
		regs->eax = ret;
	}
        thread_exception_return();
        /*NOTREACHED*/
}


#if	MACH_KDB
boolean_t	debug_all_traps_with_kdb = FALSE;
extern struct db_watchpoint *db_watchpoint_list;
extern boolean_t db_watchpoints_inserted;
extern boolean_t db_breakpoints_inserted;

void
thread_kdb_return(void)
{
	thread_t		thr_act = current_thread();
	x86_saved_state_t	*iss = USER_STATE(thr_act);

        if (is_saved_state64(iss)) {
	        x86_saved_state64_t	*regs;
		
		regs = saved_state64(iss);

		if (kdb_trap(regs->isf.trapno, (int)regs->isf.err, (void *)regs)) {
		        thread_exception_return();
			/*NOTREACHED*/
		}

	} else {
	        x86_saved_state32_t	*regs;
		
		regs = saved_state32(iss);

		if (kdb_trap(regs->trapno, regs->err, (void *)regs)) {
		        thread_exception_return();
			/*NOTREACHED*/
		}
	}
}

#endif	/* MACH_KDB */

void
user_page_fault_continue(
			 kern_return_t	kr)
{
	thread_t	thread = current_thread();
	x86_saved_state_t *regs = USER_STATE(thread);
	ast_t		*myast;
	boolean_t	intr;
	user_addr_t	vaddr;
#if	MACH_KDB
	int		err;
	int		trapno;
#endif

	assert((is_saved_state32(regs) && !thread_is_64bit(thread)) ||
	       (is_saved_state64(regs) &&  thread_is_64bit(thread)));

        if (thread_is_64bit(thread)) {
	        x86_saved_state64_t	*uregs;

		uregs = USER_REGS64(thread);

#if	MACH_KDB
		trapno = uregs->isf.trapno;
		err = uregs->isf.err;
#endif
		vaddr = (user_addr_t)uregs->cr2;
	} else {
	        x86_saved_state32_t	*uregs;

		uregs = USER_REGS32(thread);

#if	MACH_KDB
		trapno = uregs->trapno;
		err = uregs->err;
#endif
		vaddr = uregs->cr2;
	}

	if ((kr == KERN_SUCCESS) || (kr == KERN_ABORTED)) {
#if	MACH_KDB
		if (!db_breakpoints_inserted) {
			db_set_breakpoints();
		}
		if (db_watchpoint_list &&
		    db_watchpoints_inserted &&
		    (err & T_PF_WRITE) &&
		    db_find_watchpoint(thread->map,
				       (vm_offset_t)vaddr,
				       regs))
			kdb_trap(T_WATCHPOINT, 0, regs);
#endif	/* MACH_KDB */
		intr = ml_set_interrupts_enabled(FALSE);
		myast = ast_pending();
		while (*myast & AST_ALL) {
			ast_taken(AST_ALL, intr);
			ml_set_interrupts_enabled(FALSE);
			myast = ast_pending();
		}
		ml_set_interrupts_enabled(intr);

		thread_exception_return();
		/*NOTREACHED*/
	}

#if	MACH_KDB
	if (debug_all_traps_with_kdb &&
	    kdb_trap(trapno, err, regs)) {
		thread_exception_return();
		/*NOTREACHED*/
	}
#endif	/* MACH_KDB */

	i386_exception(EXC_BAD_ACCESS, kr, vaddr);
	/*NOTREACHED*/
}

/*
 * Fault recovery in copyin/copyout routines.
 */
struct recovery {
	uint32_t	fault_addr;
	uint32_t	recover_addr;
};

extern struct recovery	recover_table[];
extern struct recovery	recover_table_end[];

const char *	trap_type[] = {TRAP_NAMES};
unsigned 	TRAP_TYPES = sizeof(trap_type)/sizeof(trap_type[0]);

extern unsigned panic_io_port;

static inline void
reset_dr7(void)
{
	uint32_t dr7 = 0x400; /* magic dr7 reset value */
	__asm__ volatile("movl %0,%%dr7" : : "r" (dr7));
}
#if MACH_KDP
unsigned kdp_has_active_watchpoints = 0;
#endif
/*
 * Trap from kernel mode.  Only page-fault errors are recoverable,
 * and then only in special circumstances.  All other errors are
 * fatal.  Return value indicates if trap was handled.
 */
void
kernel_trap(
	x86_saved_state_t	*state)
{
	x86_saved_state32_t	*saved_state;
	int			code;
	user_addr_t		vaddr;
	int			type;
	vm_map_t		map;
	kern_return_t		result = KERN_FAILURE;
	thread_t		thread;
	ast_t			*myast;
	boolean_t               intr;
	vm_prot_t		prot;
        struct recovery		*rp;
	vm_offset_t		kern_ip;
	int			fault_in_copy_window = -1;
	int			is_user = 0;
#if MACH_KDB	
	pt_entry_t		*pte;
#endif /* MACH_KDB */

	thread = current_thread();

	if (is_saved_state64(state))
		panic("kernel_trap(%p) with 64-bit state", state);
	saved_state = saved_state32(state);

	vaddr = (user_addr_t)saved_state->cr2;
	type  = saved_state->trapno;
	code  = saved_state->err & 0xffff;
	intr  = (saved_state->efl & EFL_IF) != 0;	/* state of ints at trap */

	kern_ip = (vm_offset_t)saved_state->eip;

	myast = ast_pending();

	if (perfASTHook) {
		if (*myast & AST_CHUD_ALL)
			perfASTHook(type, NULL, 0, 0);
	} else
		*myast &= ~AST_CHUD_ALL;

	/*
	 * Is there a hook?
	 */
	if (perfTrapHook) {
	        if (perfTrapHook(type, NULL, 0, 0) == KERN_SUCCESS) {
		        /*
			 * If it succeeds, we are done...
			 */
			return;
		}
	}
	/*
	 * we come here with interrupts off as we don't want to recurse
	 * on preemption below.  but we do want to re-enable interrupts
	 * as soon we possibly can to hold latency down
	 */
	if (T_PREEMPT == type) {

	        KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_EXCP_KTRAP_x86, type)) | DBG_FUNC_NONE,
				      0, 0, 0, kern_ip, 0);

	        ast_taken(AST_PREEMPTION, FALSE);
		return;
	}
	
	if (T_PAGE_FAULT == type) {
		/*
		 * assume we're faulting in the kernel map
		 */
		map = kernel_map;

		if (thread != THREAD_NULL && thread->map != kernel_map) {
		        vm_offset_t	copy_window_base;
			vm_offset_t	kvaddr;
			int		window_index;

			kvaddr = (vm_offset_t)vaddr;
		        /*
			 * must determine if fault occurred in
			 * the copy window while pre-emption is
			 * disabled for this processor so that
			 * we only need to look at the window
			 * associated with this processor
			 */
		        copy_window_base = current_cpu_datap()->cpu_copywindow_base;

			if (kvaddr >= copy_window_base && kvaddr < (copy_window_base + (NBPDE * NCOPY_WINDOWS)) ) {

				window_index = (kvaddr - copy_window_base) / NBPDE;

				if (thread->machine.copy_window[window_index].user_base != (user_addr_t)-1) {

				        kvaddr -= (copy_window_base + (NBPDE * window_index));
				        vaddr = thread->machine.copy_window[window_index].user_base + kvaddr;

					map = thread->map;
					fault_in_copy_window = window_index;
				}
				is_user = -1;
			}
		}
	}
	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_EXCP_KTRAP_x86, type)) | DBG_FUNC_NONE,
			      (int)(vaddr >> 32), (int)vaddr, is_user, kern_ip, 0);


	(void) ml_set_interrupts_enabled(intr);

	switch (type) {

	    case T_NO_FPU:
		fpnoextflt();
		return;

	    case T_FPU_FAULT:
		fpextovrflt();
		return;

	    case T_FLOATING_POINT_ERROR:
		fpexterrflt();
		return;

	    case T_SSE_FLOAT_ERROR:
	        fpSSEexterrflt();
		return;
 	    case T_DEBUG:
		    if ((saved_state->efl & EFL_TF) == 0
		    && !kdp_has_active_watchpoints) {
			    /* We've somehow encountered a debug
			     * register match that does not belong
			     * to the kernel debugger.
			     * This isn't supposed to happen.
			     */
			    reset_dr7();
			    return;
			    }
		    goto debugger_entry;
	    case T_PAGE_FAULT:
		/*
		 * If the current map is a submap of the kernel map,
		 * and the address is within that map, fault on that
		 * map.  If the same check is done in vm_fault
		 * (vm_map_lookup), we may deadlock on the kernel map
		 * lock.
		 */

		prot = VM_PROT_READ;

		if (code & T_PF_WRITE)
		        prot |= VM_PROT_WRITE;
#if     PAE
		if (code & T_PF_EXECUTE)
		        prot |= VM_PROT_EXECUTE;
#endif

#if	MACH_KDB
		/*
		 * Check for watchpoint on kernel static data.
		 * vm_fault would fail in this case 
		 */
		if (map == kernel_map && db_watchpoint_list && db_watchpoints_inserted &&
		    (code & T_PF_WRITE) && vaddr < vm_map_max(map) &&
		    ((*(pte = pmap_pte(kernel_pmap, (vm_map_offset_t)vaddr))) & INTEL_PTE_WRITE) == 0) {
			pmap_store_pte(
				pte,
				*pte | INTEL_PTE_VALID | INTEL_PTE_WRITE);
			/* XXX need invltlb here? */

			result = KERN_SUCCESS;
			goto look_for_watchpoints;
		}
#endif	/* MACH_KDB */

		result = vm_fault(map,
				  vm_map_trunc_page(vaddr),
				  prot,
				  FALSE, 
				  THREAD_UNINT, NULL, 0);

#if	MACH_KDB
		if (result == KERN_SUCCESS) {
		        /*
			 * Look for watchpoints
			 */
look_for_watchpoints:
		        if (map == kernel_map && db_watchpoint_list && db_watchpoints_inserted && (code & T_PF_WRITE) &&
			    db_find_watchpoint(map, vaddr, saved_state))
			        kdb_trap(T_WATCHPOINT, 0, saved_state);
		}
#endif	/* MACH_KDB */

		if (result == KERN_SUCCESS) {

			if (fault_in_copy_window != -1) {
			        pt_entry_t	*updp;
				pt_entry_t	*kpdp;

				/*
				 * in case there was no page table assigned
				 * for the user base address and the pmap
				 * got 'expanded' due to this fault, we'll
				 * copy in the descriptor 
				 *
				 * we're either setting the page table descriptor
				 * to the same value or it was 0... no need
				 * for a TLB flush in either case
				 */

			        ml_set_interrupts_enabled(FALSE);
			        updp = pmap_pde(map->pmap, thread->machine.copy_window[fault_in_copy_window].user_base);
				assert(updp);
				if (0 == updp) panic("trap: updp 0"); /* XXX DEBUG */
				kpdp = current_cpu_datap()->cpu_copywindow_pdp;
				kpdp += fault_in_copy_window;

#if JOE_DEBUG
				if (*kpdp && (*kpdp & PG_FRAME) != (*updp & PG_FRAME))
				        panic("kernel_fault: user pdp doesn't match - updp = 0x%x, kpdp = 0x%x\n", updp, kpdp);
#endif
				pmap_store_pte(kpdp, *updp);

				(void) ml_set_interrupts_enabled(intr);
			}
			return;
		}
		/*
		 * fall through
		 */

	    case T_GENERAL_PROTECTION:
		/*
		 * If there is a failure recovery address
		 * for this fault, go there.
		 */
	        for (rp = recover_table; rp < recover_table_end; rp++) {
		        if (kern_ip == rp->fault_addr) {
			        set_recovery_ip(saved_state, rp->recover_addr);
				return;
			}
		}

		/*
		 * Check thread recovery address also.
		 */
		if (thread->recover) {
		        set_recovery_ip(saved_state, thread->recover);
			thread->recover = 0;
			return;
		}
		/*
		 * Unanticipated page-fault errors in kernel
		 * should not happen.
		 *
		 * fall through...
		 */

	    default:
		/*
		 * Exception 15 is reserved but some chips may generate it
		 * spuriously. Seen at startup on AMD Athlon-64.
		 */
	    	if (type == 15) {
			kprintf("kernel_trap() ignoring spurious trap 15\n"); 
			return;
		}
debugger_entry:
		/* Ensure that the i386_kernel_state at the base of the
		 * current thread's stack (if any) is synchronized with the
		 * context at the moment of the trap, to facilitate
		 * access through the debugger.
		 */
		sync_iss_to_iks(saved_state);
#if MACH_KDB
restart_debugger:
#endif /* MACH_KDB */		
#if  MACH_KDP
                if (current_debugger != KDB_CUR_DB) {
			if (kdp_i386_trap(type, saved_state, result, vaddr))
				return;
		}
#endif /* MACH_KDP */
#if MACH_KDB
		else
			if (kdb_trap(type, code, saved_state)) {
				if (switch_debugger) {
					current_debugger = KDP_CUR_DB;
					switch_debugger = 0;
					goto restart_debugger;
				}
				return;
			}
#endif /* MACH_KDB */
	}

	panic_trap(saved_state);
	/*
	 * NO RETURN
	 */
}


static void
set_recovery_ip(x86_saved_state32_t  *saved_state, vm_offset_t ip)
{
        saved_state->eip = ip;
}


static void
panic_trap(x86_saved_state32_t *regs)
{
	const char *trapname = "Unknown";
	uint32_t	cr0 = get_cr0();
	uint32_t	cr2 = get_cr2();
	uint32_t	cr3 = get_cr3();
	uint32_t	cr4 = get_cr4();

	if (panic_io_port)
	  (void)inb(panic_io_port);

	kprintf("panic trap number 0x%x, eip 0x%x\n", regs->trapno, regs->eip);
	kprintf("cr0 0x%08x cr2 0x%08x cr3 0x%08x cr4 0x%08x\n",
		cr0, cr2, cr3, cr4);

	if (regs->trapno < TRAP_TYPES)
	        trapname = trap_type[regs->trapno];

	panic("Unresolved kernel trap (CPU %d, Type %d=%s), registers:\n"
	      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
	      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
	      "CR2: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
	      "EFL: 0x%08x, EIP: 0x%08x, CS:  0x%08x, DS:  0x%08x\n",
	      cpu_number(), regs->trapno, trapname, cr0, cr2, cr3, cr4,
	      regs->eax,regs->ebx,regs->ecx,regs->edx,
	      regs->cr2,regs->ebp,regs->esi,regs->edi,
	      regs->efl,regs->eip,regs->cs, regs->ds);
	/*
	 * This next statement is not executed,
	 * but it's needed to stop the compiler using tail call optimization
	 * for the panic call - which confuses the subsequent backtrace.
	 */
	cr0 = 0;
}

extern void     kprintf_break_lock(void);


/*
 * Called from locore on a special reserved stack after a double-fault
 * is taken in kernel space.
 * Kernel stack overflow is one route here.
 */
void
panic_double_fault(int code)
{
	struct i386_tss *my_ktss = current_ktss();

	/* Set postcode (DEBUG only) */
	postcode(PANIC_DOUBLE_FAULT);

/* Issue an I/O port read if one has been requested - this is an event logic
 * analyzers can use as a trigger point.
 */
	if (panic_io_port)
		(void)inb(panic_io_port);

	/*
	 * Break kprintf lock in case of recursion,
	 * and record originally faulted instruction address.
	 */
	kprintf_break_lock();

#if MACH_KDP
	/*
	 * Print backtrace leading to first fault:
	 */
	panic_i386_backtrace((void *) my_ktss->ebp, 10);
#endif

	panic("Double fault (CPU:%d, thread:%p, code:0x%x),"
	      "registers:\n"
	      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
	      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
	      "ESP: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
	      "EFL: 0x%08x, EIP: 0x%08x\n",
	      cpu_number(), current_thread(), code,
	      get_cr0(), get_cr2(), get_cr3(), get_cr4(),
	      my_ktss->eax, my_ktss->ebx, my_ktss->ecx, my_ktss->edx,
	      my_ktss->esp, my_ktss->ebp, my_ktss->esi, my_ktss->edi,
	      my_ktss->eflags, my_ktss->eip);
}


/*
 * Called from locore on a special reserved stack after a machine-check
 */
void
panic_machine_check(int code)
{
	struct i386_tss *my_ktss = current_ktss();

	/* Set postcode (DEBUG only) */
	postcode(PANIC_MACHINE_CHECK);

	/*
	 * Break kprintf lock in case of recursion,
	 * and record originally faulted instruction address.
	 */
	kprintf_break_lock();
	panic("Machine-check (CPU:%d, thread:%p, code:0x%x),"
	      "registers:\n"
	      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
	      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
	      "ESP: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
	      "EFL: 0x%08x, EIP: 0x%08x\n",
	      cpu_number(), current_thread(), code,
	      get_cr0(), get_cr2(), get_cr3(), get_cr4(),
	      my_ktss->eax, my_ktss->ebx, my_ktss->ecx, my_ktss->edx,
	      my_ktss->esp, my_ktss->ebp, my_ktss->esi, my_ktss->edi,
	      my_ktss->eflags, my_ktss->eip);
}

void
panic_double_fault64(x86_saved_state_t *esp)
{
	/* Set postcode (DEBUG only) */
	postcode(PANIC_DOUBLE_FAULT);

	/*
	 * Break kprintf lock in case of recursion,
	 * and record originally faulted instruction address.
	 */
	kprintf_break_lock();

	/*
	 * Dump the interrupt stack frame at last kernel entry.
	 */
	if (is_saved_state64(esp)) {
		x86_saved_state64_t	*ss64p = saved_state64(esp);
		panic("Double fault (CPU:%d, thread:%p, trapno:0x%x, err:0x%qx),"
		      "registers:\n"
		      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
		      "RAX: 0x%016qx, RBX: 0x%016qx, RCX: 0x%016qx, RDX: 0x%016qx\n"
		      "RSP: 0x%016qx, RBP: 0x%016qx, RSI: 0x%016qx, RDI: 0x%016qx\n"
		      "R8:  0x%016qx, R9:  0x%016qx, R10: 0x%016qx, R11: 0x%016qx\n"
		      "R12: 0x%016qx, R13: 0x%016qx, R14: 0x%016qx, R15: 0x%016qx\n"
		      "RFL: 0x%016qx, RIP: 0x%016qx\n",
		      cpu_number(), current_thread(), ss64p->isf.trapno, ss64p->isf.err,
		      get_cr0(), get_cr2(), get_cr3(), get_cr4(),
		      ss64p->rax, ss64p->rbx, ss64p->rcx, ss64p->rdx,
		      ss64p->isf.rsp, ss64p->rbp, ss64p->rsi, ss64p->rdi,
		      ss64p->r8, ss64p->r9, ss64p->r10, ss64p->r11,
		      ss64p->r12, ss64p->r13, ss64p->r14, ss64p->r15,
		      ss64p->isf.rflags, ss64p->isf.rip);
	} else {
		x86_saved_state32_t	*ss32p = saved_state32(esp);
		panic("Double fault (CPU:%d, thread:%p, trapno:0x%x, err:0x%x),"
		      "registers:\n"
		      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
		      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
		      "ESP: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
		      "EFL: 0x%08x, EIP: 0x%08x\n",
		      cpu_number(), current_thread(), ss32p->trapno, ss32p->err,
		      get_cr0(), get_cr2(), get_cr3(), get_cr4(),
		      ss32p->eax, ss32p->ebx, ss32p->ecx, ss32p->edx,
		      ss32p->uesp, ss32p->ebp, ss32p->esi, ss32p->edi,
		      ss32p->efl, ss32p->eip);
	}
}

/*
 * Simplistic machine check handler.
 * We could peruse all those MSRs but we only dump register state as we do for
 * the double fault exception.
 * Note: the machine check registers are non-volatile across warm boot - so
 * they'll be around when we return.
 */
void
panic_machine_check64(x86_saved_state_t *esp)
{
	/* Set postcode (DEBUG only) */
	postcode(PANIC_MACHINE_CHECK);

	/*
	 * Break kprintf lock in case of recursion,
	 * and record originally faulted instruction address.
	 */
	kprintf_break_lock();

	/*
	 * Dump the interrupt stack frame at last kernel entry.
	 */
	if (is_saved_state64(esp)) {
		x86_saved_state64_t	*ss64p = saved_state64(esp);
		panic("Machine Check (CPU:%d, thread:%p, trapno:0x%x, err:0x%qx),"
		      "registers:\n"
		      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
		      "RAX: 0x%016qx, RBX: 0x%016qx, RCX: 0x%016qx, RDX: 0x%016qx\n"
		      "RSP: 0x%016qx, RBP: 0x%016qx, RSI: 0x%016qx, RDI: 0x%016qx\n"
		      "R8:  0x%016qx, R9:  0x%016qx, R10: 0x%016qx, R11: 0x%016qx\n"
		      "R12: 0x%016qx, R13: 0x%016qx, R14: 0x%016qx, R15: 0x%016qx\n"
		      "RFL: 0x%016qx, RIP: 0x%016qx\n",
		      cpu_number(), current_thread(), ss64p->isf.trapno, ss64p->isf.err,
		      get_cr0(), get_cr2(), get_cr3(), get_cr4(),
		      ss64p->rax, ss64p->rbx, ss64p->rcx, ss64p->rdx,
		      ss64p->isf.rsp, ss64p->rbp, ss64p->rsi, ss64p->rdi,
		      ss64p->r8, ss64p->r9, ss64p->r10, ss64p->r11,
		      ss64p->r12, ss64p->r13, ss64p->r14, ss64p->r15,
		      ss64p->isf.rflags, ss64p->isf.rip);
	} else {
		x86_saved_state32_t	*ss32p = saved_state32(esp);
		panic("Machine Check (CPU:%d, thread:%p, trapno:0x%x, err:0x%x),"
		      "registers:\n"
		      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
		      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
		      "ESP: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
		      "EFL: 0x%08x, EIP: 0x%08x\n",
		      cpu_number(), current_thread(), ss32p->trapno, ss32p->err,
		      get_cr0(), get_cr2(), get_cr3(), get_cr4(),
		      ss32p->eax, ss32p->ebx, ss32p->ecx, ss32p->edx,
		      ss32p->uesp, ss32p->ebp, ss32p->esi, ss32p->edi,
		      ss32p->efl, ss32p->eip);
	}
}

/*
 *	Trap from user mode.
 */
void
user_trap(
	x86_saved_state_t *saved_state)
{
	int		exc;
	int		code;
	int		err;
	unsigned int	subcode;
	int		type;
	user_addr_t	vaddr;
	vm_prot_t	prot;
	thread_t	thread = current_thread();
	ast_t		*myast;
	boolean_t       intr;
	kern_return_t	kret;
	user_addr_t	rip;

	assert((is_saved_state32(saved_state) && !thread_is_64bit(thread)) ||
	       (is_saved_state64(saved_state) &&  thread_is_64bit(thread)));

	if (is_saved_state64(saved_state)) {
	        x86_saved_state64_t	*regs;

		regs = saved_state64(saved_state);

		type = regs->isf.trapno;
		err  = regs->isf.err & 0xffff;
		vaddr = (user_addr_t)regs->cr2;
		rip   = (user_addr_t)regs->isf.rip;
	} else {
	        x86_saved_state32_t	*regs;

		regs = saved_state32(saved_state);

		type  = regs->trapno;
		err   = regs->err & 0xffff;
		vaddr = (user_addr_t)regs->cr2;
		rip   = (user_addr_t)regs->eip;
	}

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_EXCP_UTRAP_x86, type)) | DBG_FUNC_NONE,
			      (int)(vaddr>>32), (int)vaddr, (int)(rip>>32), (int)rip, 0);

	code = 0;
	subcode = 0;
	exc = 0;

#if DEBUG_TRACE
	kprintf("user_trap(0x%08x) type=%d vaddr=0x%016llx\n",
		saved_state, type, vaddr);
#endif
	myast = ast_pending();
	if (perfASTHook) {
		if (*myast & AST_CHUD_ALL) {
			perfASTHook(type, saved_state, 0, 0);
		}
	} else {
		*myast &= ~AST_CHUD_ALL;
	}

	/* Is there a hook? */
	if (perfTrapHook) {
		if (perfTrapHook(type, saved_state, 0, 0) == KERN_SUCCESS)
			return;	/* If it succeeds, we are done... */
	}

	switch (type) {

	    case T_DIVIDE_ERROR:
		exc = EXC_ARITHMETIC;
		code = EXC_I386_DIV;
		break;

	    case T_DEBUG:
		{
			pcb_t	pcb;
			unsigned int clear = 0;
			/*
			 * get dr6 and set it in the thread's pcb before
			 * returning to userland
			 */
			pcb = thread->machine.pcb;
			if (pcb->ids) {
				/*
				 * We can get and set the status register
				 * in 32-bit mode even on a 64-bit thread
				 * because the high order bits are not
				 * used on x86_64
				 */
				if (thread_is_64bit(thread)) {
					uint32_t dr6;
					x86_debug_state64_t *ids = pcb->ids;
					dr6 = (uint32_t)ids->dr6;
					__asm__ volatile ("movl %%db6, %0" : "=r" (dr6));
					ids->dr6 = dr6;
				} else { /* 32 bit thread */
					x86_debug_state32_t *ids = pcb->ids;
					__asm__ volatile ("movl %%db6, %0" : "=r" (ids->dr6));
				}
				__asm__ volatile ("movl %0, %%db6" : : "r" (clear));
			}
			exc = EXC_BREAKPOINT;
			code = EXC_I386_SGL;
			break;
		}
	    case T_INT3:
		exc = EXC_BREAKPOINT;
		code = EXC_I386_BPT;
		break;

	    case T_OVERFLOW:
		exc = EXC_ARITHMETIC;
		code = EXC_I386_INTO;
		break;

	    case T_OUT_OF_BOUNDS:
		exc = EXC_SOFTWARE;
		code = EXC_I386_BOUND;
		break;

	    case T_INVALID_OPCODE:
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_INVOP;
		break;

	    case T_NO_FPU:
	    case 32:		/* XXX */
		fpnoextflt();
		return;

	    case T_FPU_FAULT:
		fpextovrflt();
		return;

	    case 10:		/* invalid TSS == iret with NT flag set */
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_INVTSSFLT;
		subcode = err;
		break;

	    case T_SEGMENT_NOT_PRESENT:
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_SEGNPFLT;
		subcode = err;
		break;

	    case T_STACK_FAULT:
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_STKFLT;
		subcode = err;
		break;

	    case T_GENERAL_PROTECTION:
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_GPFLT;
		subcode = err;
		break;

	    case T_PAGE_FAULT:
		prot = VM_PROT_READ;

		if (err & T_PF_WRITE)
		        prot |= VM_PROT_WRITE;
#if     PAE
		if (err & T_PF_EXECUTE)
		        prot |= VM_PROT_EXECUTE;
#endif
		kret = vm_fault(thread->map, vm_map_trunc_page(vaddr),
				 prot, FALSE,
				 THREAD_ABORTSAFE, NULL, 0);

	        user_page_fault_continue(kret);
	
		/* NOTREACHED */
		break;

	    case T_SSE_FLOAT_ERROR:
	        fpSSEexterrflt();
		return;


	    case T_FLOATING_POINT_ERROR:
		fpexterrflt();
		return;

	    default:
#if     MACH_KGDB
		Debugger("Unanticipated user trap");
		return;
#endif  /* MACH_KGDB */
#if	MACH_KDB
		if (kdb_trap(type, err, saved_state))
		    return;
#endif	/* MACH_KDB */
		panic("user trap");
		return;
	}
	intr = ml_set_interrupts_enabled(FALSE);
	myast = ast_pending();
	while (*myast & AST_ALL) {
	        ast_taken(AST_ALL, intr);
		ml_set_interrupts_enabled(FALSE);
		myast = ast_pending();
	}
	ml_set_interrupts_enabled(intr);

	i386_exception(exc, code, subcode);
	/*NOTREACHED*/
}


/*
 * Handle AST traps for i386.
 * Check for delayed floating-point exception from
 * AT-bus machines.
 */

extern void     log_thread_action (thread_t, char *);

void
i386_astintr(int preemption)
{
	ast_t		mask = AST_ALL;
	spl_t		s;

	if (preemption)
	        mask = AST_PREEMPTION;

	s = splsched();

	ast_taken(mask, s);

	splx(s);
}

/*
 * Handle exceptions for i386.
 *
 * If we are an AT bus machine, we must turn off the AST for a
 * delayed floating-point exception.
 *
 * If we are providing floating-point emulation, we may have
 * to retrieve the real register values from the floating point
 * emulator.
 */
void
i386_exception(
	int	exc,
	int	code,
	int	subcode)
{
	exception_data_type_t   codes[EXCEPTION_CODE_MAX];

	codes[0] = code;		/* new exception interface */
	codes[1] = subcode;
	exception_triage(exc, codes, 2);
	/*NOTREACHED*/
}


void
kernel_preempt_check(void)
{
	ast_t		*myast;
	boolean_t	intr;

	/*
	 * disable interrupts to both prevent pre-emption
	 * and to keep the ast state from changing via
	 * an interrupt handler making something runnable
	 */
	intr = ml_set_interrupts_enabled(FALSE);

	myast = ast_pending();

	if ((*myast & AST_URGENT) && intr == TRUE && get_interrupt_level() == 0) {
	        /*
		 * can handle interrupts and preemptions 
		 * at this point
		 */
	        ml_set_interrupts_enabled(intr);

		/*
		 * now cause the PRE-EMPTION trap
		 */
		__asm__ volatile ("     int     $0xff");
	} else {
	        /*
		 * if interrupts were already disabled or
		 * we're in an interrupt context, we can't
		 * preempt...  of course if AST_URGENT
		 * isn't set we also don't want to
		 */
	        ml_set_interrupts_enabled(intr);
	}
}

#if	MACH_KDB

extern void 	db_i386_state(x86_saved_state32_t *regs);

#include <ddb/db_output.h>

void 
db_i386_state(
	x86_saved_state32_t *regs)
{
  	db_printf("eip	%8x\n", regs->eip);
  	db_printf("trap	%8x\n", regs->trapno);
  	db_printf("err	%8x\n", regs->err);
  	db_printf("efl	%8x\n", regs->efl);
  	db_printf("ebp	%8x\n", regs->ebp);
  	db_printf("esp	%8x\n", regs->cr2);
  	db_printf("uesp	%8x\n", regs->uesp);
  	db_printf("cs	%8x\n", regs->cs & 0xff);
  	db_printf("ds	%8x\n", regs->ds & 0xff);
  	db_printf("es	%8x\n", regs->es & 0xff);
  	db_printf("fs	%8x\n", regs->fs & 0xff);
  	db_printf("gs	%8x\n", regs->gs & 0xff);
  	db_printf("ss	%8x\n", regs->ss & 0xff);
  	db_printf("eax	%8x\n", regs->eax);
  	db_printf("ebx	%8x\n", regs->ebx);
   	db_printf("ecx	%8x\n", regs->ecx);
  	db_printf("edx	%8x\n", regs->edx);
  	db_printf("esi	%8x\n", regs->esi);
  	db_printf("edi	%8x\n", regs->edi);
}

#endif	/* MACH_KDB */

/* Synchronize a thread's i386_kernel_state (if any) with the given
 * i386_saved_state_t obtained from the trap/IPI handler; called in
 * kernel_trap() prior to entering the debugger, and when receiving
 * an "MP_KDP" IPI.
 */
  
void
sync_iss_to_iks(x86_saved_state32_t *saved_state)
{
	struct x86_kernel_state32 *iks;
	vm_offset_t kstack;
	boolean_t record_active_regs = FALSE;

	if ((kstack = current_thread()->kernel_stack) != 0) {
	        x86_saved_state32_t	*regs;

		regs = saved_state;

		iks = STACK_IKS(kstack);

		 /*
		  * Did we take the trap/interrupt in kernel mode?
		  */
		if (regs == USER_REGS32(current_thread()))
		        record_active_regs = TRUE;
		else {
		        iks->k_ebx = regs->ebx;
			iks->k_esp = (int)regs;
			iks->k_ebp = regs->ebp;
			iks->k_edi = regs->edi;
			iks->k_esi = regs->esi;
			iks->k_eip = regs->eip;
		}
	}

	if (record_active_regs == TRUE) {
		/*
		 * Show the trap handler path
		 */
		__asm__ volatile("movl %%ebx, %0" : "=m" (iks->k_ebx));
		__asm__ volatile("movl %%esp, %0" : "=m" (iks->k_esp));
		__asm__ volatile("movl %%ebp, %0" : "=m" (iks->k_ebp));
		__asm__ volatile("movl %%edi, %0" : "=m" (iks->k_edi));
		__asm__ volatile("movl %%esi, %0" : "=m" (iks->k_esi));
		/*
		 * "Current" instruction pointer
		 */
		__asm__ volatile("movl $1f, %0\n1:" : "=m" (iks->k_eip));
	}
}

/*
 * This is used by the NMI interrupt handler (from mp.c) to
 * uncondtionally sync the trap handler context to the IKS
 * irrespective of whether the NMI was fielded in kernel
 * or user space.
 */
void
sync_iss_to_iks_unconditionally(__unused x86_saved_state32_t *saved_state) {
	struct x86_kernel_state32 *iks;
	vm_offset_t kstack;
	boolean_t record_active_regs = FALSE;

	if ((kstack = current_thread()->kernel_stack) != 0) {

		iks = STACK_IKS(kstack);
				/*
		 * Show the trap handler path
		 */
		__asm__ volatile("movl %%ebx, %0" : "=m" (iks->k_ebx));
		__asm__ volatile("movl %%esp, %0" : "=m" (iks->k_esp));
		__asm__ volatile("movl %%ebp, %0" : "=m" (iks->k_ebp));
		__asm__ volatile("movl %%edi, %0" : "=m" (iks->k_edi));
		__asm__ volatile("movl %%esi, %0" : "=m" (iks->k_esi));
		/*
		 * "Current" instruction pointer
		 */
		__asm__ volatile("movl $1f, %0\n1:" : "=m" (iks->k_eip));

	}
}
