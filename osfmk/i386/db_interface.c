/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 */

/*
 * Interface to new debugger.
 */
#include <platforms.h>
#include <time_stamp.h>
#include <mach_mp_debug.h>
#include <mach_ldebug.h>
#include <kern/spl.h>
#include <kern/cpu_number.h>
#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <vm/pmap.h>

#include <i386/thread.h>
#include <i386/db_machdep.h>
#include <i386/seg.h>
#include <i386/trap.h>
#include <i386/setjmp.h>
#include <i386/pmap.h>
#include <i386/misc_protos.h>
#include <i386/mp.h>
#include <i386/machine_cpu.h>

#include <mach/vm_param.h>
#include <vm/vm_map.h>
#include <kern/thread.h>
#include <kern/task.h>

#include <ddb/db_command.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_run.h>
#include <ddb/db_trap.h>
#include <ddb/db_output.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_break.h>
#include <ddb/db_watch.h>

#include <i386/cpu_data.h>

int	 db_active = 0;
x86_saved_state32_t	*i386_last_saved_statep;
x86_saved_state32_t	i386_nested_saved_state;
unsigned i386_last_kdb_sp;
db_regs_t	ddb_regs;	/* register state */

extern	thread_t db_default_act;
extern pt_entry_t *DMAP1;
extern caddr_t DADDR1;

#if	MACH_MP_DEBUG
extern int masked_state_cnt[];
#endif	/* MACH_MP_DEBUG */

/*
 *	Enter KDB through a keyboard trap.
 *	We show the registers as of the keyboard interrupt
 *	instead of those at its call to KDB.
 */
struct int_regs {
	int	gs;
	int	fs;
	int	edi;
	int	esi;
	int	ebp;
	int	ebx;
	x86_saved_state32_t *is;
};

extern char *	trap_type[];
extern int	TRAP_TYPES;

/* Forward */

extern void	kdbprinttrap(
			int			type,
			int			code,
			int			*pc,
			int			sp);
extern void	kdb_kentry(
			struct int_regs		*int_regs);
extern int	db_user_to_kernel_address(
			task_t			task,
			vm_offset_t		addr,
			unsigned		*kaddr,
			int			flag);
extern void	db_write_bytes_user_space(
			vm_offset_t		addr,
			int			size,
			char			*data,
			task_t			task);
extern int	db_search_null(
			task_t			task,
			unsigned		*svaddr,
			unsigned		evaddr,
			unsigned		*skaddr,
			int			flag);
extern int	kdb_enter(int);
extern void	kdb_leave(void);
extern void	lock_kdb(void);
extern void	unlock_kdb(void);

/*
 *  kdb_trap - field a TRACE or BPT trap
 */


extern jmp_buf_t *db_recover;

/*
 * Translate the state saved in a task state segment into an
 * exception frame.  Since we "know" we always want the state
 * in a ktss, we hard-wire that in, rather than indexing the gdt
 * with tss_sel to derive a pointer to the desired tss.
 */

/*
 * Code used to synchronize kdb among all cpus, one active at a time, switch
 * from one to another using cpu #cpu
 */

decl_simple_lock_data(, kdb_lock)	/* kdb lock			*/

#define	db_simple_lock_init(l, e)	hw_lock_init(&((l)->interlock))
#define	db_simple_lock_try(l)		hw_lock_try(&((l)->interlock))
#define	db_simple_unlock(l)		hw_lock_unlock(&((l)->interlock))

int			kdb_cpu = -1;	/* current cpu running kdb	*/
int			kdb_debug = 1;
volatile unsigned int	cpus_holding_bkpts;	/* counter for number of cpus
						 * holding breakpoints
						 */
extern boolean_t	db_breakpoints_inserted;

void
db_tss_to_frame(
	int tss_sel,
	x86_saved_state32_t *regs)
{
	extern struct i386_tss ktss;
	int mycpu = cpu_number();
	struct i386_tss *tss;

	tss = cpu_datap(mycpu)->cpu_desc_index.cdi_ktss;	/* XXX */

	/*
	 * ddb will overwrite whatever's in esp, so put esp0 elsewhere, too.
	 */
	regs->cr2 = tss->esp0;
	regs->efl = tss->eflags;
	regs->eip = tss->eip;
	regs->trapno = tss->ss0;	/* XXX */
	regs->err = tss->esp0;	/* XXX */
	regs->eax = tss->eax;
	regs->ecx = tss->ecx;
	regs->edx = tss->edx;
	regs->ebx = tss->ebx;
	regs->uesp = tss->esp;
	regs->ebp = tss->ebp;
	regs->esi = tss->esi;
	regs->edi = tss->edi;
	regs->es = tss->es;
	regs->ss = tss->ss;
	regs->cs = tss->cs;
	regs->ds = tss->ds;
	regs->fs = tss->fs;
	regs->gs = tss->gs;
}

/*
 * Compose a call to the debugger from the saved state in regs.  (No
 * reason not to do this in C.)
 */
boolean_t
db_trap_from_asm(
	x86_saved_state32_t *regs)
{
	int	code;
	int	type;

	type = regs->trapno;
	code = regs->err;
	return (kdb_trap(type, code, regs));
}

int
kdb_trap(
	int			type,
	int			code,
	x86_saved_state32_t	*regs)
{
	extern char 		etext;
	boolean_t		trap_from_user;
	spl_t			s;
	int                     previous_console_device;

	s = splhigh();

	previous_console_device = switch_to_serial_console();

	db_printf("kdb_trap(): type %d, code %d, regs->eip 0x%x\n", type, code, regs->eip);
	switch (type) {
	    case T_DEBUG:	/* single_step */
	    {
	    	extern int dr_addr[];
		int addr;
	    	uint32_t status;

		__asm__ volatile ("movl %%dr6, %0" : "=r" (status));

		if (status & 0xf) {	/* hmm hdw break */
			addr =	status & 0x8 ? dr_addr[3] :
				status & 0x4 ? dr_addr[2] :
				status & 0x2 ? dr_addr[1] :
					       dr_addr[0];
			regs->efl |= EFL_RF;
			db_single_step_cmd(addr, 0, 1, "p");
		}
	    }
	    case T_INT3:	/* breakpoint */
	    case T_WATCHPOINT:	/* watchpoint */
	    case -1:	/* keyboard interrupt */
		break;

	    default:
		if (db_recover) {
		    i386_nested_saved_state = *regs;
		    db_printf("Caught ");
		    if (type < 0 || type > TRAP_TYPES)
			db_printf("type %d", type);
		    else
			db_printf("%s", trap_type[type]);
		    db_printf(" trap, code = %x, pc = %x\n",
			      code, regs->eip);
			splx(s);
		    db_error("");
		    /*NOTREACHED*/
		}
		kdbprinttrap(type, code, (int *)&regs->eip, regs->uesp);
	}

	disable_preemption();

	current_cpu_datap()->cpu_kdb_saved_ipl = s;
	current_cpu_datap()->cpu_kdb_saved_state = regs;

	i386_last_saved_statep = regs;
	i386_last_kdb_sp = (unsigned) &type;

	if (!kdb_enter(regs->eip))
		goto kdb_exit;

	/*  Should switch to kdb's own stack here. */

	if (!IS_USER_TRAP(regs, &etext)) {
		bzero((char *)&ddb_regs, sizeof (ddb_regs));
		*(struct x86_saved_state32_from_kernel *)&ddb_regs =
			*(struct x86_saved_state32_from_kernel *)regs;
		trap_from_user = FALSE;
	}
	else {
		ddb_regs = *regs;
		trap_from_user = TRUE;
	}
	if (!trap_from_user) {
	    /*
	     * Kernel mode - esp and ss not saved
	     */
	    ddb_regs.uesp = (int)&regs->uesp;	/* kernel stack pointer */
	    ddb_regs.ss   = KERNEL_DS;
	}

	db_active++;
	db_task_trap(type, code, trap_from_user);
	db_active--;

	regs->eip    = ddb_regs.eip;
	regs->efl    = ddb_regs.efl;
	regs->eax    = ddb_regs.eax;
	regs->ecx    = ddb_regs.ecx;
	regs->edx    = ddb_regs.edx;
	regs->ebx    = ddb_regs.ebx;

	if (trap_from_user) {
	    /*
	     * user mode - saved esp and ss valid
	     */
	    regs->uesp = ddb_regs.uesp;		/* user stack pointer */
	    regs->ss   = ddb_regs.ss & 0xffff;	/* user stack segment */
	}

	regs->ebp    = ddb_regs.ebp;
	regs->esi    = ddb_regs.esi;
	regs->edi    = ddb_regs.edi;
	regs->es     = ddb_regs.es & 0xffff;
	regs->cs     = ddb_regs.cs & 0xffff;
	regs->ds     = ddb_regs.ds & 0xffff;
	regs->fs     = ddb_regs.fs & 0xffff;
	regs->gs     = ddb_regs.gs & 0xffff;

	if ((type == T_INT3) &&
	    (db_get_task_value(regs->eip,
			       BKPT_SIZE,
			       FALSE,
			       db_target_space(current_thread(),
					       trap_from_user))
	                      == BKPT_INST))
	    regs->eip += BKPT_SIZE;
	
	switch_to_old_console(previous_console_device);
kdb_exit:
	kdb_leave();

	current_cpu_datap()->cpu_kdb_saved_state = 0;

	enable_preemption();

	splx(s);

	/* Allow continue to upper layers of exception handling if
	 * trap was not a debugging trap.
	 */

	if (trap_from_user && type != T_DEBUG && type != T_INT3 
		&& type != T_WATCHPOINT)
		return 0;
	else
		return (1);
}

/*
 *	Enter KDB through a keyboard trap.
 *	We show the registers as of the keyboard interrupt
 *	instead of those at its call to KDB.
 */

spl_t kdb_oldspl;

void
kdb_kentry(
	struct int_regs	*int_regs)
{
	extern char etext;
	boolean_t trap_from_user;
	x86_saved_state32_t *is = int_regs->is;
	x86_saved_state32_t regs;
	spl_t s;

	s = splhigh();
	kdb_oldspl = s;

	if (IS_USER_TRAP(is, &etext))
	{
	    regs.uesp = ((int *)(is+1))[0];
	    regs.ss   = ((int *)(is+1))[1];
	}
	else {
	    regs.ss  = KERNEL_DS;
	    regs.uesp= (int)(is+1);
	}
	regs.efl = is->efl;
	regs.cs  = is->cs;
	regs.eip = is->eip;
	regs.eax = is->eax;
	regs.ecx = is->ecx;
	regs.edx = is->edx;
	regs.ebx = int_regs->ebx;
	regs.ebp = int_regs->ebp;
	regs.esi = int_regs->esi;
	regs.edi = int_regs->edi;
	regs.ds  = is->ds;
	regs.es  = is->es;
	regs.fs  = int_regs->fs;
	regs.gs  = int_regs->gs;

	disable_preemption();

	current_cpu_datap()->cpu_kdb_saved_state = &regs;

	if (!kdb_enter(regs.eip))
		goto kdb_exit;

	bcopy((char *)&regs, (char *)&ddb_regs, sizeof (ddb_regs));
	trap_from_user = IS_USER_TRAP(&ddb_regs, &etext);

	db_active++;
	db_task_trap(-1, 0, trap_from_user);
	db_active--;

	if (trap_from_user) {
	    ((int *)(is+1))[0] = ddb_regs.uesp;
	    ((int *)(is+1))[1] = ddb_regs.ss & 0xffff;
	}
	is->efl = ddb_regs.efl;
	is->cs  = ddb_regs.cs & 0xffff;
	is->eip = ddb_regs.eip;
	is->eax = ddb_regs.eax;
	is->ecx = ddb_regs.ecx;
	is->edx = ddb_regs.edx;
	int_regs->ebx = ddb_regs.ebx;
	int_regs->ebp = ddb_regs.ebp;
	int_regs->esi = ddb_regs.esi;
	int_regs->edi = ddb_regs.edi;
	is->ds  = ddb_regs.ds & 0xffff;
	is->es  = ddb_regs.es & 0xffff;
	int_regs->fs = ddb_regs.fs & 0xffff;
	int_regs->gs = ddb_regs.gs & 0xffff;

kdb_exit:
	kdb_leave();
	current_cpu_datap()->cpu_kdb_saved_state = 0;

	enable_preemption();

	splx(s);
}

/*
 * Print trap reason.
 */

void
kdbprinttrap(
	int	type,
	int	code,
	int	*pc,
	int	sp)
{
	printf("kernel: ");
	if (type < 0 || type > TRAP_TYPES)
	    db_printf("type %d", type);
	else
	    db_printf("%s", trap_type[type]);
	db_printf(" trap, code=%x eip@%x = %x esp=%x\n",
		  code, pc, *(int *)pc, sp);
	db_run_mode = STEP_CONTINUE;
}

int
db_user_to_kernel_address(
	task_t		task,
	vm_offset_t	addr,
	unsigned	*kaddr,
	int		flag)
{
	register pt_entry_t *ptp;
	vm_offset_t src;

	/*
	 * must not pre-empted while using the pte pointer passed
	 * back since it's been mapped through a per-cpu window
	 */
        mp_disable_preemption();

	ptp = pmap_pte(task->map->pmap, (vm_map_offset_t)addr);
	if (ptp == PT_ENTRY_NULL || (*ptp & INTEL_PTE_VALID) == 0) {
	    if (flag) {
		db_printf("\nno memory is assigned to address %08x\n", addr);
		db_error(0);
		/* NOTREACHED */
	    }
	    mp_enable_preemption();
	    return(-1);
	}
	src = (vm_offset_t)pte_to_pa(*ptp);
	mp_enable_preemption();

	*(int *) DMAP1 = INTEL_PTE_VALID | INTEL_PTE_RW | (src & PG_FRAME) | 
	  INTEL_PTE_REF | INTEL_PTE_MOD;
#if defined(I386_CPU)
	if (cpu_class == CPUCLASS_386) {
		invltlb();
	} else
#endif
	{
		invlpg((u_int)DADDR1);
	}

	*kaddr = (unsigned)DADDR1 + (addr & PAGE_MASK);

	return(0);
}
	
/*
 * Read bytes from kernel address space for debugger.
 */

void
db_read_bytes(
	vm_offset_t	addr,
	int		size,
	char		*data,
	task_t		task)
{
	register char	*src;
	register int	n;
	unsigned	kern_addr;

	src = (char *)addr;
	if (task == kernel_task || task == TASK_NULL) {
	    while (--size >= 0) {
		if (addr++ > VM_MAX_KERNEL_ADDRESS) {
		    db_printf("\nbad address %x\n", addr);
		    db_error(0);
		    /* NOTREACHED */
		}
		*data++ = *src++;
	    }
	    return;
	}
	while (size > 0) {
	    if (db_user_to_kernel_address(task, addr, &kern_addr, 1) < 0)
		return;
	    src = (char *)kern_addr;
	    n = intel_trunc_page(addr+INTEL_PGBYTES) - addr;
	    if (n > size)
		n = size;
	    size -= n;
	    addr += n;
	    while (--n >= 0)
		*data++ = *src++;
	}
}

/*
 * Write bytes to kernel address space for debugger.
 */

void
db_write_bytes(
	vm_offset_t	addr,
	int		size,
	char		*data,
	task_t		task)
{
	register char	*dst;

	register pt_entry_t *ptep0 = 0;
	pt_entry_t	oldmap0 = 0;
	vm_offset_t	addr1;
	register pt_entry_t *ptep1 = 0;
	pt_entry_t	oldmap1 = 0;
	extern char	etext;

	if (task && task != kernel_task) {
	    db_write_bytes_user_space(addr, size, data, task);
	    return;
	}

	    
	if (addr >= VM_MIN_KERNEL_LOADED_ADDRESS) {
		db_write_bytes_user_space(addr, size, data, kernel_task);
		return;
	}

	if (addr >= VM_MIN_KERNEL_ADDRESS &&
	    addr <= (vm_offset_t)&etext)
	{
	    ptep0 = pmap_pte(kernel_pmap, (vm_map_offset_t)addr);
	    oldmap0 = *ptep0;
	    *ptep0 |= INTEL_PTE_WRITE;

	    addr1 = i386_trunc_page(addr + size - 1);
	    if (i386_trunc_page(addr) != addr1) {
		/* data crosses a page boundary */

		ptep1 = pmap_pte(kernel_pmap, (vm_map_offset_t)addr1);
		oldmap1 = *ptep1;
		*ptep1 |= INTEL_PTE_WRITE;
	    }
	    flush_tlb();
	} 

	dst = (char *)addr;

	while (--size >= 0) {
	    if (addr++ > VM_MAX_KERNEL_ADDRESS) {
		db_printf("\nbad address %x\n", addr);
		db_error(0);
		/* NOTREACHED */
	    }
	    *dst++ = *data++;
	}

	if (ptep0) {
	    *ptep0 = oldmap0;
	    if (ptep1) {
		*ptep1 = oldmap1;
	    }
	    flush_tlb();
	}
}
	
void
db_write_bytes_user_space(
	vm_offset_t	addr,
	int		size,
	char		*data,
	task_t		task)
{
	register char	*dst;
	register int	n;
	unsigned	kern_addr;

	while (size > 0) {
	    if (db_user_to_kernel_address(task, addr, &kern_addr, 1) < 0)
		return;
	    dst = (char *)kern_addr;
	    n = intel_trunc_page(addr+INTEL_PGBYTES) - addr;
	    if (n > size)
		n = size;
	    size -= n;
	    addr += n;
	    while (--n >= 0)
		*dst++ = *data++;
	}
}

boolean_t
db_check_access(
	vm_offset_t	addr,
	int		size,
	task_t		task)
{
	register	n;
	unsigned	kern_addr;

	if (task == kernel_task || task == TASK_NULL) {
	    if (kernel_task == TASK_NULL)
	        return(TRUE);
	    task = kernel_task;
	} else if (task == TASK_NULL) {
	    if (current_thread() == THREAD_NULL)
		return(FALSE);
	    task = current_thread()->task;
	}
	while (size > 0) {
	    if (db_user_to_kernel_address(task, addr, &kern_addr, 0) < 0)
		return(FALSE);
	    n = intel_trunc_page(addr+INTEL_PGBYTES) - addr;
	    if (n > size)
		n = size;
	    size -= n;
	    addr += n;
	}
	return(TRUE);
}

boolean_t
db_phys_eq(
	task_t		task1,
	vm_offset_t	addr1,
	task_t		task2,
	vm_offset_t	addr2)
{
	unsigned	kern_addr1, kern_addr2;

	if ((addr1 & (INTEL_PGBYTES-1)) != (addr2 & (INTEL_PGBYTES-1)))
	    return(FALSE);
	if (task1 == TASK_NULL) {
	    if (current_thread() == THREAD_NULL)
		return(FALSE);
	    task1 = current_thread()->task;
	}
	if (db_user_to_kernel_address(task1, addr1, &kern_addr1, 0) < 0 ||
		db_user_to_kernel_address(task2, addr2, &kern_addr2, 0) < 0)
	    return(FALSE);
	return(kern_addr1 == kern_addr2);
}

#define DB_USER_STACK_ADDR		(VM_MIN_KERNEL_ADDRESS)
#define DB_NAME_SEARCH_LIMIT		(DB_USER_STACK_ADDR-(INTEL_PGBYTES*3))

int
db_search_null(
	task_t		task,
	unsigned	*svaddr,
	unsigned	evaddr,
	unsigned	*skaddr,
	int		flag)
{
	register unsigned vaddr;
	register unsigned *kaddr;

	kaddr = (unsigned *)*skaddr;
	for (vaddr = *svaddr; vaddr > evaddr; vaddr -= sizeof(unsigned)) {
	    if (vaddr % INTEL_PGBYTES == 0) {
		vaddr -= sizeof(unsigned);
		if (db_user_to_kernel_address(task, vaddr, skaddr, 0) < 0)
		    return(-1);
		kaddr = (unsigned *)*skaddr;
	    } else {
		vaddr -= sizeof(unsigned);
		kaddr--;
	    }
	    if ((*kaddr == 0) ^ (flag  == 0)) {
		*svaddr = vaddr;
		*skaddr = (unsigned)kaddr;
		return(0);
	    }
	}
	return(-1);
}

void
db_task_name(
	task_t		task)
{
	register char *p;
	register n;
	unsigned vaddr, kaddr;

	vaddr = DB_USER_STACK_ADDR;
	kaddr = 0;

	/*
	 * skip nulls at the end
	 */
	if (db_search_null(task, &vaddr, DB_NAME_SEARCH_LIMIT, &kaddr, 0) < 0) {
	    db_printf(DB_NULL_TASK_NAME);
	    return;
	}
	/*
	 * search start of args
	 */
	if (db_search_null(task, &vaddr, DB_NAME_SEARCH_LIMIT, &kaddr, 1) < 0) {
	    db_printf(DB_NULL_TASK_NAME);
	    return;
	}

	n = DB_TASK_NAME_LEN-1;
	p = (char *)kaddr + sizeof(unsigned);
	for (vaddr += sizeof(int); vaddr < DB_USER_STACK_ADDR && n > 0; 
							vaddr++, p++, n--) {
	    if (vaddr % INTEL_PGBYTES == 0) {
		(void)db_user_to_kernel_address(task, vaddr, &kaddr, 0);
		p = (char*)kaddr;
	    }
	    db_printf("%c", (*p < ' ' || *p > '~')? ' ': *p);
	}
	while (n-- >= 0)	/* compare with >= 0 for one more space */
	    db_printf(" ");
}

void
db_machdep_init(void)
{
	int c;

	db_simple_lock_init(&kdb_lock, 0);
#if MACH_KDB /*this only works for legacy 32-bit machines */
	for (c = 0; c < real_ncpus; ++c) {
		if (c == master_cpu) {
			master_dbtss.esp0 = (int)(db_task_stack_store +
				(INTSTACK_SIZE * (c + 1)) - sizeof (natural_t));
			master_dbtss.esp = master_dbtss.esp0;
			master_dbtss.eip = (int)&db_task_start;
			/*
			 * The TSS for the debugging task on each slave CPU
			 * is set up in cpu_desc_init().
			 */
		}
	}
#endif
}

/*
 * Called when entering kdb:
 * Takes kdb lock. If if we were called remotely (slave state) we just
 * wait for kdb_cpu to be equal to cpu_number(). Otherwise enter kdb if
 * not active on another cpu.
 * If db_pass_thru[cpu_number()] > 0, then kdb can't stop now.
 */

int
kdb_enter(int pc)
{
	int my_cpu;
	int retval;

	disable_preemption();

	my_cpu = cpu_number();

	if (current_cpu_datap()->cpu_db_pass_thru) {
		retval = 0;
		goto kdb_exit;
	}

	current_cpu_datap()->cpu_kdb_active++;

	lock_kdb();

	db_printf("kdb_enter(): cpu_number %d, kdb_cpu %d\n", my_cpu, kdb_cpu);
	
	if (db_breakpoints_inserted)
		cpus_holding_bkpts++;

	if (kdb_cpu == -1 && !current_cpu_datap()->cpu_kdb_is_slave) {
		kdb_cpu = my_cpu;
		db_printf("Signaling other processors..\n");
		remote_kdb();	/* stop other cpus */
		retval = 1;
	} else if (kdb_cpu == my_cpu) 
		retval = 1;
	else
		retval = 0;

kdb_exit:
	enable_preemption();

	return (retval);
}

void
kdb_leave(void)
{
	int my_cpu;
	boolean_t	wait = FALSE;

	disable_preemption();

	my_cpu = cpu_number();

	if (db_run_mode == STEP_CONTINUE) {
		wait = TRUE;
		kdb_cpu = -1;
	}
	if (db_breakpoints_inserted)
		cpus_holding_bkpts--;
	if (current_cpu_datap()->cpu_kdb_is_slave)
		current_cpu_datap()->cpu_kdb_is_slave--;
	if (kdb_debug)
		db_printf("kdb_leave: cpu %d, kdb_cpu %d, run_mode %d pc %x (%x) holds %d\n",
			  my_cpu, kdb_cpu, db_run_mode,
			  ddb_regs.eip, *(int *)ddb_regs.eip,
			  cpus_holding_bkpts);
	clear_kdb_intr();
	unlock_kdb();
	current_cpu_datap()->cpu_kdb_active--;

	mp_kdb_exit();

	enable_preemption();

	if (wait) {
		while(cpus_holding_bkpts);
	}
}

void
lock_kdb(void)
{
	int		my_cpu;
	register	i;

	disable_preemption();

	my_cpu = cpu_number();

	for(;;) {
		if (kdb_cpu != -1 && kdb_cpu != my_cpu) {
			continue;
		}
		if (db_simple_lock_try(&kdb_lock)) {
			if (kdb_cpu == -1 || kdb_cpu == my_cpu)
				break;
			db_simple_unlock(&kdb_lock);
		}
	} 

	enable_preemption();
}

#if	TIME_STAMP
extern unsigned old_time_stamp;
#endif	/* TIME_STAMP */

void
unlock_kdb(void)
{
	db_simple_unlock(&kdb_lock);
#if	TIME_STAMP
	old_time_stamp = 0;
#endif	/* TIME_STAMP */
}


#ifdef	__STDC__
#define KDB_SAVE(type, name) extern type name; type name##_save = name
#define KDB_RESTORE(name) name = name##_save
#else	/* __STDC__ */
#define KDB_SAVE(type, name) extern type name; type name/**/_save = name
#define KDB_RESTORE(name) name = name/**/_save
#endif	/* __STDC__ */

#define KDB_SAVE_CTXT() \
	KDB_SAVE(int, db_run_mode); \
	KDB_SAVE(boolean_t, db_sstep_print); \
	KDB_SAVE(int, db_loop_count); \
	KDB_SAVE(int, db_call_depth); \
	KDB_SAVE(int, db_inst_count); \
	KDB_SAVE(int, db_last_inst_count); \
	KDB_SAVE(int, db_load_count); \
	KDB_SAVE(int, db_store_count); \
	KDB_SAVE(boolean_t, db_cmd_loop_done); \
	KDB_SAVE(jmp_buf_t *, db_recover); \
	KDB_SAVE(db_addr_t, db_dot); \
	KDB_SAVE(db_addr_t, db_last_addr); \
	KDB_SAVE(db_addr_t, db_prev); \
	KDB_SAVE(db_addr_t, db_next); \
	KDB_SAVE(db_regs_t, ddb_regs); 

#define KDB_RESTORE_CTXT() \
	KDB_RESTORE(db_run_mode); \
	KDB_RESTORE(db_sstep_print); \
	KDB_RESTORE(db_loop_count); \
	KDB_RESTORE(db_call_depth); \
	KDB_RESTORE(db_inst_count); \
	KDB_RESTORE(db_last_inst_count); \
	KDB_RESTORE(db_load_count); \
	KDB_RESTORE(db_store_count); \
	KDB_RESTORE(db_cmd_loop_done); \
	KDB_RESTORE(db_recover); \
	KDB_RESTORE(db_dot); \
	KDB_RESTORE(db_last_addr); \
	KDB_RESTORE(db_prev); \
	KDB_RESTORE(db_next); \
	KDB_RESTORE(ddb_regs); 

/*
 * switch to another cpu
 */

void
kdb_on(
	int		cpu)
{
	KDB_SAVE_CTXT();
	if (cpu < 0 || cpu >= real_ncpus || !cpu_datap(cpu)->cpu_kdb_active)
		return;
	db_set_breakpoints();
	db_set_watchpoints();
	kdb_cpu = cpu;
	unlock_kdb();
	lock_kdb();
	db_clear_breakpoints();
	db_clear_watchpoints();
	KDB_RESTORE_CTXT();
	if (kdb_cpu == -1)  {/* someone continued */
		kdb_cpu = cpu_number();
		db_continue_cmd(0, 0, 0, "");
	}
}

/*
 * system reboot
 */

extern void kdp_machine_reboot(void);

void db_reboot(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	kdp_machine_reboot();
}
