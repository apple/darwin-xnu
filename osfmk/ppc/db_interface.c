/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <cpus.h>
#include <platforms.h>
#include <time_stamp.h>
#include <mach_mp_debug.h>
#include <mach_ldebug.h>
#include <db_machine_commands.h>

#include <kern/spl.h>
#include <kern/cpu_number.h>
#include <kern/kern_types.h>
#include <kern/misc_protos.h>
#include <vm/pmap.h>

#include <ppc/mem.h>
#include <ppc/thread.h>
#include <ppc/db_machdep.h>
#include <ppc/trap.h>
#include <ppc/setjmp.h>
#include <ppc/pmap.h>
#include <ppc/misc_protos.h>
#include <ppc/exception.h>
#include <ppc/db_machdep.h>
#include <ppc/mappings.h>
#include <ppc/Firmware.h>

#include <mach/vm_param.h>
#include <mach/machine/vm_types.h>
#include <vm/vm_map.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/debug.h>

#include <ddb/db_command.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_run.h>
#include <ddb/db_trap.h>
#include <ddb/db_output.h>
#include <ddb/db_access.h>
#include <ddb/db_sym.h>
#include <ddb/db_break.h>
#include <ddb/db_watch.h>

struct	 savearea *ppc_last_saved_statep;
struct	 savearea ppc_nested_saved_state;
unsigned ppc_last_kdb_sp;

extern int debugger_active[NCPUS];		/* Debugger active on CPU */
extern int debugger_cpu;				/* Current cpu running debugger	*/

int		db_all_set_up = 0;


#if !MACH_KDP
void kdp_register_send_receive(void);
#endif

/*
 *	Enter KDB through a keyboard trap.
 *	We show the registers as of the keyboard interrupt
 *	instead of those at its call to KDB.
 */
struct int_regs {
	/* XXX more registers ? */
	struct ppc_interrupt_state *is;
};

extern char *	trap_type[];
extern int	TRAP_TYPES;

/*
 * Code used to synchronize kdb among all cpus, one active at a time, switch
 * from on to another using kdb_on! #cpu or cpu #cpu
 */

decl_simple_lock_data(, kdb_lock)	/* kdb lock			*/

#define	db_simple_lock_init(l, e)	hw_lock_init(&((l)->interlock))
#define	db_simple_lock_try(l)		hw_lock_try(&((l)->interlock))
#define	db_simple_unlock(l)		hw_lock_unlock(&((l)->interlock))

extern volatile unsigned int	cpus_holding_bkpts;	/* counter for number of cpus holding
						   breakpoints (ie: cpus that did not
						   insert back breakpoints) */
extern boolean_t	db_breakpoints_inserted;

/* Forward */

extern void	kdbprinttrap(
			int			type,
			int			code,
			int			*pc,
			int			sp);
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

#if DB_MACHINE_COMMANDS
struct db_command	ppc_db_commands[] = {
	{ "lt",		db_low_trace,	CS_MORE|CS_SET_DOT,	0 },
	{ (char *)0, 	0,		0,			0 }
};
#endif /* DB_MACHINE_COMMANDS */

#if !MACH_KDP
void kdp_register_send_receive(void) {}
#endif

extern jmp_buf_t *db_recover;
spl_t	saved_ipl[NCPUS];	/* just to know what IPL was before trap */
struct savearea *saved_state[NCPUS];

/*
 *  kdb_trap - field a TRACE or BPT trap
 */
void
kdb_trap(
	int			type,
	struct savearea *regs)
{
	boolean_t	trap_from_user;
	int			previous_console_device;
	int			code=0;

	previous_console_device=switch_to_serial_console();

	switch (type) {
	    case T_TRACE:	/* single_step */
	    case T_PROGRAM:	/* breakpoint */
#if 0
	    case T_WATCHPOINT:	/* watchpoint */
#endif
	    case -1:	/* keyboard interrupt */
		break;

	    default:
		if (db_recover) {
		    ppc_nested_saved_state = *regs;
		    db_printf("Caught ");
		    if (type > TRAP_TYPES)
			db_printf("type %d", type);
		    else
			db_printf("%s", trap_type[type]);
		    db_printf(" trap, pc = %x\n",
			      regs->save_srr0);
		    db_error("");
		    /*NOTREACHED*/
		}
		kdbprinttrap(type, code, (int *)&regs->save_srr0, regs->save_r1);
	}

	saved_state[cpu_number()] = regs;

	ppc_last_saved_statep = regs;
	ppc_last_kdb_sp = (unsigned) &type;

	if (!IS_USER_TRAP(regs)) {
		bzero((char *)&ddb_regs, sizeof (ddb_regs));
		ddb_regs = *regs;
		trap_from_user = FALSE;	

	}
	else {
		ddb_regs = *regs;
		trap_from_user = TRUE;
	}

	db_task_trap(type, code, trap_from_user);

	*regs = ddb_regs;

	if ((type == T_PROGRAM) &&
	    (db_get_task_value(regs->save_srr0,
			       BKPT_SIZE,
			       FALSE,
			       db_target_space(current_act(),
					       trap_from_user))
	                      == BKPT_INST))
	    regs->save_srr0 += BKPT_SIZE;

kdb_exit:
	saved_state[cpu_number()] = 0;
	switch_to_old_console(previous_console_device);

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
	if (type > TRAP_TYPES)
	    db_printf("type %d", type);
	else
	    db_printf("%s", trap_type[type]);
	db_printf(" trap, code=%x pc@%x = %x sp=%x\n",
		  code, pc, *(int *)pc, sp);
	db_run_mode = STEP_CONTINUE;
}

/*
 *
 */
vm_offset_t db_vtophys(
	pmap_t pmap,
	vm_offset_t va)
{
	register mapping	*mp;
	register vm_offset_t	pa;

	pa = (vm_offset_t)LRA(pmap->space,(void *)va);

	if (pa != 0)
		return(pa);

	mp = hw_lock_phys_vir(pmap->space, va);
	if((unsigned int)mp&1) {
		return 0;
	}

	if(!mp) {								/* If it was not a normal page */
		pa = hw_cvp_blk(pmap, va);			/* Try to convert odd-sized page (returns 0 if not found) */
		return pa;							/* Return physical address */
	}

	mp = hw_cpv(mp);						/* Convert to virtual address */

	if(!mp->physent) {
		pa = (vm_offset_t)((mp->PTEr & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));
	} else {
		pa = (vm_offset_t)((mp->physent->pte1 & -PAGE_SIZE) | ((unsigned int)va & (PAGE_SIZE-1)));
		hw_unlock_bit((unsigned int *)&mp->physent->phys_link, PHYS_LOCK);
	}

	return(pa);
}

int
db_user_to_kernel_address(
	task_t		task,
	vm_offset_t	addr,
	unsigned	*kaddr,
	int		flag)
{
	unsigned int	sr_val, raddr;

	raddr = (unsigned int)db_vtophys(task->map->pmap, trunc_page(addr));	/* Get the real address */

	if (!raddr) {
	    if (flag) {
		db_printf("\nno memory is assigned to address %08x\n", addr);
		db_error(0);
		/* NOTREACHED */
	    }
	    return -1;
	}
	sr_val = SEG_REG_PROT | task->map->pmap->space
		 | ((addr >> 8) & 0x00F00000);
		
	mtsr(SR_COPYIN_NUM, sr_val);
	sync();
	*kaddr = (addr & 0x0fffffff) | (SR_COPYIN_NUM << 28);
	return(0);
}
	
/*
 * Read bytes from task address space for debugger.
 */
void
db_read_bytes(
	vm_offset_t	addr,
	int		size,
	char		*data,
	task_t		task)
{
	int		n,max;
	unsigned	phys_dst;
	unsigned 	phys_src;
	pmap_t	pmap;
	
	while (size > 0) {
		if (task != NULL)
			pmap = task->map->pmap;
		else
			pmap = kernel_pmap;

		phys_src = (unsigned int)db_vtophys(pmap, trunc_page(addr));  
		if (phys_src == 0) {
			db_printf("\nno memory is assigned to src address %08x\n",
				  addr);
			db_error(0);
			/* NOTREACHED */
		}
		phys_src = phys_src| (addr & page_mask);

		phys_dst = (unsigned int)db_vtophys(kernel_pmap, trunc_page(data)); 
		if (phys_dst == 0) {
			db_printf("\nno memory is assigned to dst address %08x\n",
				  data);
			db_error(0);
			/* NOTREACHED */
		}
		
		phys_dst = phys_dst | (((vm_offset_t) data) & page_mask);

		/* don't over-run any page boundaries - check src range */
		max = ppc_round_page(phys_src) - phys_src;
		if (max > size)
			max = size;
		/* Check destination won't run over boundary either */
		n = ppc_round_page(phys_dst) - phys_dst;
		if (n < max)
			max = n;
		size -= max;
		addr += max;
		phys_copy(phys_src, phys_dst, max);

		/* resync I+D caches */
		sync_cache(phys_dst, max);

		phys_src += max;
		phys_dst += max;
	}
}

/*
 * Write bytes to task address space for debugger.
 */
void
db_write_bytes(
	vm_offset_t	addr,
	int		size,
	char		*data,
	task_t		task)
{
	int		n,max;
	unsigned	phys_dst;
	unsigned 	phys_src;
	pmap_t	pmap;
	
	while (size > 0) {

		phys_src = (unsigned int)db_vtophys(kernel_pmap, trunc_page(data)); 
		if (phys_src == 0) {
			db_printf("\nno memory is assigned to src address %08x\n",
				  data);
			db_error(0);
			/* NOTREACHED */
		}
		
		phys_src = phys_src | (((vm_offset_t) data) & page_mask);

		/* space stays as kernel space unless in another task */
		if (task == NULL) pmap = kernel_pmap;
		else pmap = task->map->pmap;

		phys_dst = (unsigned int)db_vtophys(pmap, trunc_page(addr));  
		if (phys_dst == 0) {
			db_printf("\nno memory is assigned to dst address %08x\n",
				  addr);
			db_error(0);
			/* NOTREACHED */
		}
		phys_dst = phys_dst| (addr & page_mask);

		/* don't over-run any page boundaries - check src range */
		max = ppc_round_page(phys_src) - phys_src;
		if (max > size)
			max = size;
		/* Check destination won't run over boundary either */
		n = ppc_round_page(phys_dst) - phys_dst;
		if (n < max)
			max = n;
		size -= max;
		addr += max;
		phys_copy(phys_src, phys_dst, max);

		/* resync I+D caches */
		sync_cache(phys_dst, max);

		phys_src += max;
		phys_dst += max;
	}
}
	
boolean_t
db_check_access(
	vm_offset_t	addr,
	int		size,
	task_t		task)
{
	register int	n;
	unsigned int	kern_addr;

	if (task == kernel_task || task == TASK_NULL) {
	    if (kernel_task == TASK_NULL)
	        return(TRUE);
	    task = kernel_task;
	} else if (task == TASK_NULL) {
	    if (current_act() == THR_ACT_NULL)
		return(FALSE);
	    task = current_act()->task;
	}
	while (size > 0) {
	    if (db_user_to_kernel_address(task, addr, &kern_addr, 0) < 0)
		return(FALSE);
	    n = ppc_trunc_page(addr+PPC_PGBYTES) - addr;
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
	vm_offset_t	physa, physb;

	if ((addr1 & (PPC_PGBYTES-1)) != (addr2 & (PPC_PGBYTES-1)))	/* Is byte displacement the same? */
		return FALSE;

	if (task1 == TASK_NULL) {						/* See if there is a task active */
		if (current_act() == THR_ACT_NULL)			/* See if there is a current task */
			return FALSE;
		task1 = current_act()->task;				/* If so, use that one */
	}
	
	if(!(physa = db_vtophys(task1->map->pmap, trunc_page(addr1)))) return FALSE;	/* Get real address of the first */
	if(!(physb = db_vtophys(task2->map->pmap, trunc_page(addr2)))) return FALSE;	/* Get real address of the second */
	
	return (physa == physb);						/* Check if they are equal, then return... */
}

#define DB_USER_STACK_ADDR		(0xc0000000)
#define DB_NAME_SEARCH_LIMIT		(DB_USER_STACK_ADDR-(PPC_PGBYTES*3))

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
	for (vaddr = *svaddr; vaddr > evaddr; ) {
	    if (vaddr % PPC_PGBYTES == 0) {
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
	register int n;
	unsigned int vaddr, kaddr;

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
	    if (vaddr % PPC_PGBYTES == 0) {
		if (db_user_to_kernel_address(task, vaddr, &kaddr, 0) <0)
			return;
		p = (char*)kaddr;
	    }
	    db_printf("%c", (*p < ' ' || *p > '~')? ' ': *p);
	}
	while (n-- >= 0)	/* compare with >= 0 for one more space */
	    db_printf(" ");
}

void
db_machdep_init(void) {
#define KDB_READY       0x1
	extern int     kdb_flag;  

	kdb_flag |= KDB_READY;
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
	if (cpu < 0 || cpu >= NCPUS || !debugger_active[cpu])
		return;
	db_set_breakpoints();
	db_set_watchpoints();
	debugger_cpu = cpu;
	unlock_debugger();
	lock_debugger();
	db_clear_breakpoints();
	db_clear_watchpoints();
	KDB_RESTORE_CTXT();
	if (debugger_cpu == -1)  {/* someone continued */
		debugger_cpu = cpu_number();
		db_continue_cmd(0, 0, 0, "");
	}
}

/*
 * system reboot
 */
void db_reboot(
	db_expr_t	addr,
	boolean_t	have_addr,
	db_expr_t	count,
	char		*modif)
{
	boolean_t	reboot = TRUE;
	char		*cp, c;
	
	cp = modif;
	while ((c = *cp++) != 0) {
		if (c == 'r')	/* reboot */
			reboot = TRUE;
		if (c == 'h')	/* halt */
			reboot = FALSE;
	}
	halt_all_cpus(reboot);
}

/*
 * Switch to gdb
 */
void
db_to_gdb(
	void)
{
	extern unsigned int switch_debugger;

	switch_debugger=1;
}
