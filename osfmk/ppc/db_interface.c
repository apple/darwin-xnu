/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

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
#include <ppc/db_machdep.h>
#include <ppc/trap.h>
#include <ppc/setjmp.h>
#include <ppc/pmap.h>
#include <ppc/misc_protos.h>
#include <ppc/cpu_internal.h>
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
#include <pexpert/pexpert.h>
#include <IOKit/IOPlatformExpert.h>

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
		    db_printf(" trap, pc = %llx\n",
			      regs->save_srr0);
		    db_error("");
		    /*NOTREACHED*/
		}
		kdbprinttrap(type, code, (int *)&regs->save_srr0, regs->save_r1);
	}

	getPerProc()->db_saved_state = regs;

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
			       db_target_space(current_thread(),
					       trap_from_user))
	                      == BKPT_INST))
	    regs->save_srr0 += BKPT_SIZE;

kdb_exit:
	getPerProc()->db_saved_state = 0;
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
addr64_t db_vtophys(
	pmap_t pmap,
	vm_offset_t va)
{
	ppnum_t pp;
	addr64_t pa;

	pp = pmap_find_phys(pmap, (addr64_t)va);

	if (pp == 0) return(0);					/* Couldn't find it */
	
	pa = ((addr64_t)pp << 12) | (addr64_t)(va & 0xFFF);	/* Get physical address */

	return(pa);
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
	addr64_t	phys_dst;
	addr64_t 	phys_src;
	pmap_t	pmap;
	
	while (size > 0) {
		if (task != NULL)
			pmap = task->map->pmap;
		else
			pmap = kernel_pmap;

		phys_src = db_vtophys(pmap, (vm_offset_t)addr);  
		if (phys_src == 0) {
			db_printf("\nno memory is assigned to src address %08x\n",
				  addr);
			db_error(0);
			/* NOTREACHED */
		}

		phys_dst = db_vtophys(kernel_pmap, (vm_offset_t)data); 
		if (phys_dst == 0) {
			db_printf("\nno memory is assigned to dst address %08x\n",
				  data);
			db_error(0);
			/* NOTREACHED */
		}
		
		/* don't over-run any page boundaries - check src range */
		max = round_page_64(phys_src + 1) - phys_src;
		if (max > size)
			max = size;
		/* Check destination won't run over boundary either */
		n = round_page_64(phys_dst + 1) - phys_dst;
		
		if (n < max) max = n;
		size -= max;
		addr += max;
		phys_copy(phys_src, phys_dst, max);

		/* resync I+D caches */
		sync_cache64(phys_dst, max);

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
	addr64_t	phys_dst;
	addr64_t 	phys_src;
	pmap_t	pmap;
	
	while (size > 0) {

		phys_src = db_vtophys(kernel_pmap, (vm_offset_t)data); 
		if (phys_src == 0) {
			db_printf("\nno memory is assigned to src address %08x\n",
				  data);
			db_error(0);
			/* NOTREACHED */
		}
		
		/* space stays as kernel space unless in another task */
		if (task == NULL) pmap = kernel_pmap;
		else pmap = task->map->pmap;

		phys_dst = db_vtophys(pmap, (vm_offset_t)addr);  
		if (phys_dst == 0) {
			db_printf("\nno memory is assigned to dst address %08x\n",
				  addr);
			db_error(0);
			/* NOTREACHED */
		}

		/* don't over-run any page boundaries - check src range */
		max = round_page_64(phys_src + 1) - phys_src;
		if (max > size)
			max = size;
		/* Check destination won't run over boundary either */
		n = round_page_64(phys_dst + 1) - phys_dst;
		if (n < max)
			max = n;
		size -= max;
		addr += max;
		phys_copy(phys_src, phys_dst, max);

		/* resync I+D caches */
		sync_cache64(phys_dst, max);

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
	    if (kernel_task == TASK_NULL)  return(TRUE);
	    task = kernel_task;
	} else if (task == TASK_NULL) {
	    if (current_thread() == THR_ACT_NULL) return(FALSE);
	    task = current_thread()->task;
	}

	while (size > 0) {
		if(!pmap_find_phys(task->map->pmap, (addr64_t)addr)) return (FALSE);	/* Fail if page not mapped */
	    n = trunc_page_32(addr+PPC_PGBYTES) - addr;
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
	addr64_t	physa, physb;

	if ((addr1 & (PPC_PGBYTES-1)) != (addr2 & (PPC_PGBYTES-1)))	/* Is byte displacement the same? */
		return FALSE;

	if (task1 == TASK_NULL) {						/* See if there is a task active */
		if (current_thread() == THR_ACT_NULL)		/* See if there is a current task */
			return FALSE;
		task1 = current_thread()->task;				/* If so, use that one */
	}
	
	if(!(physa = db_vtophys(task1->map->pmap, (vm_offset_t)trunc_page_32(addr1)))) return FALSE;	/* Get real address of the first */
	if(!(physb = db_vtophys(task2->map->pmap, (vm_offset_t)trunc_page_32(addr2)))) return FALSE;	/* Get real address of the second */
	
	return (physa == physb);						/* Check if they are equal, then return... */
}

#define DB_USER_STACK_ADDR		(0xc0000000)
#define DB_NAME_SEARCH_LIMIT		(DB_USER_STACK_ADDR-(PPC_PGBYTES*3))

boolean_t	db_phys_cmp(
				vm_offset_t a1, 
				vm_offset_t a2, 
				vm_size_t s1) {

	db_printf("db_phys_cmp: not implemented\n");
	return 0;
}


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

	db_printf("db_search_null: not implemented\n");

	return(-1);
}

unsigned char *getProcName(struct proc *proc);

void
db_task_name(
	task_t		task)
{
	register unsigned char *p;
	register int n;
	unsigned int vaddr, kaddr;
	unsigned char tname[33];
	int i;

	p = 0;
	tname[0] = 0;
	
	if(task->bsd_info) p = getProcName((struct proc *)(task->bsd_info));	/* Point to task name */
	
	if(p) {
		for(i = 0; i < 32; i++) {			/* Move no more than 32 bytes */
			tname[i] = p[i];
			if(p[i] == 0) break;
		}
		tname[i] = 0;
		db_printf("%s", tname);
	}
	else db_printf("no name");
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
	if (cpu < 0 || cpu >= real_ncpus || !PerProcTable[cpu].ppe_vaddr->debugger_active)
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

extern int (*PE_halt_restart)(unsigned int type);

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
	if(!reboot) halt_all_cpus(FALSE);	/* If no reboot, try to be clean about it */

	if (PE_halt_restart) return (*PE_halt_restart)(kPERestartCPU);
	db_printf("Sorry, system can't reboot automatically yet...  You need to do it by hand...\n");

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
