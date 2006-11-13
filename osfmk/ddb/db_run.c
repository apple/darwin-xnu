/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * 	Author: David B. Golub, Carnegie Mellon University
 *	Date:	7/90
 */

/*
 * Commands to run process.
 */
#include <mach/boolean.h>
#include <machine/db_machdep.h>

#include <ddb/db_lex.h>
#include <ddb/db_break.h>
#include <ddb/db_access.h>
#include <ddb/db_run.h>
#include <ddb/db_cond.h>
#include <ddb/db_examine.h>
#include <ddb/db_output.h>		/* For db_printf() */
#include <ddb/db_watch.h>
#include <kern/misc_protos.h>
#include <kern/debug.h>

#include <IOKit/IOPlatformExpert.h>

boolean_t	db_sstep_print;
int		db_loop_count;
int		db_call_depth;

int		db_inst_count;
int		db_last_inst_count;
int		db_load_count;
int		db_store_count;
int		db_max_inst_count = 1000;

#ifndef db_set_single_step
void db_set_task_single_step(
	register db_regs_t	*regs,
	task_t		   	task);
#else
#define	db_set_task_single_step(regs,task)	db_set_single_step(regs)
#endif
#ifndef db_clear_single_step
void db_clear_task_single_step(
	db_regs_t	*regs,
	task_t	  	task);
#else
#define db_clear_task_single_step(regs,task)	db_clear_single_step(regs)
#endif

extern jmp_buf_t *db_recover;
boolean_t db_step_again(void);

boolean_t
db_stop_at_pc(
	boolean_t	*is_breakpoint,
	task_t		task,
	task_t		space)
{
	register  db_addr_t	pc;
	register  db_thread_breakpoint_t bkpt;

	db_clear_task_single_step(DDB_REGS, space);
	db_clear_breakpoints();
	db_clear_watchpoints();
	pc = PC_REGS(DDB_REGS);

#ifdef	FIXUP_PC_AFTER_BREAK
	if (*is_breakpoint) {
	    /*
	     * Breakpoint trap.  Fix up the PC if the
	     * machine requires it.
	     */
	    FIXUP_PC_AFTER_BREAK
	    pc = PC_REGS(DDB_REGS);
	}
#endif

	/*
	 * Now check for a breakpoint at this address.
	 */
	bkpt = db_find_thread_breakpoint_here(space, pc);
	if (bkpt) {
	    if (db_cond_check(bkpt)) {
		*is_breakpoint = TRUE;
		return (TRUE);	/* stop here */
	    }
	}
	*is_breakpoint = FALSE;

	if (db_run_mode == STEP_INVISIBLE) {
	    db_run_mode = STEP_CONTINUE;
	    return (FALSE);	/* continue */
	}
	if (db_run_mode == STEP_COUNT) {
	    return (FALSE); /* continue */
	}
	if (db_run_mode == STEP_ONCE) {
	    if (--db_loop_count > 0) {
		if (db_sstep_print) {
		    db_print_loc_and_inst(pc, task);
		}
		return (FALSE);	/* continue */
	    }
	}
	if (db_run_mode == STEP_RETURN) {
	    jmp_buf_t *prev;
	    jmp_buf_t db_jmpbuf;
	    /* WARNING: the following assumes an instruction fits an int */
	    db_expr_t ins = db_get_task_value(pc, sizeof(int), FALSE, space);

	    /* continue until matching return */

	    prev = db_recover;
	    if (_setjmp(db_recover = &db_jmpbuf) == 0) {
	    	if (!inst_trap_return(ins) &&
		    (!inst_return(ins) || --db_call_depth != 0)) {
			if (db_sstep_print) {
		    	    if (inst_call(ins) || inst_return(ins)) {
				register int i;

				db_printf("[after %6d /%4d] ",
					  db_inst_count,
					  db_inst_count - db_last_inst_count);
				db_last_inst_count = db_inst_count;
				for (i = db_call_depth; --i > 0; )
				    db_printf("  ");
				db_print_loc_and_inst(pc, task);
				db_printf("\n");
		    	    }
		        }
			if (inst_call(ins))
			    db_call_depth++;
			db_recover = prev;
			if (db_step_again())
				return (FALSE);	/* continue */
	        }
	    }
	    db_recover = prev;
	}
	if (db_run_mode == STEP_CALLT) {
	    /* WARNING: the following assumes an instruction fits an int */
	    db_expr_t ins = db_get_task_value(pc, sizeof(int), FALSE, space);

	    /* continue until call or return */

	    if (!inst_call(ins) &&
		!inst_return(ins) &&
		!inst_trap_return(ins)) {
			if (db_step_again())
				return (FALSE);	/* continue */
	    }
	}
	if (db_find_breakpoint_here(space, pc))
		return(FALSE);
	db_run_mode = STEP_NONE;
	return (TRUE);
}

void
db_restart_at_pc(
	boolean_t	watchpt,
	task_t	  	task)
{
	register db_addr_t pc = PC_REGS(DDB_REGS), brpc;

	if ((db_run_mode == STEP_COUNT) ||
	    (db_run_mode == STEP_RETURN) ||
	    (db_run_mode == STEP_CALLT)) {
	    db_expr_t		ins;

	    /*
	     * We are about to execute this instruction,
	     * so count it now.
	     */

	    ins = db_get_task_value(pc, sizeof(int), FALSE, task);
	    db_inst_count++;
	    db_load_count += db_inst_load(ins);
	    db_store_count += db_inst_store(ins);
#ifdef	SOFTWARE_SSTEP
	    /* Account for instructions in delay slots */
	    brpc = next_instr_address(pc,1,task);
	    if ((brpc != pc) && (inst_branch(ins) || inst_call(ins))) {
		/* Note: this ~assumes an instruction <= sizeof(int) */
		ins = db_get_task_value(brpc, sizeof(int), FALSE, task);
		db_inst_count++;
		db_load_count += db_inst_load(ins);
		db_store_count += db_inst_store(ins);
	    }
#endif	/* SOFTWARE_SSTEP */
	}

	if (db_run_mode == STEP_CONTINUE) {
	    if (watchpt || db_find_breakpoint_here(task, pc)) {
		/*
		 * Step over breakpoint/watchpoint.
		 */
		db_run_mode = STEP_INVISIBLE;
		db_set_task_single_step(DDB_REGS, task);
	    } else {
		db_set_breakpoints();
		db_set_watchpoints();
	    }
	} else {
	    db_set_task_single_step(DDB_REGS, task);
	}
}

/*
 * 'n' and 'u' commands might never return.
 * Limit the maximum number of steps.
 */

boolean_t
db_step_again(void)
{
	if (db_inst_count && !(db_inst_count%db_max_inst_count)) {
		char c;
		db_printf("%d instructions, continue ? (y/n) ",
			  db_inst_count);
	        c = cngetc();
		db_printf("\n");
		if(c == 'n')
			return(FALSE);
	}
	return(TRUE);
}

void
db_single_step(
	db_regs_t	*regs,
	task_t	  	task)
{
	if (db_run_mode == STEP_CONTINUE) {
	    db_run_mode = STEP_INVISIBLE;
	    db_set_task_single_step(regs, task);
	}
}

#ifdef	SOFTWARE_SSTEP
/*
 *	Software implementation of single-stepping.
 *	If your machine does not have a trace mode
 *	similar to the vax or sun ones you can use
 *	this implementation, done for the mips.
 *	Just define the above conditional and provide
 *	the functions/macros defined below.
 *
 * extern boolean_t
 *	inst_branch(),		returns true if the instruction might branch
 * extern unsigned
 *	branch_taken(),		return the address the instruction might
 *				branch to
 *	db_getreg_val();	return the value of a user register,
 *				as indicated in the hardware instruction
 *				encoding, e.g. 8 for r8
 *			
 * next_instr_address(pc,bd,task) returns the address of the first
 *				instruction following the one at "pc",
 *				which is either in the taken path of
 *				the branch (bd==1) or not.  This is
 *				for machines (mips) with branch delays.
 *
 *	A single-step may involve at most 2 breakpoints -
 *	one for branch-not-taken and one for branch taken.
 *	If one of these addresses does not already have a breakpoint,
 *	we allocate a breakpoint and save it here.
 *	These breakpoints are deleted on return.
 */			
db_breakpoint_t	db_not_taken_bkpt = 0;
db_breakpoint_t	db_taken_bkpt = 0;

db_breakpoint_t
db_find_temp_breakpoint(
	task_t		   task,
	db_addr_t	   addr)
{
	if (db_taken_bkpt && (db_taken_bkpt->address == addr) &&
	    db_taken_bkpt->task == task)
		return db_taken_bkpt;
	if (db_not_taken_bkpt && (db_not_taken_bkpt->address == addr) &&
	    db_not_taken_bkpt->task == task)
		return db_not_taken_bkpt;
	return 0;
}

void
db_set_task_single_step(
	register db_regs_t	*regs,
	task_t		   	task)
{
	db_addr_t pc = PC_REGS(regs), brpc;
	register unsigned int	 inst;
	register boolean_t       unconditional;

	/*
	 *	User was stopped at pc, e.g. the instruction
	 *	at pc was not executed.
	 */
	inst = db_get_task_value(pc, sizeof(int), FALSE, task);
	if (inst_branch(inst) || inst_call(inst)) {
	    extern db_expr_t getreg_val();	/* XXX -- need prototype! */

	    brpc = branch_taken(inst, pc, getreg_val, (unsigned char*)regs);
	    if (brpc != pc) {	/* self-branches are hopeless */
		db_taken_bkpt = db_set_temp_breakpoint(task, brpc);
	    } else
	        db_taken_bkpt = 0;
	    pc = next_instr_address(pc,1,task);
	} else 
	    pc = next_instr_address(pc,0,task);
	
	/* 
	 * check if this control flow instruction is an
	 * unconditional transfer
	 */

	unconditional = inst_unconditional_flow_transfer(inst);

	/* 
	  We only set the sequential breakpoint if previous instruction was not
	  an unconditional change of flow of control. If the previous instruction
	  is an unconditional change of flow of control, setting a breakpoint in the
	  next sequential location may set a breakpoint in data or in another routine,
	  which could screw up either the program or the debugger. 
	  (Consider, for instance, that the next sequential instruction is the 
	  start of a routine needed by the debugger.)
	*/
	if (!unconditional && db_find_breakpoint_here(task, pc) == 0 &&
	    (db_taken_bkpt == 0 || db_taken_bkpt->address != pc)) {
	    	db_not_taken_bkpt = db_set_temp_breakpoint(task, pc);
	} else
	    	db_not_taken_bkpt = 0;
}

void
db_clear_task_single_step(
	db_regs_t	*regs,
	task_t	  	task)
{
	if (db_taken_bkpt != 0) {
	    db_delete_temp_breakpoint(task, db_taken_bkpt);
	    db_taken_bkpt = 0;
	}
	if (db_not_taken_bkpt != 0) {
	    db_delete_temp_breakpoint(task, db_not_taken_bkpt);
	    db_not_taken_bkpt = 0;
	}
}

#endif	/* SOFTWARE_SSTEP */

extern int	db_cmd_loop_done;

/* single-step */
void
db_single_step_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	boolean_t	print = FALSE;

	if (count == -1)
	    count = 1;

	if (modif[0] == 'p')
	    print = TRUE;

	db_run_mode = STEP_ONCE;
	db_loop_count = count;
	db_sstep_print = print;
	db_inst_count = 0;
	db_last_inst_count = 0;
	db_load_count = 0;
	db_store_count = 0;

	db_cmd_loop_done = 1;
}

/* trace and print until call/return */
void
db_trace_until_call_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	boolean_t	print = FALSE;

	if (modif[0] == 'p')
	    print = TRUE;

	db_run_mode = STEP_CALLT;
	db_sstep_print = print;
	db_inst_count = 0;
	db_last_inst_count = 0;
	db_load_count = 0;
	db_store_count = 0;

	db_cmd_loop_done = 1;
}

void
db_trace_until_matching_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	boolean_t	print = FALSE;

	if (modif[0] == 'p')
	    print = TRUE;

	db_run_mode = STEP_RETURN;
	db_call_depth = 1;
	db_sstep_print = print;
	db_inst_count = 0;
	db_last_inst_count = 0;
	db_load_count = 0;
	db_store_count = 0;

	db_cmd_loop_done = 1;
}

/* continue */
void
db_continue_cmd(
	db_expr_t	addr,
	int		have_addr,
	db_expr_t	count,
	char *		modif)
{
	/*
	 * Though "cont/c" works fairly well, it's not really robust
	 * enough to use in arbitrary situations, so disable it.
	 * (Doesn't seem cost-effective to debug and fix what ails
	 * it.)
	 */
#if 0
	if (modif[0] == 'c')
	    db_run_mode = STEP_COUNT;
	else
	    db_run_mode = STEP_CONTINUE;
#else
	db_run_mode = STEP_CONTINUE;
#endif
	db_inst_count = 0;
	db_last_inst_count = 0;
	db_load_count = 0;
	db_store_count = 0;

	db_cmd_loop_done = 1;
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

/* gdb */
void    
db_continue_gdb(
	db_expr_t	addr, 
	int		have_addr,
	db_expr_t	count,   
	char *		modif)
{
	db_to_gdb();
	db_run_mode = STEP_CONTINUE;
	db_inst_count = 0;
	db_last_inst_count = 0;   
	db_load_count = 0;
	db_store_count = 0;  

	db_cmd_loop_done = 1;
}
        

boolean_t
db_in_single_step(void)
{
	return(db_run_mode != STEP_NONE && db_run_mode != STEP_CONTINUE);
}

