/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

#ifndef	_I386_DB_MACHDEP_H_
#define	_I386_DB_MACHDEP_H_

/*
 * Machine-dependent defines for new kernel debugger.
 */

#include <kern/kern_types.h>
#include <mach/i386/vm_types.h>
#include <mach/i386/vm_param.h>
#include <i386/thread.h>		/* for thread_status */
#include <i386/eflags.h>
#include <i386/trap.h>
#include <i386/pmCPU.h>
#include <i386/hpet.h>

typedef	addr64_t	db_addr_t;	/* address - unsigned */
typedef	uint64_t	db_expr_t;	/* expression */

typedef struct x86_saved_state32 db_regs_t;
db_regs_t	ddb_regs;	/* register state */
#define	DDB_REGS	(&ddb_regs)
extern int	db_active;	/* ddb is active */

#define	PC_REGS(regs)	((db_addr_t)(regs)->eip)

#define	BKPT_INST	0xcc		/* breakpoint instruction */
#define	BKPT_SIZE	(1)		/* size of breakpoint inst */
#define	BKPT_SET(inst)	(BKPT_INST)

#define	FIXUP_PC_AFTER_BREAK	ddb_regs.eip -= 1;

#define	db_clear_single_step(regs)	((regs)->efl &= ~EFL_TF)
#define	db_set_single_step(regs)	((regs)->efl |=  EFL_TF)

#define	IS_BREAKPOINT_TRAP(type, code)	((type) == T_INT3)
#define IS_WATCHPOINT_TRAP(type, code)	((type) == T_WATCHPOINT)

#define	I_CALL		0xe8
#define	I_CALLI		0xff
#define	I_RET		0xc3
#define	I_IRET		0xcf

#define	inst_trap_return(ins)	(((ins)&0xff) == I_IRET)
#define	inst_return(ins)	(((ins)&0xff) == I_RET)
#define	inst_call(ins)		(((ins)&0xff) == I_CALL || \
				 (((ins)&0xff) == I_CALLI && \
				  ((ins)&0x3800) == 0x1000))

int db_inst_load(unsigned long);
int db_inst_store(unsigned long);

/* access capability and access macros */

#define DB_ACCESS_LEVEL		2	/* access any space */
#define DB_CHECK_ACCESS(addr,size,task)				\
	db_check_access(addr,size,task)
#define DB_PHYS_EQ(task1,addr1,task2,addr2)			\
	db_phys_eq(task1,addr1,task2,addr2)
#define DB_VALID_KERN_ADDR(addr)		(1)
#define DB_VALID_ADDRESS(addr,user)				\
	((!(user) && DB_VALID_KERN_ADDR(addr)) ||		\
	 ((user) && (addr) < VM_MAX_ADDRESS))

/*
 * Given pointer to i386_saved_state, determine if it represents
 * a thread executing in user space.
 */
#define IS_USER_TRAP(regs, etext)	(((regs)->cs & 3) != 0)

extern boolean_t	db_check_access(
				vm_offset_t	addr,
				int		size,
				task_t		task);
extern boolean_t	db_phys_eq(
				task_t		task1,
				vm_offset_t	addr1,
				task_t		task2,
				vm_offset_t	addr2);
extern db_addr_t	db_disasm(
				db_addr_t	loc,
				boolean_t	altfmt,
				task_t		task);
extern void		db_read_bytes(
				vm_offset_t	addr,
				int		size,
				char		*data,
				task_t		task);
extern void		db_write_bytes(
				vm_offset_t	addr,
				int		size,
				char		*data,
				task_t		task);
extern void		db_stack_trace_cmd(
				db_expr_t	addr,
				boolean_t	have_addr,
				db_expr_t	count,
				char		*modif);
extern void		db_reboot(
				db_expr_t	addr,
				boolean_t	have_addr,
				db_expr_t	count,
				char		*modif);

extern void db_display_kmod(db_expr_t addr, boolean_t have_addr,
			    db_expr_t count, char *modif);
extern void db_display_real(db_expr_t addr, boolean_t have_addr,
			    db_expr_t count, char *modif);
extern void db_display_iokit(db_expr_t addr, boolean_t have_addr,
			     db_expr_t count, char * modif);
extern void db_cpuid(db_expr_t addr, boolean_t have_addr, db_expr_t count,
		     char *modif);
extern void db_msr(db_expr_t addr, boolean_t have_addr, db_expr_t count,
		   char *modif);
extern void db_apic(db_expr_t addr, boolean_t have_addr, db_expr_t count,
		    char *modif);
extern void db_display_hpet(hpetReg_t *);
extern void db_hpet(db_expr_t addr, boolean_t have_addr, db_expr_t count,
		    char *modif);

/* macros for printing OS server dependent task name */

#define DB_TASK_NAME(task)	db_task_name(task)
#define DB_TASK_NAME_TITLE	"COMMAND                "
#define DB_TASK_NAME_LEN	23
#define DB_NULL_TASK_NAME	"?                      "

extern void		db_task_name(
				task_t			task);

/* macro for checking if a thread has used floating-point */

#define db_act_fp_used(act)	(act && act->machine.pcb->ifps)

extern void		db_tss_to_frame(
				int			tss_sel,
				x86_saved_state32_t	*regs);
extern int		kdb_trap(
				int			type,
				int			code,
				x86_saved_state32_t	*regs);
extern boolean_t	db_trap_from_asm(
				x86_saved_state32_t *regs);
extern void		kdb_on(
				int			cpu);

#if MACH_KDB
extern void db_getpmgr(pmData_t *pmj);
extern void db_chkpmgr(void);
#endif /* MACH_KDB */
extern void db_pmgr(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
extern void db_nap(db_expr_t addr, int have_addr, db_expr_t count, char * modif);

#endif	/* _I386_DB_MACHDEP_H_ */
