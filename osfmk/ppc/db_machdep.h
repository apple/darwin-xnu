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

#ifndef	_PPC_DB_MACHDEP_H_
#define	_PPC_DB_MACHDEP_H_

/*
 * Machine-dependent defines for new kernel debugger.
 */

#include <kern/kern_types.h>
#include <mach/ppc/vm_types.h>
#include <mach/ppc/vm_param.h>
#include <kern/thread.h>
#include <ppc/trap.h>
#include <ppc/proc_reg.h>
#include <ppc/savearea.h>

typedef	addr64_t db_addr_t;	/* address - unsigned */
typedef	uint64_t db_expr_t;	/* expression - signed???  try unsigned */

typedef struct savearea db_regs_t;
db_regs_t	ddb_regs;	/* register state */
#define	DDB_REGS	(&ddb_regs)
extern int	db_active;	/* ddb is active */

#define	PC_REGS(regs)	((db_addr_t)(regs)->save_srr0)

#define	BKPT_INST	0x7c810808	/* breakpoint instruction */
#define	BKPT_SIZE	(4)		/* size of breakpoint inst */
#define	BKPT_SET(inst)	(BKPT_INST)

#define db_clear_single_step(regs)	((regs)->save_srr1 &= ~MASK(MSR_SE))
#define db_set_single_step(regs)	((regs)->save_srr1 |= MASK(MSR_SE))

#define	IS_BREAKPOINT_TRAP(type, code)	(FALSE)
#define IS_WATCHPOINT_TRAP(type, code)	(FALSE)

#define	inst_trap_return(ins)	(FALSE)
#define	inst_return(ins)	(FALSE)
#define	inst_call(ins)		(FALSE)

int db_inst_load(unsigned long);
int db_inst_store(unsigned long);

/* access capability and access macros */

#define DB_ACCESS_LEVEL	DB_ACCESS_ANY	/* any space */
#define DB_CHECK_ACCESS(addr,size,task)				\
	db_check_access(addr,size,task)
#define DB_PHYS_EQ(task1,addr1,task2,addr2)			\
	db_phys_eq(task1,addr1,task2,addr2)
#define DB_VALID_KERN_ADDR(addr)				\
	((addr) >= VM_MIN_KERNEL_ADDRESS && 			\
	 (addr) < vm_last_addr)
#define DB_VALID_ADDRESS(addr,user)				\
	((!(user) && DB_VALID_KERN_ADDR(addr)) ||		\
	 ((user) && (addr) < VM_MAX_ADDRESS))

/*
 * Given pointer to savearea, determine if it represents
 * a thread executing a) in user space, b) in the kernel, or c)
 * in a kernel-loaded task.  Return true for cases a) and c).
 */
#define IS_USER_TRAP(regs)	\
     (USER_MODE(regs->save_srr1))

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
extern void		db_low_trace(
				db_expr_t	addr,
				int		have_addr,
				db_expr_t	count,
				char 		*modif);
extern void		db_to_gdb(
				void);


/* macros for printing OS server dependent task name */

#define DB_TASK_NAME(task)	db_task_name(task)
#define DB_TASK_NAME_TITLE	"COMMAND                                "
#define DB_TASK_NAME_LEN	39
#define DB_NULL_TASK_NAME	"?                      "

extern void		db_task_name(
				task_t			task);

/* macro for checking if a thread has used floating-point */

#define db_act_fp_used(act)	(FALSE)

extern void		kdb_trap(
				int			type,
				struct savearea	*regs);
extern boolean_t	db_trap_from_asm(
				struct savearea *regs);
extern void		kdb_on(
				int			cpu);
extern void		cnpollc(
				boolean_t		on);

extern boolean_t	db_phys_cmp(
				vm_offset_t, 
				vm_offset_t, 
				vm_size_t);

#endif	/* _PPC_DB_MACHDEP_H_ */
