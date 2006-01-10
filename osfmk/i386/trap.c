/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#if	MACH_KGDB
#include <kgdb/kgdb_defs.h>
#endif	/* MACH_KGDB */

#include <i386/intel_read_fault.h>

#if     MACH_KGDB
#include <kgdb/kgdb_defs.h>
#endif  /* MACH_KGDB */

#if 	MACH_KDB
#include <ddb/db_watch.h>
#include <ddb/db_run.h>
#include <ddb/db_break.h>
#include <ddb/db_trap.h>
#endif	/* MACH_KDB */

#include <string.h>

#include <i386/io_emulate.h>

/*
 * Forward declarations
 */
extern void		user_page_fault_continue(
				kern_return_t		kr);

extern boolean_t	v86_assist(
				thread_t		thread,
				struct i386_saved_state	*regs);

extern boolean_t	check_io_fault(
				struct i386_saved_state	*regs);

extern int		inst_fetch(
				int			eip,
				int			cs);

void
thread_syscall_return(
        kern_return_t ret)
{
        register thread_t   thr_act = current_thread();
        register struct i386_saved_state *regs = USER_REGS(thr_act);
        regs->eax = ret;
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
	register thread_t	thread = current_thread();
	register struct i386_saved_state *regs = USER_REGS(thread);

	if (kdb_trap(regs->trapno, regs->err, regs)) {
#if		MACH_LDEBUG
		assert(thread->mutex_count == 0); 
#endif		/* MACH_LDEBUG */
		thread_exception_return();
		/*NOTREACHED*/
	}
}
boolean_t let_ddb_vm_fault = FALSE;

#endif	/* MACH_KDB */

void
user_page_fault_continue(
	kern_return_t	kr)
{
	register thread_t	thread = current_thread();
	register struct i386_saved_state *regs = USER_REGS(thread);

	if ((kr == KERN_SUCCESS) || (kr == KERN_ABORTED)) {
#if	MACH_KDB
		if (!db_breakpoints_inserted) {
			db_set_breakpoints();
		}
		if (db_watchpoint_list &&
		    db_watchpoints_inserted &&
		    (regs->err & T_PF_WRITE) &&
		    db_find_watchpoint(thread->map,
				       (vm_offset_t)regs->cr2,
				       regs))
			kdb_trap(T_WATCHPOINT, 0, regs);
#endif	/* MACH_KDB */
		thread_exception_return();
		/*NOTREACHED*/
	}

#if	MACH_KDB
	if (debug_all_traps_with_kdb &&
	    kdb_trap(regs->trapno, regs->err, regs)) {
#if		MACH_LDEBUG
		assert(thread->mutex_count == 0);
#endif		/* MACH_LDEBUG */
		thread_exception_return();
		/*NOTREACHED*/
	}
#endif	/* MACH_KDB */

	i386_exception(EXC_BAD_ACCESS, kr, regs->cr2);
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

/*
 * Recovery from Successful fault in copyout does not
 * return directly - it retries the pte check, since
 * the 386 ignores write protection in kernel mode.
 */
extern struct recovery	retry_table[];
extern struct recovery	retry_table_end[];

const char *		trap_type[] = {TRAP_NAMES};
int	TRAP_TYPES = sizeof(trap_type)/sizeof(trap_type[0]);


/*
 * Trap from kernel mode.  Only page-fault errors are recoverable,
 * and then only in special circumstances.  All other errors are
 * fatal.  Return value indicates if trap was handled.
 */
boolean_t
kernel_trap(
	register struct i386_saved_state	*regs)
{
	int			code;
	unsigned int		subcode;
	int			interruptible = THREAD_UNINT;
	register int		type;
	vm_map_t		map;
	kern_return_t		result = KERN_FAILURE;
	register thread_t	thread;

	type = regs->trapno;
	code = regs->err;
	thread = current_thread();

	switch (type) {
	    case T_PREEMPT:
		ast_taken(AST_PREEMPTION, FALSE);
		return (TRUE);

	    case T_NO_FPU:
		fpnoextflt();
		return (TRUE);

	    case T_FPU_FAULT:
		fpextovrflt();
		return (TRUE);

	    case T_FLOATING_POINT_ERROR:
		fpexterrflt();
		return (TRUE);

	    case T_PAGE_FAULT:
		/*
		 * If the current map is a submap of the kernel map,
		 * and the address is within that map, fault on that
		 * map.  If the same check is done in vm_fault
		 * (vm_map_lookup), we may deadlock on the kernel map
		 * lock.
		 */
#if	MACH_KDB
		mp_disable_preemption();
		if (db_active
		    && kdb_active[cpu_number()]
		    && !let_ddb_vm_fault) {
			/*
			 * Force kdb to handle this one.
			 */
			mp_enable_preemption();
			return (FALSE);
		}
		mp_enable_preemption();
#endif	/* MACH_KDB */
		subcode = regs->cr2;	/* get faulting address */

		if (subcode > LINEAR_KERNEL_ADDRESS) {
		    map = kernel_map;
		} else if (thread == THREAD_NULL)
		    map = kernel_map;
		else {
		    map = thread->map;
		}
#if	MACH_KDB
		/*
		 * Check for watchpoint on kernel static data.
		 * vm_fault would fail in this case 
		 */
		if (map == kernel_map && 
		    db_watchpoint_list &&
		    db_watchpoints_inserted &&
		    (code & T_PF_WRITE) &&
		    (vm_offset_t)subcode < vm_last_phys &&
		    ((*(pte = pmap_pte(kernel_pmap, (vm_offset_t)subcode))) &
		     INTEL_PTE_WRITE) == 0) {
		  *pte = *pte | INTEL_PTE_VALID | INTEL_PTE_WRITE; /* XXX need invltlb here? */
			result = KERN_SUCCESS;
		} else
#endif	/* MACH_KDB */
		{
		  	/*
			 * Since the 386 ignores write protection in
			 * kernel mode, always try for write permission
			 * first.  If that fails and the fault was a
			 * read fault, retry with read permission.
			 */
			if (map == kernel_map) {
				register struct recovery *rp;

				interruptible = THREAD_UNINT;
				for (rp = recover_table; rp < recover_table_end; rp++) {
					if (regs->eip == rp->fault_addr) {
						interruptible = THREAD_ABORTSAFE;
						break;
					}
				}
			}
		  	result = vm_fault(map,
					  trunc_page((vm_offset_t)subcode),
					  VM_PROT_READ|VM_PROT_WRITE,
					  FALSE, 
					  (map == kernel_map) ? interruptible : THREAD_ABORTSAFE, NULL, 0);
		}
#if	MACH_KDB
		if (result == KERN_SUCCESS) {
		    /* Look for watchpoints */
		    if (db_watchpoint_list &&
			db_watchpoints_inserted &&
			(code & T_PF_WRITE) &&
			db_find_watchpoint(map,
				(vm_offset_t)subcode, regs))
			kdb_trap(T_WATCHPOINT, 0, regs);
		}
		else
#endif	/* MACH_KDB */
		if ((code & T_PF_WRITE) == 0 &&
		    result == KERN_PROTECTION_FAILURE)
		{
		    /*
		     *	Must expand vm_fault by hand,
		     *	so that we can ask for read-only access
		     *	but enter a (kernel)writable mapping.
		     */
		    result = intel_read_fault(map,
					  trunc_page((vm_offset_t)subcode));
		}

		if (result == KERN_SUCCESS) {
		    /*
		     * Certain faults require that we back up
		     * the EIP.
		     */
		    register struct recovery *rp;

		    for (rp = retry_table; rp < retry_table_end; rp++) {
			if (regs->eip == rp->fault_addr) {
			    regs->eip = rp->recover_addr;
			    break;
			}
		    }
		    return (TRUE);
		}

		/* fall through */

	    case T_GENERAL_PROTECTION:

		/*
		 * If there is a failure recovery address
		 * for this fault, go there.
		 */
		{
		    register struct recovery *rp;

		    for (rp = recover_table;
			 rp < recover_table_end;
			 rp++) {
			if (regs->eip == rp->fault_addr) {
			    regs->eip = rp->recover_addr;
			    return (TRUE);
			}
		    }
		}

		/*
		 * Check thread recovery address also -
		 * v86 assist uses it.
		 */
		if (thread->recover) {
		    regs->eip = thread->recover;
		    thread->recover = 0;
		    return (TRUE);
		}

		/*
		 * Unanticipated page-fault errors in kernel
		 * should not happen.
		 */
		/* fall through... */

	    default:
		/*
		 * Exception 15 is reserved but some chips may generate it
		 * spuriously. Seen at startup on AMD Athlon-64.
		 */
	    	if (type == 15) {
			kprintf("kernel_trap() ignoring spurious trap 15\n"); 
			return (TRUE);
		}

		/*
		 * ...and return failure, so that locore can call into
		 * debugger.
		 */
#if  MACH_KDP
		kdp_i386_trap(type, regs, result, regs->cr2);
#endif
		return (FALSE);
	}
	return (TRUE);
}

/*
 * Called if both kernel_trap() and kdb_trap() fail.
 */
void
panic_trap(
	register struct i386_saved_state	*regs)
{
	int		code;
	register int	type;

	type = regs->trapno;
	code = regs->err;

	printf("trap type %d, code = %x, pc = %x\n",
		type, code, regs->eip);
	panic("trap");
}


/*
 *	Trap from user mode.
 */
void
user_trap(
	register struct i386_saved_state	*regs)
{
	int		exc;
	int		code;
	unsigned int	subcode;
	register int	type;
	vm_map_t	map;
	vm_prot_t	prot;
	kern_return_t	result;
	thread_t	thread = current_thread();
	boolean_t	kernel_act = FALSE;

	if (regs->efl & EFL_VM) {
	    /*
	     * If hardware assist can handle exception,
	     * continue execution.
	     */
	    if (v86_assist(thread, regs))
		return;
	}

	type = regs->trapno;
	code = 0;
	subcode = 0;
	exc = 0;

	switch (type) {

	    case T_DIVIDE_ERROR:
		exc = EXC_ARITHMETIC;
		code = EXC_I386_DIV;
		break;

	    case T_DEBUG:
		exc = EXC_BREAKPOINT;
		code = EXC_I386_SGL;
		break;

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
		subcode = regs->err & 0xffff;
		break;

	    case T_SEGMENT_NOT_PRESENT:
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_SEGNPFLT;
		subcode = regs->err & 0xffff;
		break;

	    case T_STACK_FAULT:
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_STKFLT;
		subcode = regs->err & 0xffff;
		break;

	    case T_GENERAL_PROTECTION:
		if (!(regs->efl & EFL_VM)) {
		    if (check_io_fault(regs))
			return;
		}
		exc = EXC_BAD_INSTRUCTION;
		code = EXC_I386_GPFLT;
		subcode = regs->err & 0xffff;
		break;

	    case T_PAGE_FAULT:
		subcode = regs->cr2;
		prot = VM_PROT_READ|VM_PROT_WRITE;
		if (kernel_act == FALSE) {
			if (!(regs->err & T_PF_WRITE))
				prot = VM_PROT_READ;
			(void) user_page_fault_continue(vm_fault(thread->map,
				trunc_page((vm_offset_t)subcode),
				prot,
				FALSE,
				THREAD_ABORTSAFE, NULL, 0));
			/* NOTREACHED */
		}
		else {
			if (subcode > LINEAR_KERNEL_ADDRESS) {
			  	map = kernel_map;
			}
			result = vm_fault(thread->map,
				trunc_page((vm_offset_t)subcode),
				prot,
				FALSE,
				(map == kernel_map) ? THREAD_UNINT : THREAD_ABORTSAFE, NULL, 0);
			if ((result != KERN_SUCCESS) && (result != KERN_ABORTED)) {
				/*
				 * Must expand vm_fault by hand,
				 * so that we can ask for read-only access
				 * but enter a (kernel) writable mapping.
				 */
				result = intel_read_fault(thread->map,
					trunc_page((vm_offset_t)subcode));
			}
			user_page_fault_continue(result);
			/*NOTREACHED*/
		}
		break;

	    case T_FLOATING_POINT_ERROR:
		fpexterrflt();
		return;

	    default:
#if     MACH_KGDB
		Debugger("Unanticipated user trap");
		return;
#endif  /* MACH_KGDB */
#if	MACH_KDB
		if (kdb_trap(type, regs->err, regs))
		    return;
#endif	/* MACH_KDB */
		printf("user trap type %d, code = %x, pc = %x\n",
		       type, regs->err, regs->eip);
		panic("user trap");
		return;
	}

#if	MACH_KDB
	if (debug_all_traps_with_kdb &&
	    kdb_trap(type, regs->err, regs))
		return;
#endif	/* MACH_KDB */

	i386_exception(exc, code, subcode);
	/*NOTREACHED*/
}

/*
 *	V86 mode assist for interrupt handling.
 */
boolean_t v86_assist_on = TRUE;
boolean_t v86_unsafe_ok = FALSE;
boolean_t v86_do_sti_cli = TRUE;
boolean_t v86_do_sti_immediate = FALSE;

#define	V86_IRET_PENDING 0x4000

int cli_count = 0;
int sti_count = 0;

boolean_t
v86_assist(
	thread_t				thread,
	register struct i386_saved_state	*regs)
{
	register struct v86_assist_state *v86 = &thread->machine.pcb->ims.v86s;

/*
 * Build an 8086 address.  Use only when off is known to be 16 bits.
 */
#define	Addr8086(seg,off)	((((seg) & 0xffff) << 4) + (off))

#define	EFL_V86_SAFE		(  EFL_OF | EFL_DF | EFL_TF \
				 | EFL_SF | EFL_ZF | EFL_AF \
				 | EFL_PF | EFL_CF )
	struct iret_32 {
		int		eip;
		int		cs;
		int		eflags;
	};
	struct iret_16 {
		unsigned short	ip;
		unsigned short	cs;
		unsigned short	flags;
	};
	union iret_struct {
		struct iret_32	iret_32;
		struct iret_16	iret_16;
	};

	struct int_vec {
		unsigned short	ip;
		unsigned short	cs;
	};

	if (!v86_assist_on)
	    return FALSE;

	/*
	 * If delayed STI pending, enable interrupts.
	 * Turn off tracing if on only to delay STI.
	 */
	if (v86->flags & V86_IF_PENDING) {
	    v86->flags &= ~V86_IF_PENDING;
	    v86->flags |=  EFL_IF;
	    if ((v86->flags & EFL_TF) == 0)
		regs->efl &= ~EFL_TF;
	}

	if (regs->trapno == T_DEBUG) {

	    if (v86->flags & EFL_TF) {
		/*
		 * Trace flag was also set - it has priority
		 */
		return FALSE;			/* handle as single-step */
	    }
	    /*
	     * Fall through to check for interrupts.
	     */
	}
	else if (regs->trapno == T_GENERAL_PROTECTION) {
	    /*
	     * General protection error - must be an 8086 instruction
	     * to emulate.
	     */
	    register int	eip;
	    boolean_t	addr_32 = FALSE;
	    boolean_t	data_32 = FALSE;
	    int		io_port;

	    /*
	     * Set up error handler for bad instruction/data
	     * fetches.
	     */
	    __asm__("movl $(addr_error), %0" : : "m" (thread->recover));

	    eip = regs->eip;
	    while (TRUE) {
		unsigned char	opcode;

		if (eip > 0xFFFF) {
		    thread->recover = 0;
		    return FALSE;	/* GP fault: IP out of range */
		}

		opcode = *(unsigned char *)Addr8086(regs->cs,eip);
		eip++;
		switch (opcode) {
		    case 0xf0:		/* lock */
		    case 0xf2:		/* repne */
		    case 0xf3:		/* repe */
		    case 0x2e:		/* cs */
		    case 0x36:		/* ss */
		    case 0x3e:		/* ds */
		    case 0x26:		/* es */
		    case 0x64:		/* fs */
		    case 0x65:		/* gs */
			/* ignore prefix */
			continue;

		    case 0x66:		/* data size */
			data_32 = TRUE;
			continue;

		    case 0x67:		/* address size */
			addr_32 = TRUE;
			continue;

		    case 0xe4:		/* inb imm */
		    case 0xe5:		/* inw imm */
		    case 0xe6:		/* outb imm */
		    case 0xe7:		/* outw imm */
			io_port = *(unsigned char *)Addr8086(regs->cs, eip);
			eip++;
			goto do_in_out;

		    case 0xec:		/* inb dx */
		    case 0xed:		/* inw dx */
		    case 0xee:		/* outb dx */
		    case 0xef:		/* outw dx */
		    case 0x6c:		/* insb */
		    case 0x6d:		/* insw */
		    case 0x6e:		/* outsb */
		    case 0x6f:		/* outsw */
			io_port = regs->edx & 0xffff;

		    do_in_out:
			if (!data_32)
			    opcode |= 0x6600;	/* word IO */

			switch (emulate_io(regs, opcode, io_port)) {
			    case EM_IO_DONE:
				/* instruction executed */
				break;
			    case EM_IO_RETRY:
				/* port mapped, retry instruction */
				thread->recover = 0;
				return TRUE;
			    case EM_IO_ERROR:
				/* port not mapped */
				thread->recover = 0;
				return FALSE;
			}
			break;

		    case 0xfa:		/* cli */
			if (!v86_do_sti_cli) {
			    thread->recover = 0;
			    return (FALSE);
			}

			v86->flags &= ~EFL_IF;
					/* disable simulated interrupts */
			cli_count++;
			break;

		    case 0xfb:		/* sti */
			if (!v86_do_sti_cli) {
			    thread->recover = 0;
			    return (FALSE);
			}

			if ((v86->flags & EFL_IF) == 0) {
			    if (v86_do_sti_immediate) {
				    v86->flags |= EFL_IF;
			    } else {
				    v86->flags |= V86_IF_PENDING;
				    regs->efl |= EFL_TF;
			    }
					/* single step to set IF next inst. */
			}
			sti_count++;
			break;

		    case 0x9c:		/* pushf */
		    {
			int		flags;
			vm_offset_t	sp;
			unsigned int	size;

			flags = regs->efl;
			if ((v86->flags & EFL_IF) == 0)
			    flags &= ~EFL_IF;

			if ((v86->flags & EFL_TF) == 0)
			    flags &= ~EFL_TF;
			else flags |= EFL_TF;

			sp = regs->uesp;
			if (!addr_32)
			    sp &= 0xffff;
			else if (sp > 0xffff)
			    goto stack_error;
			size = (data_32) ? 4 : 2;
			if (sp < size)
			    goto stack_error;
			sp -= size;
			if (copyout((char *)&flags,
				    (user_addr_t)Addr8086(regs->ss,sp),
				    size))
			    goto addr_error;
			if (addr_32)
			    regs->uesp = sp;
			else
			    regs->uesp = (regs->uesp & 0xffff0000) | sp;
			break;
		    }

		    case 0x9d:		/* popf */
		    {
			vm_offset_t sp;
			int	nflags;

			sp = regs->uesp;
			if (!addr_32)
			    sp &= 0xffff;
			else if (sp > 0xffff)
			    goto stack_error;

			if (data_32) {
			    if (sp > 0xffff - sizeof(int))
				goto stack_error;
			    nflags = *(int *)Addr8086(regs->ss,sp);
			    sp += sizeof(int);
			}
			else {
			    if (sp > 0xffff - sizeof(short))
				goto stack_error;
			    nflags = *(unsigned short *)
					Addr8086(regs->ss,sp);
			    sp += sizeof(short);
			}
			if (addr_32)
			    regs->uesp = sp;
			else
			    regs->uesp = (regs->uesp & 0xffff0000) | sp;

			if (v86->flags & V86_IRET_PENDING) {
				v86->flags = nflags & (EFL_TF | EFL_IF);
				v86->flags |= V86_IRET_PENDING;
			} else {
				v86->flags = nflags & (EFL_TF | EFL_IF);
			}
			regs->efl = (regs->efl & ~EFL_V86_SAFE)
				     | (nflags & EFL_V86_SAFE);
			break;
		    }
		    case 0xcf:		/* iret */
		    {
			vm_offset_t sp;
			int	nflags;
			union iret_struct iret_struct;

			v86->flags &= ~V86_IRET_PENDING;
			sp = regs->uesp;
			if (!addr_32)
			    sp &= 0xffff;
			else if (sp > 0xffff)
			    goto stack_error;

			if (data_32) {
			    if (sp > 0xffff - sizeof(struct iret_32))
				goto stack_error;
			    iret_struct.iret_32 =
				*(struct iret_32 *) Addr8086(regs->ss,sp);
			    sp += sizeof(struct iret_32);
			}
			else {
			    if (sp > 0xffff - sizeof(struct iret_16))
				goto stack_error;
			    iret_struct.iret_16 =
				*(struct iret_16 *) Addr8086(regs->ss,sp);
			    sp += sizeof(struct iret_16);
			}
			if (addr_32)
			    regs->uesp = sp;
			else
			    regs->uesp = (regs->uesp & 0xffff0000) | sp;

			if (data_32) {
			    eip	      = iret_struct.iret_32.eip;
			    regs->cs  = iret_struct.iret_32.cs & 0xffff;
			    nflags    = iret_struct.iret_32.eflags;
			}
			else {
			    eip       = iret_struct.iret_16.ip;
			    regs->cs  = iret_struct.iret_16.cs;
			    nflags    = iret_struct.iret_16.flags;
			}

			v86->flags = nflags & (EFL_TF | EFL_IF);
			regs->efl = (regs->efl & ~EFL_V86_SAFE)
				     | (nflags & EFL_V86_SAFE);
			break;
		    }
		    default:
			/*
			 * Instruction not emulated here.
			 */
			thread->recover = 0;
			return FALSE;
		}
		break;	/* exit from 'while TRUE' */
	    }
	    regs->eip = (regs->eip & 0xffff0000) | eip;
	}
	else {
	    /*
	     * Not a trap we handle.
	     */
	    thread->recover = 0;
	    return FALSE;
	}

	if ((v86->flags & EFL_IF) && ((v86->flags & V86_IRET_PENDING)==0)) {

	    struct v86_interrupt_table *int_table;
	    int int_count;
	    int vec;
	    int i;

	    int_table = (struct v86_interrupt_table *) v86->int_table;
	    int_count = v86->int_count;

	    vec = 0;
	    for (i = 0; i < int_count; int_table++, i++) {
		if (!int_table->mask && int_table->count > 0) {
		    int_table->count--;
		    vec = int_table->vec;
		    break;
		}
	    }
	    if (vec != 0) {
		/*
		 * Take this interrupt
		 */
		vm_offset_t	sp;
		struct iret_16 iret_16;
		struct int_vec int_vec;

		sp = regs->uesp & 0xffff;
		if (sp < sizeof(struct iret_16))
		    goto stack_error;
		sp -= sizeof(struct iret_16);
		iret_16.ip = regs->eip;
		iret_16.cs = regs->cs;
		iret_16.flags = regs->efl & 0xFFFF;
		if ((v86->flags & EFL_TF) == 0)
		    iret_16.flags &= ~EFL_TF;
		else iret_16.flags |= EFL_TF;

		(void) memcpy((char *) &int_vec, 
			      (char *) (sizeof(struct int_vec) * vec),
		      	      sizeof (struct int_vec));
		if (copyout((char *)&iret_16,
			    (user_addr_t)Addr8086(regs->ss,sp),
			    sizeof(struct iret_16)))
		    goto addr_error;
		regs->uesp = (regs->uesp & 0xFFFF0000) | (sp & 0xffff);
		regs->eip = int_vec.ip;
		regs->cs  = int_vec.cs;
		regs->efl  &= ~EFL_TF;
		v86->flags &= ~(EFL_IF | EFL_TF);
		v86->flags |= V86_IRET_PENDING;
	    }
	}

	thread->recover = 0;
	return TRUE;

	/*
	 *	On address error, report a page fault.
	 *	XXX report GP fault - we don`t save
	 *	the faulting address.
	 */
    addr_error:
	__asm__("addr_error:;");
	thread->recover = 0;
	return FALSE;

	/*
	 *	On stack address error, return stack fault (12).
	 */
    stack_error:
	thread->recover = 0;
	regs->trapno = T_STACK_FAULT;
	return FALSE;
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
	ast_t		*my_ast, mask = AST_ALL;
	spl_t		s;

	s = splsched();		/* block interrupts to check reasons */
	mp_disable_preemption();
	my_ast = ast_pending();
	if (*my_ast & AST_I386_FP) {
	    /*
	     * AST was for delayed floating-point exception -
	     * FP interrupt occurred while in kernel.
	     * Turn off this AST reason and handle the FPU error.
	     */

	    ast_off(AST_I386_FP);
	    mp_enable_preemption();
	    splx(s);

	    fpexterrflt();
	}
	else {
	    /*
	     * Not an FPU trap.  Handle the AST.
	     * Interrupts are still blocked.
	     */

#if 1
	    if (preemption) {
		mask = AST_PREEMPTION;
		mp_enable_preemption();
	    } else {
		mp_enable_preemption();
	    }
#else
	mp_enable_preemption();
#endif

	ast_taken(mask, s);

	}
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
	spl_t			s;
	exception_data_type_t   codes[EXCEPTION_CODE_MAX];

	/*
	 * Turn off delayed FPU error handling.
	 */
	s = splsched();
	mp_disable_preemption();
	ast_off(AST_I386_FP);
	mp_enable_preemption();
	splx(s);

	codes[0] = code;		/* new exception interface */
	codes[1] = subcode;
	exception_triage(exc, codes, 2);
	/*NOTREACHED*/
}

boolean_t
check_io_fault(
	struct i386_saved_state		*regs)
{
	int		eip, opcode, io_port;
	boolean_t	data_16 = FALSE;

	/*
	 * Get the instruction.
	 */
	eip = regs->eip;

	for (;;) {
	    opcode = inst_fetch(eip, regs->cs);
	    eip++;
	    switch (opcode) {
		case 0x66:	/* data-size prefix */
		    data_16 = TRUE;
		    continue;

		case 0xf3:	/* rep prefix */
		case 0x26:	/* es */
		case 0x2e:	/* cs */
		case 0x36:	/* ss */
		case 0x3e:	/* ds */
		case 0x64:	/* fs */
		case 0x65:	/* gs */
		    continue;

		case 0xE4:	/* inb imm */
		case 0xE5:	/* inl imm */
		case 0xE6:	/* outb imm */
		case 0xE7:	/* outl imm */
		    /* port is immediate byte */
		    io_port = inst_fetch(eip, regs->cs);
		    eip++;
		    break;

		case 0xEC:	/* inb dx */
		case 0xED:	/* inl dx */
		case 0xEE:	/* outb dx */
		case 0xEF:	/* outl dx */
		case 0x6C:	/* insb */
		case 0x6D:	/* insl */
		case 0x6E:	/* outsb */
		case 0x6F:	/* outsl */
		    /* port is in DX register */
		    io_port = regs->edx & 0xFFFF;
		    break;

		default:
		    return FALSE;
	    }
	    break;
	}

	if (data_16)
	    opcode |= 0x6600;		/* word IO */

	switch (emulate_io(regs, opcode, io_port)) {
	    case EM_IO_DONE:
		/* instruction executed */
		regs->eip = eip;
		return TRUE;

	    case EM_IO_RETRY:
		/* port mapped, retry instruction */
		return TRUE;

	    case EM_IO_ERROR:
		/* port not mapped */
		return FALSE;
	}
	return FALSE;
}

void
kernel_preempt_check (void)
{
	ast_t		*myast;

	mp_disable_preemption();
	myast = ast_pending();
        if ((*myast & AST_URGENT) &&
	    get_interrupt_level() == 1
	    ) {
		mp_enable_preemption_no_check();
                __asm__ volatile ("     int     $0xff");
        } else {
		mp_enable_preemption_no_check();
	}
}

#if	MACH_KDB

extern void 	db_i386_state(struct i386_saved_state *regs);

#include <ddb/db_output.h>

void 
db_i386_state(
	struct i386_saved_state *regs)
{
  	db_printf("eip	%8x\n", regs->eip);
  	db_printf("trap	%8x\n", regs->trapno);
  	db_printf("err	%8x\n", regs->err);
  	db_printf("efl	%8x\n", regs->efl);
  	db_printf("ebp	%8x\n", regs->ebp);
  	db_printf("esp	%8x\n", regs->esp);
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
