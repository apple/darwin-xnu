/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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

#include <types.h>
#include <i386/eflags.h>
#include <i386/trap.h>
#include <i386/pmap.h>
#include <i386/fpu.h>
#include <i386/misc_protos.h> /* panic_io_port_read() */

#include <mach/exception.h>
#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <mach/i386/thread_status.h>

#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/sched.h>
#include <kern/sched_prim.h>
#include <kern/exception.h>
#include <kern/spl.h>
#include <kern/misc_protos.h>
#include <kern/debug.h>

#include <sys/kdebug.h>

#include <string.h>

#include <i386/postcode.h>
#include <i386/mp_desc.h>
#include <i386/proc_reg.h>
#if CONFIG_MCA
#include <i386/machine_check.h>
#endif
#include <mach/i386/syscall_sw.h>

#include <machine/pal_routines.h>
#include <libkern/OSAtomic.h>

extern void kprintf_break_lock(void);
extern void kprint_state(x86_saved_state64_t *saved_state);
void panic_64(x86_saved_state_t *, int, const char *, boolean_t);

extern volatile int panic_double_fault_cpu;


#if defined(__x86_64__) && DEBUG
/*
 * K64 debug - fatal handler for debug code in the trap vectors.
 */
extern void
panic_idt64(x86_saved_state_t *rsp);
void
panic_idt64(x86_saved_state_t *rsp)
{
	kprint_state(saved_state64(rsp));
	panic("panic_idt64");
}
#endif

#ifdef __i386__
static void
panic_32(__unused int code, __unused int pc, __unused const char *msg, boolean_t do_mca_dump, boolean_t do_bt)
{
	struct i386_tss *my_ktss = current_ktss();

	/* Set postcode (DEBUG only) */
	postcode(pc);

	/*
	 * Issue an I/O port read if one has been requested - this is an
	 * event logic analyzers can use as a trigger point.
	 */
	panic_io_port_read();

	/*
	 * Break kprintf lock in case of recursion,
	 * and record originally faulted instruction address.
	 */
	kprintf_break_lock();

	if (do_mca_dump) {
#if CONFIG_MCA
		/*
		 * Dump the contents of the machine check MSRs (if any).
		 */
		mca_dump();
#endif
	}

#if MACH_KDP
	/*
	 * Print backtrace leading to first fault:
	 */
	if (do_bt)
		panic_i386_backtrace((void *) my_ktss->ebp, 10, NULL, FALSE, NULL);
#endif

	panic("%s at 0x%08x, code:0x%x, "
	      "registers:\n"
	      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
	      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
	      "ESP: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
	      "EFL: 0x%08x, EIP: 0x%08x%s\n",
		  msg,
	      my_ktss->eip, code,
	      (uint32_t)get_cr0(), (uint32_t)get_cr2(), (uint32_t)get_cr3(), (uint32_t)get_cr4(),
	      my_ktss->eax, my_ktss->ebx, my_ktss->ecx, my_ktss->edx,
	      my_ktss->esp, my_ktss->ebp, my_ktss->esi, my_ktss->edi,
	      my_ktss->eflags, my_ktss->eip, virtualized ? " VMM" : "");
}

/*
 * Called from locore on a special reserved stack after a double-fault
 * is taken in kernel space.
 * Kernel stack overflow is one route here.
 */
void
panic_double_fault32(int code)
{
	(void)OSCompareAndSwap((UInt32) -1, (UInt32) cpu_number(), (volatile UInt32 *)&panic_double_fault_cpu);
	panic_32(code, PANIC_DOUBLE_FAULT, "Double fault", FALSE, TRUE);
}

/*
 * Called from locore on a special reserved stack after a machine-check
 */
void 
panic_machine_check32(int code)
{
	panic_32(code, PANIC_MACHINE_CHECK, "Machine-check", TRUE, FALSE);
}
#endif /* __i386__ */

void
panic_64(x86_saved_state_t *sp, __unused int pc, __unused const char *msg, boolean_t do_mca_dump)
{
	/* Set postcode (DEBUG only) */
	postcode(pc);

	/*
	 * Issue an I/O port read if one has been requested - this is an
	 * event logic analyzers can use as a trigger point.
	 */
	panic_io_port_read();

	
	/*
	 * Break kprintf lock in case of recursion,
	 * and record originally faulted instruction address.
	 */
	kprintf_break_lock();

	if (do_mca_dump) {
#if CONFIG_MCA
		/*
		 * Dump the contents of the machine check MSRs (if any).
		 */
		mca_dump();
#endif
	}

#ifdef __i386__
	/*
	 * Dump the interrupt stack frame at last kernel entry.
	 */
	if (is_saved_state64(sp)) {
		x86_saved_state64_t	*ss64p = saved_state64(sp);
		panic("%s trapno:0x%x, err:0x%qx, "
		      "registers:\n"
		      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
		      "RAX: 0x%016qx, RBX: 0x%016qx, RCX: 0x%016qx, RDX: 0x%016qx\n"
		      "RSP: 0x%016qx, RBP: 0x%016qx, RSI: 0x%016qx, RDI: 0x%016qx\n"
		      "R8:  0x%016qx, R9:  0x%016qx, R10: 0x%016qx, R11: 0x%016qx\n"
		      "R12: 0x%016qx, R13: 0x%016qx, R14: 0x%016qx, R15: 0x%016qx\n"
		      "RFL: 0x%016qx, RIP: 0x%016qx, CR2: 0x%016qx%s\n",
			  msg,
		      ss64p->isf.trapno, ss64p->isf.err,
		      (uint32_t)get_cr0(), (uint32_t)get_cr2(), (uint32_t)get_cr3(), (uint32_t)get_cr4(),
		      ss64p->rax, ss64p->rbx, ss64p->rcx, ss64p->rdx,
		      ss64p->isf.rsp, ss64p->rbp, ss64p->rsi, ss64p->rdi,
		      ss64p->r8, ss64p->r9, ss64p->r10, ss64p->r11,
		      ss64p->r12, ss64p->r13, ss64p->r14, ss64p->r15,
		      ss64p->isf.rflags, ss64p->isf.rip, ss64p->cr2,
			  virtualized ? " VMM" : "");
	} else {
		x86_saved_state32_t	*ss32p = saved_state32(sp);
		panic("%s at 0x%08x, trapno:0x%x, err:0x%x,"
		      "registers:\n"
		      "CR0: 0x%08x, CR2: 0x%08x, CR3: 0x%08x, CR4: 0x%08x\n"
		      "EAX: 0x%08x, EBX: 0x%08x, ECX: 0x%08x, EDX: 0x%08x\n"
		      "ESP: 0x%08x, EBP: 0x%08x, ESI: 0x%08x, EDI: 0x%08x\n"
		      "EFL: 0x%08x, EIP: 0x%08x%s\n",
		      msg,
			  ss32p->eip, ss32p->trapno, ss32p->err,
		      (uint32_t)get_cr0(), (uint32_t)get_cr2(), (uint32_t)get_cr3(), (uint32_t)get_cr4(),
		      ss32p->eax, ss32p->ebx, ss32p->ecx, ss32p->edx,
		      ss32p->uesp, ss32p->ebp, ss32p->esi, ss32p->edi,
		      ss32p->efl, ss32p->eip, virtualized ? " VMM" : "");
	}
#else
	x86_saved_state64_t *regs = saved_state64(sp);
	panic("%s at 0x%016llx, registers:\n"
	      "CR0: 0x%016lx, CR2: 0x%016lx, CR3: 0x%016lx, CR4: 0x%016lx\n"
	      "RAX: 0x%016llx, RBX: 0x%016llx, RCX: 0x%016llx, RDX: 0x%016llx\n"
	      "RSP: 0x%016llx, RBP: 0x%016llx, RSI: 0x%016llx, RDI: 0x%016llx\n"
	      "R8:  0x%016llx, R9:  0x%016llx, R10: 0x%016llx, R11: 0x%016llx\n"
	      "R12: 0x%016llx, R13: 0x%016llx, R14: 0x%016llx, R15: 0x%016llx\n"
	      "RFL: 0x%016llx, RIP: 0x%016llx, CS:  0x%016llx, SS:  0x%016llx\n"
	      "Error code: 0x%016llx%s\n",
	      msg,
		  regs->isf.rip,
	      get_cr0(), get_cr2(), get_cr3_raw(), get_cr4(),
	      regs->rax, regs->rbx, regs->rcx, regs->rdx,
	      regs->isf.rsp, regs->rbp, regs->rsi, regs->rdi,
	      regs->r8,  regs->r9,  regs->r10, regs->r11,
	      regs->r12, regs->r13, regs->r14, regs->r15,
	      regs->isf.rflags, regs->isf.rip, regs->isf.cs & 0xFFFF,  regs->isf.ss & 0xFFFF,
	      regs->isf.err, virtualized ? " VMM" : "");
#endif
}

void
panic_double_fault64(x86_saved_state_t *sp)
{
	(void)OSCompareAndSwap((UInt32) -1, (UInt32) cpu_number(), (volatile UInt32 *)&panic_double_fault_cpu);
	panic_64(sp, PANIC_DOUBLE_FAULT, "Double fault", FALSE);

}
void

panic_machine_check64(x86_saved_state_t *sp)
{
	panic_64(sp, PANIC_MACHINE_CHECK, "Machine Check", TRUE);

}
