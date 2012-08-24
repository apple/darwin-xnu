/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#include <string.h>

#include <mach/machine/vm_types.h>

#include <mach/boolean.h>
#include <kern/thread.h>
#include <kern/zalloc.h>

#include <kern/lock.h>
#include <kern/kalloc.h>
#include <kern/spl.h>

#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <mach/vm_param.h>
#include <mach/vm_prot.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <mach/machine/vm_param.h>
#include <machine/thread.h>

#include <kern/misc_protos.h>			/* prototyping */
#include <i386/misc_protos.h>

#include <i386/cpuid.h>
#include <i386/cpu_data.h>
#include <i386/mp.h>
#include <i386/cpu_number.h>
#include <i386/machine_cpu.h>
#include <i386/seg.h>

#include <vm/vm_protos.h>

#include <sys/kdebug.h>

#include <i386/postcode.h>

#ifdef __i386__
void
cpu_IA32e_enable(cpu_data_t *cdp)
{
	assert(!ml_get_interrupts_enabled());

	if (!cdp->cpu_is64bit ||
	    (rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) != 0)
		return;

	postcode(CPU_IA32_ENABLE_ENTRY);

	/* 
	 * The following steps are performed by inlines so that
	 * we can be assured we don't use the stack or any other
	 * non-identity mapped data while paging is turned off...
	 */
	/* Turn paging off */
	asm volatile(
		"mov	%%cr0, %%eax	\n\t"
		"andl	%0, %%eax	\n\t"
		"mov	%%eax, %%cr0	\n\t"
		:
		: "i" (~CR0_PG)
		: "eax" );

	/* Pop new top level phys pg addr into CR3 */
	asm volatile(
		"mov	%%eax, %%cr3	\n\t"
		:
		: "a" ((uint32_t) kernel64_cr3));

	/* Turn on the 64-bit mode bit */
	asm volatile(
		"rdmsr			\n\t"
		"orl	%1, %%eax	\n\t"
		"wrmsr			\n\t"
		:
		: "c" (MSR_IA32_EFER), "i" (MSR_IA32_EFER_LME)
		: "eax", "edx");

	/* Turn paging on again */
	asm volatile(
		"mov	%%cr0, %%eax	\n\t"
		"orl	%0, %%eax	\n\t"
		"mov	%%eax, %%cr0	\n\t"
		:
		: "i" (CR0_PG)
		: "eax" );
	
#if ONLY_SAFE_FOR_LINDA_SERIAL
	kprintf("cpu_IA32e_enable(%p)\n", cdp);
#endif

	if ((rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) == 0)
		panic("cpu_IA32e_enable() MSR_IA32_EFER_LMA not asserted");

	cdp->cpu_kernel_cr3 = kernel64_cr3;

	postcode(CPU_IA32_ENABLE_EXIT);
}

void
cpu_IA32e_disable(cpu_data_t *cdp)
{
	assert(!ml_get_interrupts_enabled());

	postcode(CPU_IA32_DISABLE_ENTRY);

	if (!cdp->cpu_is64bit ||
	    (rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) == 0)
		return;

	/* 
	 * The following steps are performed by inlines so that
	 * we can be assured we don't use the stack or any other
	 * non-identity mapped data while paging is turned off...
	 */
	/* Turn paging off */
	asm volatile(
		"mov	%%cr0, %%eax	\n\t"
		"andl	%0, %%eax	\n\t"
		"mov	%%eax, %%cr0	\n\t"
		:
		: "i" (~CR0_PG)
		: "eax" );

	/* Pop legacy top level phys pg addr into CR3 */
	asm volatile(
		"mov	%%eax, %%cr3	\n\t"
		:
		: "a" ((uint32_t) lo_kernel_cr3));

	/* Turn off the 64-bit mode bit */
	asm volatile(
		"rdmsr			\n\t"
		"andl	%1, %%eax	\n\t"
		"wrmsr			\n\t"
		:
		: "c" (MSR_IA32_EFER), "i" (~MSR_IA32_EFER_LME)
		: "eax", "edx");

	/* Turn paging on again */
	asm volatile(
		"mov	%%cr0, %%eax	\n\t"
		"orl	%0, %%eax	\n\t"
		"mov	%%eax, %%cr0	\n\t"
		:
		: "i" (CR0_PG)
		: "eax" );
	
	kprintf("cpu_IA32e_disable(%p)\n", cdp);

	if ((rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) != 0)
		panic("cpu_IA32e_disable() MSR_IA32_EFER_LMA not cleared");

	cdp->cpu_kernel_cr3 = 0ULL;

	postcode(CPU_IA32_DISABLE_EXIT);
}
#endif

#if DEBUG
extern void dump_regs64(void);
extern void dump_gdt(void *);
extern void dump_ldt(void *);
extern void dump_idt(void *);
extern void dump_tss(void *);
extern void dump_frame32(x86_saved_state_compat32_t *scp);
extern void dump_frame64(x86_saved_state64_t *sp);
extern void dump_frame(x86_saved_state_t *sp);

void
dump_frame(x86_saved_state_t *sp)
{
	if (is_saved_state32(sp))
		dump_frame32((x86_saved_state_compat32_t *) sp);
	else if (is_saved_state64(sp))
		dump_frame64(&sp->ss_64);
	else
		kprintf("dump_frame(%p) unknown type %d\n", sp, sp->flavor);
}

void
dump_frame32(x86_saved_state_compat32_t *scp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) scp;

	kprintf("dump_frame32(%p):\n", scp);
	
	for (i = 0;
	     i < sizeof(x86_saved_state_compat32_t)/sizeof(uint32_t);
	     i++, ip++)
		kprintf("%p: 0x%08x\n", ip, *ip);

	kprintf("scp->isf64.err:    0x%016llx\n", scp->isf64.err);
	kprintf("scp->isf64.rip:    0x%016llx\n", scp->isf64.rip);
	kprintf("scp->isf64.cs:     0x%016llx\n", scp->isf64.cs);
	kprintf("scp->isf64.rflags: 0x%016llx\n", scp->isf64.rflags);
	kprintf("scp->isf64.rsp:    0x%016llx\n", scp->isf64.rsp);
	kprintf("scp->isf64.ss:     0x%016llx\n", scp->isf64.ss);

	kprintf("scp->iss32.tag:    0x%08x\n", scp->iss32.tag);
	kprintf("scp->iss32.state.gs:     0x%08x\n", scp->iss32.state.gs);
	kprintf("scp->iss32.state.fs:     0x%08x\n", scp->iss32.state.fs);
	kprintf("scp->iss32.state.es:     0x%08x\n", scp->iss32.state.es);
	kprintf("scp->iss32.state.ds:     0x%08x\n", scp->iss32.state.ds);
	kprintf("scp->iss32.state.edi:    0x%08x\n", scp->iss32.state.edi);
	kprintf("scp->iss32.state.esi:    0x%08x\n", scp->iss32.state.esi);
	kprintf("scp->iss32.state.ebp:    0x%08x\n", scp->iss32.state.ebp);
	kprintf("scp->iss32.state.cr2:    0x%08x\n", scp->iss32.state.cr2);
	kprintf("scp->iss32.state.ebx:    0x%08x\n", scp->iss32.state.ebx);
	kprintf("scp->iss32.state.edx:    0x%08x\n", scp->iss32.state.edx);
	kprintf("scp->iss32.state.ecx:    0x%08x\n", scp->iss32.state.ecx);
	kprintf("scp->iss32.state.eax:    0x%08x\n", scp->iss32.state.eax);
	kprintf("scp->iss32.state.trapno: 0x%08x\n", scp->iss32.state.eax);
	kprintf("scp->iss32.state.eip:    0x%08x\n", scp->iss32.state.eip);
	kprintf("scp->iss32.state.cs:     0x%08x\n", scp->iss32.state.cs);
	kprintf("scp->iss32.state.efl:    0x%08x\n", scp->iss32.state.efl);
	kprintf("scp->iss32.state.uesp:   0x%08x\n", scp->iss32.state.uesp);
	kprintf("scp->iss32.state.ss:     0x%08x\n", scp->iss32.state.ss);

	postcode(0x99);
}

void
dump_frame64(x86_saved_state64_t *sp)
{
	unsigned int	i;
	uint64_t	*ip = (uint64_t *) sp;

	kprintf("dump_frame64(%p):\n", sp);
	
	for (i = 0;
	     i < sizeof(x86_saved_state64_t)/sizeof(uint64_t);
	     i++, ip++)
		kprintf("%p: 0x%016llx\n", ip, *ip);

	kprintf("sp->isf.trapno: 0x%08x\n", sp->isf.trapno);
	kprintf("sp->isf.trapfn: 0x%016llx\n", sp->isf.trapfn);
	kprintf("sp->isf.err:    0x%016llx\n", sp->isf.err);
	kprintf("sp->isf.rip:    0x%016llx\n", sp->isf.rip);
	kprintf("sp->isf.cs:     0x%016llx\n", sp->isf.cs);
	kprintf("sp->isf.rflags: 0x%016llx\n", sp->isf.rflags);
	kprintf("sp->isf.rsp:    0x%016llx\n", sp->isf.rsp);
	kprintf("sp->isf.ss:     0x%016llx\n", sp->isf.ss);

	kprintf("sp->fs:         0x%016x\n", sp->fs);
	kprintf("sp->gs:         0x%016x\n", sp->gs);
	kprintf("sp->rax:        0x%016llx\n", sp->rax);
	kprintf("sp->rcx:        0x%016llx\n", sp->rcx);
	kprintf("sp->rbx:        0x%016llx\n", sp->rbx);
	kprintf("sp->rbp:        0x%016llx\n", sp->rbp);
	kprintf("sp->r11:        0x%016llx\n", sp->r11);
	kprintf("sp->r12:        0x%016llx\n", sp->r12);
	kprintf("sp->r13:        0x%016llx\n", sp->r13);
	kprintf("sp->r14:        0x%016llx\n", sp->r14);
	kprintf("sp->r15:        0x%016llx\n", sp->r15);
	kprintf("sp->cr2:        0x%016llx\n", sp->cr2);
	kprintf("sp->v_arg8:     0x%016llx\n", sp->v_arg8);
	kprintf("sp->v_arg7:     0x%016llx\n", sp->v_arg7);
	kprintf("sp->v_arg6:     0x%016llx\n", sp->v_arg6);
	kprintf("sp->r9:         0x%016llx\n", sp->r9);
	kprintf("sp->r8:         0x%016llx\n", sp->r8);
	kprintf("sp->r10:        0x%016llx\n", sp->r10);
	kprintf("sp->rdx:        0x%016llx\n", sp->rdx);
	kprintf("sp->rsi:        0x%016llx\n", sp->rsi);
	kprintf("sp->rdi:        0x%016llx\n", sp->rdi);

	postcode(0x98);
}

void
dump_gdt(void *gdtp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) gdtp;

	kprintf("GDT:\n");
	for (i = 0; i < GDTSZ; i++, ip += 2) {
		kprintf("%p: 0x%08x\n", ip+0, *(ip+0));
		kprintf("%p: 0x%08x\n", ip+1, *(ip+1));
	}
}

void
dump_ldt(void *ldtp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) ldtp;

	kprintf("LDT:\n");
	for (i = 0; i < LDTSZ_MIN; i++, ip += 2) {
		kprintf("%p: 0x%08x\n", ip+0, *(ip+0));
		kprintf("%p: 0x%08x\n", ip+1, *(ip+1));
	}
}

void
dump_idt(void *idtp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) idtp;

	kprintf("IDT64:\n");
	for (i = 0; i < 16; i++, ip += 4) {
		kprintf("%p: 0x%08x\n", ip+0, *(ip+0));
		kprintf("%p: 0x%08x\n", ip+1, *(ip+1));
		kprintf("%p: 0x%08x\n", ip+2, *(ip+2));
		kprintf("%p: 0x%08x\n", ip+3, *(ip+3));
	}
}

void
dump_tss(void *tssp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) tssp;

	kprintf("TSS64:\n");
	for (i = 0; i < sizeof(master_ktss64)/sizeof(uint32_t); i++, ip++) {
		kprintf("%p: 0x%08x\n", ip+0, *(ip+0));
	}
}

#if defined(__x86_64__)
void dump_regs64(void)
{

#define SNAP_REG(reg)						\
	uint64_t	reg;					\
	__asm__ volatile("mov %%" #reg ", %0" : "=m" (reg))

#define KPRINT_REG(reg)						\
	kprintf("%3s: %p\n", #reg, (void *) reg)

	SNAP_REG(rsp);
	SNAP_REG(rbp);
	SNAP_REG(rax);
	SNAP_REG(rbx);
	SNAP_REG(rcx);
	SNAP_REG(rdx);
	SNAP_REG(rsi);
	SNAP_REG(rdi);
	SNAP_REG(r8);
	SNAP_REG(r9);
	SNAP_REG(r10);
	SNAP_REG(r11);
	SNAP_REG(r12);
	SNAP_REG(r13);
	SNAP_REG(r14);

	KPRINT_REG(rsp);
	KPRINT_REG(rbp);
	KPRINT_REG(rax);
	KPRINT_REG(rbx);
	KPRINT_REG(rcx);
	KPRINT_REG(rdx);
	KPRINT_REG(rsi);
	KPRINT_REG(rdi);
	KPRINT_REG(r8);
	KPRINT_REG(r9);
	KPRINT_REG(r10);
	KPRINT_REG(r11);
	KPRINT_REG(r12);
	KPRINT_REG(r13);
	KPRINT_REG(r14);
}
#endif /* __x86_64__ */
#endif /* DEBUG */
