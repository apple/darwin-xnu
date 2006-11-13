/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
#include <i386/mp_slave_boot.h>
#include <i386/seg.h>

#include <vm/vm_protos.h>

#include <sys/kdebug.h>

#include <i386/postcode.h>

void
cpu_IA32e_enable(cpu_data_t *cdp)
{
	uint32_t	cr0 = get_cr0();
        uint64_t	efer = rdmsr64(MSR_IA32_EFER);

	assert(!ml_get_interrupts_enabled());

	postcode(CPU_IA32_ENABLE_ENTRY);

	/* Turn paging off - works because we're identity mapped */
	set_cr0(cr0 & ~CR0_PG);

	/* pop in new top level phys pg addr */
	set_cr3((vm_offset_t) kernel64_cr3);

	wrmsr64(MSR_IA32_EFER, efer | MSR_IA32_EFER_LME); /* set  mode */

	/* Turn paging on */
        set_cr0(cr0 | CR0_PG);

	/* this call is required to re-activate paging */
	kprintf("cpu_IA32e_enable(%p)\n", cdp);

	if ((rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) == 0)
		panic("cpu_IA32e_enable() MSR_IA32_EFER_LMA not asserted");

	cdp->cpu_kernel_cr3 = kernel64_cr3;

	postcode(CPU_IA32_ENABLE_EXIT);
}

void
cpu_IA32e_disable(cpu_data_t *cdp)
{
	uint32_t	cr0 = get_cr0();
        uint64_t	efer = rdmsr64(MSR_IA32_EFER);

	assert(!ml_get_interrupts_enabled());

	postcode(CPU_IA32_DISABLE_ENTRY);

	if ((rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) == 0)
		panic("cpu_IA32e_disable() MSR_IA32_EFER_LMA clear on entry");

	/* Turn paging off - works because we're identity mapped */
	set_cr0(cr0 & ~CR0_PG);

	/* pop in legacy top level phys pg addr */
	set_cr3((vm_offset_t) lo_kernel_cr3);

	wrmsr64(MSR_IA32_EFER, efer & ~MSR_IA32_EFER_LME); /* reset mode */

	/* Turn paging on */
        set_cr0(cr0 | CR0_PG);

	/* this call is required to re-activate paging */
	kprintf("cpu_IA32e_disable(%p)\n", cdp);

	if ((rdmsr64(MSR_IA32_EFER) & MSR_IA32_EFER_LMA) != 0)
		panic("cpu_IA32e_disable() MSR_IA32_EFER_LMA not cleared");

	cdp->cpu_kernel_cr3 = 0ULL;

	postcode(CPU_IA32_DISABLE_EXIT);
}

void
fix_desc64(void *descp, int count)
{
	struct fake_descriptor64	*fakep;
	union {
		struct real_gate64		gate;
		struct real_descriptor64	desc;
	}				real;
	int				i;

	fakep = (struct fake_descriptor64 *) descp;
	
	for (i = 0; i < count; i++, fakep++) {
		/*
		 * Construct the real decriptor locally.
		 */

		bzero((void *) &real, sizeof(real));

		switch (fakep->access & ACC_TYPE) {
		case 0:
			break;
		case ACC_CALL_GATE:
		case ACC_INTR_GATE:
		case ACC_TRAP_GATE:
			real.gate.offset_low16 = fakep->offset[0] & 0xFFFF;
			real.gate.selector16 = fakep->lim_or_seg & 0xFFFF;
			real.gate.IST = fakep->size_or_IST & 0x7;
			real.gate.access8 = fakep->access;
			real.gate.offset_high16 = (fakep->offset[0]>>16)&0xFFFF;
			real.gate.offset_top32 = (uint32_t)fakep->offset[1];
			break;
		default:	/* Otherwise */
			real.desc.limit_low16 = fakep->lim_or_seg & 0xFFFF;
			real.desc.base_low16 = fakep->offset[0] & 0xFFFF;
			real.desc.base_med8 = (fakep->offset[0] >> 16) & 0xFF;
			real.desc.access8 = fakep->access;
			real.desc.limit_high4 = (fakep->lim_or_seg >> 16) & 0xFF;
			real.desc.granularity4 = fakep->size_or_IST;
			real.desc.base_high8 = (fakep->offset[0] >> 24) & 0xFF;
			real.desc.base_top32 = (uint32_t) fakep->offset[1];
		}

		/*
		 * Now copy back over the fake structure.
		 */
		bcopy((void *) &real, (void *) fakep, sizeof(real));
	}
}

#if DEBUG
extern void dump_gdt(void *);
extern void dump_ldt(void *);
extern void dump_idt(void *);
extern void dump_tss(void *);
extern void dump_frame32(x86_saved_state_compat32_t *scp);
extern void dump_frame64(x86_saved_state64_t *scp);

void
dump_frame32(x86_saved_state_compat32_t *scp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) scp;

	kprintf("dump_frame32(0x%08x):\n", scp);
	
	for (i = 0;
	     i < sizeof(x86_saved_state_compat32_t)/sizeof(uint32_t);
	     i++, ip++)
		kprintf("0x%08x: 0x%08x\n", ip, *ip);

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
dump_frame64(x86_saved_state64_t *scp)
{
	unsigned int	i;
	uint64_t	*ip = (uint64_t *) scp;

	kprintf("dump_frame64(0x%08x):\n", scp);
	
	for (i = 0;
	     i < sizeof(x86_saved_state64_t)/sizeof(uint64_t);
	     i++, ip++)
		kprintf("0x%08x: 0x%016x\n", ip, *ip);

	kprintf("scp->isf.trapno: 0x%08x\n", scp->isf.trapno);
	kprintf("scp->isf.trapfn: 0x%08x\n", scp->isf.trapfn);
	kprintf("scp->isf.err:    0x%016llx\n", scp->isf.err);
	kprintf("scp->isf.rip:    0x%016llx\n", scp->isf.rip);
	kprintf("scp->isf.cs:     0x%016llx\n", scp->isf.cs);
	kprintf("scp->isf.rflags: 0x%016llx\n", scp->isf.rflags);
	kprintf("scp->isf.rsp:    0x%016llx\n", scp->isf.rsp);
	kprintf("scp->isf.ss:     0x%016llx\n", scp->isf.ss);

	kprintf("scp->fs:         0x%016llx\n", scp->fs);
	kprintf("scp->gs:         0x%016llx\n", scp->gs);
	kprintf("scp->rax:        0x%016llx\n", scp->rax);
	kprintf("scp->rcx:        0x%016llx\n", scp->rcx);
	kprintf("scp->rbx:        0x%016llx\n", scp->rbx);
	kprintf("scp->rbp:        0x%016llx\n", scp->rbp);
	kprintf("scp->r11:        0x%016llx\n", scp->r11);
	kprintf("scp->r12:        0x%016llx\n", scp->r12);
	kprintf("scp->r13:        0x%016llx\n", scp->r13);
	kprintf("scp->r14:        0x%016llx\n", scp->r14);
	kprintf("scp->r15:        0x%016llx\n", scp->r15);
	kprintf("scp->cr2:        0x%016llx\n", scp->cr2);
	kprintf("scp->v_arg8:     0x%016llx\n", scp->v_arg8);
	kprintf("scp->v_arg7:     0x%016llx\n", scp->v_arg7);
	kprintf("scp->v_arg6:     0x%016llx\n", scp->v_arg6);
	kprintf("scp->r9:         0x%016llx\n", scp->r9);
	kprintf("scp->r8:         0x%016llx\n", scp->r8);
	kprintf("scp->r10:        0x%016llx\n", scp->r10);
	kprintf("scp->rdx:        0x%016llx\n", scp->rdx);
	kprintf("scp->rsi:        0x%016llx\n", scp->rsi);
	kprintf("scp->rdi:        0x%016llx\n", scp->rdi);

	postcode(0x98);
}

void
dump_gdt(void *gdtp)
{
	unsigned int	i;
	uint32_t	*ip = (uint32_t *) gdtp;

	kprintf("GDT:\n", ip);
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

	kprintf("LDT:\n", ip);
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

	kprintf("IDT64:\n", ip);
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

	kprintf("TSS64:\n", ip);
	for (i = 0; i < sizeof(master_ktss64)/sizeof(uint32_t); i++, ip++) {
		kprintf("%p: 0x%08x\n", ip+0, *(ip+0));
	}
}
#endif /* DEBUG */
