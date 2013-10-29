/*
 * Copyright (c) 2006-2012 Apple Inc. All rights reserved.
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

#include <pexpert/pexpert.h>
#include <i386/cpuid.h>
#include <i386/cpu_data.h>
#include <i386/mp.h>
#include <i386/proc_reg.h>
#include <i386/vmx.h>
#include <i386/vmx/vmx_asm.h>
#include <i386/vmx/vmx_shims.h>
#include <i386/vmx/vmx_cpu.h>
#include <mach/mach_host.h>             /* for host_info() */

#define VMX_KPRINTF(x...) /* kprintf("vmx: " x) */

int vmx_use_count = 0;
boolean_t vmx_exclusive = FALSE;
decl_simple_lock_data(static,vmx_use_count_lock)

/* -----------------------------------------------------------------------------
   vmx_is_available()
	Is the VMX facility available on this CPU?
   -------------------------------------------------------------------------- */
static inline boolean_t
vmx_is_available(void)
{
	return (0 != (cpuid_features() & CPUID_FEATURE_VMX));
}

/* -----------------------------------------------------------------------------
   vmxon_is_enabled()
	Is the VMXON instruction enabled on this CPU?
   -------------------------------------------------------------------------- */
static inline boolean_t
vmxon_is_enabled(void)
{
	return (vmx_is_available() &&
		(rdmsr64(MSR_IA32_FEATURE_CONTROL) & MSR_IA32_FEATCTL_VMXON));
}

/* -----------------------------------------------------------------------------
   vmx_is_cr0_valid()
	Is CR0 valid for executing VMXON on this CPU?
   -------------------------------------------------------------------------- */
static inline boolean_t
vmx_is_cr0_valid(vmx_specs_t *specs)
{
	uintptr_t cr0 = get_cr0();
	return (0 == ((~cr0 & specs->cr0_fixed_0)|(cr0 & ~specs->cr0_fixed_1)));
}

/* -----------------------------------------------------------------------------
   vmx_is_cr4_valid()
	Is CR4 valid for executing VMXON on this CPU?
   -------------------------------------------------------------------------- */
static inline boolean_t
vmx_is_cr4_valid(vmx_specs_t *specs)
{
	uintptr_t cr4 = get_cr4();
	return (0 == ((~cr4 & specs->cr4_fixed_0)|(cr4 & ~specs->cr4_fixed_1)));
}

static void
vmx_init(void)
{
	uint64_t msr_image;

	if (!vmx_is_available())
		return;

	/*
	 * We don't count on EFI initializing MSR_IA32_FEATURE_CONTROL
	 * and turning VMXON on and locking the bit, so we do that now.
	 */
	msr_image = rdmsr64(MSR_IA32_FEATURE_CONTROL);
	if (0 == ((msr_image & MSR_IA32_FEATCTL_LOCK)))
		wrmsr64(MSR_IA32_FEATURE_CONTROL,
			(msr_image |
			 MSR_IA32_FEATCTL_VMXON |
			 MSR_IA32_FEATCTL_LOCK));
}

/* -----------------------------------------------------------------------------
   vmx_get_specs()
	Obtain VMX facility specifications for this CPU and
	enter them into the vmx_specs_t structure. If VMX is not available or
	disabled on this CPU, set vmx_present to false and return leaving
	the remainder of the vmx_specs_t uninitialized. 
   -------------------------------------------------------------------------- */
void
vmx_get_specs()
{
	vmx_specs_t *specs = &current_cpu_datap()->cpu_vmx.specs;
	uint64_t msr_image;
	
	/* this is called once for every CPU, but the lock doesn't care :-) */
	simple_lock_init(&vmx_use_count_lock, 0);

	vmx_init();

	/*
	 * if we have read the data on boot, we won't read it
	 *  again on wakeup, otherwise *bad* things will happen
	 */
	if (specs->initialized)
		return;
	else
		specs->initialized = TRUE;

	/* See if VMX is present, return if it is not */
	specs->vmx_present = vmx_is_available() && vmxon_is_enabled();
	if (!specs->vmx_present)
		return;

#define bitfield(x,f)	((x >> f##_BIT) & f##_MASK)
	/* Obtain and decode VMX general capabilities */	
	msr_image = rdmsr64(MSR_IA32_VMX_BASIC);
	specs->vmcs_id       = (uint32_t)(msr_image & VMX_VCR_VMCS_REV_ID);
	specs->vmcs_mem_type = bitfield(msr_image, VMX_VCR_VMCS_MEM_TYPE) != 0;
	specs->vmcs_size = bitfield(msr_image, VMX_VCR_VMCS_SIZE);
							  
	/* Obtain allowed settings for pin-based execution controls */
	msr_image = rdmsr64(MSR_IA32_VMXPINBASED_CTLS);
	specs->pin_exctls_0 = (uint32_t)(msr_image & 0xFFFFFFFF);
	specs->pin_exctls_1 = (uint32_t)(msr_image >> 32);
	
	/* Obtain allowed settings for processor-based execution controls */
	msr_image = rdmsr64(MSR_IA32_PROCBASED_CTLS);
	specs->proc_exctls_0 = (uint32_t)(msr_image & 0xFFFFFFFF);
	specs->proc_exctls_1 = (uint32_t)(msr_image >> 32);
	
	/* Obtain allowed settings for VM-exit controls */
	msr_image = rdmsr64(MSR_IA32_VMX_EXIT_CTLS);
	specs->exit_ctls_0 = (uint32_t)(msr_image & 0xFFFFFFFF);
	specs->exit_ctls_1 = (uint32_t)(msr_image >> 32);
	
	/* Obtain allowed settings for VM-entry controls */
	msr_image = rdmsr64(MSR_IA32_VMX_ENTRY_CTLS);
	specs->enter_ctls_0 = (uint32_t)(msr_image & 0xFFFFFFFF);
	specs->enter_ctls_0 = (uint32_t)(msr_image >> 32);
	
	/* Obtain and decode miscellaneous capabilities */
	msr_image = rdmsr64(MSR_IA32_VMX_MISC);
	specs->act_halt     = bitfield(msr_image, VMX_VCR_ACT_HLT) != 0;
	specs->act_shutdown = bitfield(msr_image, VMX_VCR_ACT_SHUTDOWN) != 0;
	specs->act_SIPI     = bitfield(msr_image, VMX_VCR_ACT_SIPI) != 0;
	specs->act_CSTATE   = bitfield(msr_image, VMX_VCR_ACT_CSTATE) != 0;
	specs->cr3_targs    = bitfield(msr_image, VMX_VCR_CR3_TARGS);
	specs->max_msrs     = (uint32_t)(512 * (1 + bitfield(msr_image, VMX_VCR_MAX_MSRS)));
	specs->mseg_id      = (uint32_t)bitfield(msr_image, VMX_VCR_MSEG_ID);
	
	/* Obtain VMX-fixed bits in CR0 */
	specs->cr0_fixed_0 = (uint32_t)rdmsr64(MSR_IA32_VMX_CR0_FIXED0) & 0xFFFFFFFF;
	specs->cr0_fixed_1 = (uint32_t)rdmsr64(MSR_IA32_VMX_CR0_FIXED1) & 0xFFFFFFFF;
	
	/* Obtain VMX-fixed bits in CR4 */
	specs->cr4_fixed_0 = (uint32_t)rdmsr64(MSR_IA32_VMX_CR4_FIXED0) & 0xFFFFFFFF;
	specs->cr4_fixed_1 = (uint32_t)rdmsr64(MSR_IA32_VMX_CR4_FIXED1) & 0xFFFFFFFF;
}

/* -----------------------------------------------------------------------------
   vmx_on()
	Enter VMX root operation on this CPU.
   -------------------------------------------------------------------------- */
static void
vmx_on(void *arg __unused)
{
	vmx_cpu_t *cpu = &current_cpu_datap()->cpu_vmx;
	addr64_t vmxon_region_paddr;
	int result;

	vmx_init();
	
	assert(cpu->specs.vmx_present);

	if (NULL == cpu->vmxon_region)
		panic("vmx_on: VMXON region not allocated");
	vmxon_region_paddr = vmx_paddr(cpu->vmxon_region);

	/*
	 * Enable VMX operation.
	 */
	set_cr4(get_cr4() | CR4_VMXE);
	
	assert(vmx_is_cr0_valid(&cpu->specs));
	assert(vmx_is_cr4_valid(&cpu->specs));
	
	result = __vmxon(vmxon_region_paddr);

	if (result != VMX_SUCCEED) {
		panic("vmx_on: unexpected return %d from __vmxon()", result);
	}
}

/* -----------------------------------------------------------------------------
   vmx_off()
	Leave VMX root operation on this CPU.
   -------------------------------------------------------------------------- */
static void
vmx_off(void *arg __unused)
{
	int result;
	
	/* Tell the CPU to release the VMXON region */
	result = __vmxoff();

	if (result != VMX_SUCCEED) {
		panic("vmx_off: unexpected return %d from __vmxoff()", result);
	}

	set_cr4(get_cr4() & ~CR4_VMXE);
}

/* -----------------------------------------------------------------------------
   vmx_allocate_vmxon_regions()
	Allocate, clear and init VMXON regions for all CPUs.
   -------------------------------------------------------------------------- */
static void
vmx_allocate_vmxon_regions(void)
{
	unsigned int i;
	
	for (i=0; i<real_ncpus; i++) {
		vmx_cpu_t *cpu = &cpu_datap(i)->cpu_vmx;

		/* The size is defined to be always <= 4K, so we just allocate a page */
		cpu->vmxon_region = vmx_pcalloc();
		if (NULL == cpu->vmxon_region)
			panic("vmx_allocate_vmxon_regions: unable to allocate VMXON region");
		*(uint32_t*)(cpu->vmxon_region) = cpu->specs.vmcs_id;
	}
}

/* -----------------------------------------------------------------------------
   vmx_free_vmxon_regions()
	Free VMXON regions for all CPUs.
   -------------------------------------------------------------------------- */
static void
vmx_free_vmxon_regions(void)
{
	unsigned int i;

	for (i=0; i<real_ncpus; i++) {
		vmx_cpu_t *cpu = &cpu_datap(i)->cpu_vmx;

		vmx_pfree(cpu->vmxon_region);
		cpu->vmxon_region = NULL;
	}
}

/* -----------------------------------------------------------------------------
   vmx_globally_available()
	Checks whether VT can be turned on for all CPUs.
   -------------------------------------------------------------------------- */
static boolean_t
vmx_globally_available(void)
{
	unsigned int i;
	
	boolean_t available = TRUE;

	for (i=0; i<real_ncpus; i++) {
		vmx_cpu_t *cpu = &cpu_datap(i)->cpu_vmx;

		if (!cpu->specs.vmx_present)
			available = FALSE;
	}
	VMX_KPRINTF("VMX available: %d\n", available);
	return available;
}


/* -----------------------------------------------------------------------------
   vmx_turn_on()
	Turn on VT operation on all CPUs.
   -------------------------------------------------------------------------- */
int
host_vmxon(boolean_t exclusive)
{
	int error;
	boolean_t do_it = FALSE; /* do the cpu sync outside of the area holding the lock */

	if (!vmx_globally_available())
		return VMX_UNSUPPORTED;

	simple_lock(&vmx_use_count_lock);

	if (vmx_exclusive) {
		error = VMX_INUSE;
	} else {
		vmx_use_count++;
		if (vmx_use_count == 1) /* was turned off before */
			do_it = TRUE;
		vmx_exclusive = exclusive;

		VMX_KPRINTF("VMX use count: %d\n", vmx_use_count);
		error = VMX_OK;
	}

	simple_unlock(&vmx_use_count_lock);

	if (do_it) {
		vmx_allocate_vmxon_regions();
		mp_rendezvous(NULL, vmx_on, NULL, NULL);
	}
	return error;
}

/* -----------------------------------------------------------------------------
   vmx_turn_off()
	Turn off VT operation on all CPUs.
   -------------------------------------------------------------------------- */
void
host_vmxoff()
{
	boolean_t do_it = FALSE; /* do the cpu sync outside of the area holding the lock */

	simple_lock(&vmx_use_count_lock);

	if (vmx_use_count) {
		vmx_use_count--;
		vmx_exclusive = FALSE;
		if (!vmx_use_count)
			do_it = TRUE;
	}

	simple_unlock(&vmx_use_count_lock);

	if (do_it) {
		mp_rendezvous(NULL, vmx_off, NULL, NULL);
		vmx_free_vmxon_regions();
	}

	VMX_KPRINTF("VMX use count: %d\n", vmx_use_count);
}

/* -----------------------------------------------------------------------------
   vmx_suspend()
	Turn off VT operation on this CPU if it was on.
	Called when a CPU goes offline.
   -------------------------------------------------------------------------- */
void
vmx_suspend()
{
	VMX_KPRINTF("vmx_suspend\n");
	if (vmx_use_count)
		vmx_off(NULL);
}

/* -----------------------------------------------------------------------------
   vmx_suspend()
	Restore the previous VT state. Called when CPU comes back online.
   -------------------------------------------------------------------------- */
void
vmx_resume()
{
	VMX_KPRINTF("vmx_resume\n");
	vmx_init(); /* init VMX on CPU #0 */
	if (vmx_use_count)
		vmx_on(NULL);
}
