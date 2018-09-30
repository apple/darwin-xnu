/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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
 *  ucode.c
 *
 *  Microcode updater interface sysctl
 */

#include <kern/locks.h>
#include <i386/ucode.h>
#include <sys/errno.h>
#include <i386/proc_reg.h>
#include <i386/cpuid.h>
#include <vm/vm_kern.h>
#include <i386/mp.h>			// mp_broadcast
#include <i386/fpu.h>
#include <machine/cpu_number.h> // cpu_number
#include <pexpert/pexpert.h>  // boot-args

#define IA32_BIOS_UPDT_TRIG (0x79) /* microcode update trigger MSR */

struct intel_ucupdate *global_update = NULL;

/* Exceute the actual update! */
static void
update_microcode(void)
{
	/* SDM Example 9-8 code shows that we load the
	 * address of the UpdateData within the microcode blob,
	 * not the address of the header.
	 */
	wrmsr64(IA32_BIOS_UPDT_TRIG, (uint64_t)(uintptr_t)&global_update->data);
}

/* locks */
static lck_grp_attr_t *ucode_slock_grp_attr = NULL;
static lck_grp_t *ucode_slock_grp = NULL;
static lck_attr_t *ucode_slock_attr = NULL;
static lck_spin_t *ucode_slock = NULL;

static kern_return_t
register_locks(void)
{
	/* already allocated? */
	if (ucode_slock_grp_attr && ucode_slock_grp && ucode_slock_attr && ucode_slock)
		return KERN_SUCCESS;

	/* allocate lock group attribute and group */
	if (!(ucode_slock_grp_attr = lck_grp_attr_alloc_init()))
		goto nomem_out;

	lck_grp_attr_setstat(ucode_slock_grp_attr);

	if (!(ucode_slock_grp = lck_grp_alloc_init("uccode_lock", ucode_slock_grp_attr)))
		goto nomem_out;

	/* Allocate lock attribute */
	if (!(ucode_slock_attr = lck_attr_alloc_init()))
		goto nomem_out;

	/* Allocate the spin lock */
	/* We keep one global spin-lock. We could have one per update
	 * request... but srsly, why would you update microcode like that?
	 */
	if (!(ucode_slock = lck_spin_alloc_init(ucode_slock_grp, ucode_slock_attr)))
		goto nomem_out;

	return KERN_SUCCESS;

nomem_out:
	/* clean up */
	if (ucode_slock)
		lck_spin_free(ucode_slock, ucode_slock_grp);
	if (ucode_slock_attr)
		lck_attr_free(ucode_slock_attr);
	if (ucode_slock_grp)
		lck_grp_free(ucode_slock_grp);
	if (ucode_slock_grp_attr)
		lck_grp_attr_free(ucode_slock_grp_attr);

	return KERN_NO_SPACE;
}

/* Copy in an update */
static int
copyin_update(uint64_t inaddr)
{
	struct intel_ucupdate update_header;
	struct intel_ucupdate *update;
	vm_size_t size;
	kern_return_t ret;
	int error;

	/* Copy in enough header to peek at the size */
	error = copyin((user_addr_t)inaddr, (void *)&update_header, sizeof(update_header));
	if (error)
		return error;

	/* Get the actual, alleged size */
	size = update_header.total_size;

	/* huge bogus piece of data that somehow made it through? */
	if (size >= 1024 * 1024)
		return ENOMEM;

	/* Old microcodes? */
	if (size == 0)
		size = 2048; /* default update size; see SDM */

	/*
	 * create the buffer for the update
	 * It need only be aligned to 16-bytes, according to the SDM.
	 * This also wires it down
	 */
	ret = kmem_alloc_kobject(kernel_map, (vm_offset_t *)&update, size, VM_KERN_MEMORY_OSFMK);
	if (ret != KERN_SUCCESS)
		return ENOMEM;

	/* Copy it in */
	error = copyin((user_addr_t)inaddr, (void*)update, size);
	if (error) {
		kmem_free(kernel_map, (vm_offset_t)update, size);
		return error;
	}

	global_update = update;
	return 0;
}

/*
 * This is called once by every CPU on a wake from sleep/hibernate
 * and is meant to re-apply a microcode update that got lost
 * by sleeping.
 */
void
ucode_update_wake()
{
	if (global_update) {
		kprintf("ucode: Re-applying update after wake (CPU #%d)\n", cpu_number());
		update_microcode();
#if DEBUG
	} else {
		kprintf("ucode: No update to apply (CPU #%d)\n", cpu_number());
#endif
	}
}

static void
cpu_update(__unused void *arg)
{
	/* grab the lock */
	lck_spin_lock(ucode_slock);

	/* execute the update */
	update_microcode();

	/* release the lock */
	lck_spin_unlock(ucode_slock);
}

static void
ucode_cpuid_set_info(void)
{
	uint64_t saved_xcr0, dest_xcr0;
	int need_xcr0_restore = 0;
	boolean_t intrs_enabled = ml_set_interrupts_enabled(FALSE);

	/*
	 * Before we cache the CPUID information, we must configure XCR0 with the maximal set of
	 * features to ensure the save area returned in the xsave leaf is correctly-sized.
	 *
	 * Since we are guaranteed that init_fpu() has already happened, we can use state
	 * variables set there that were already predicated on the presence of explicit
	 * boot-args enables/disables.
	 */

	if (fpu_capability == AVX512 || fpu_capability == AVX) {
		saved_xcr0 = xgetbv(XCR0);
		dest_xcr0 = (fpu_capability == AVX512) ? AVX512_XMASK : AVX_XMASK;
		assert((get_cr4() & CR4_OSXSAVE) != 0);
		if (saved_xcr0 != dest_xcr0) {
			need_xcr0_restore = 1;
			xsetbv(dest_xcr0 >> 32, dest_xcr0 & 0xFFFFFFFFUL);
		}
	}

	cpuid_set_info();

	if (need_xcr0_restore) {
		xsetbv(saved_xcr0 >> 32, saved_xcr0 & 0xFFFFFFFFUL);
	}

	ml_set_interrupts_enabled(intrs_enabled);
}

/* Farm an update out to all CPUs */
static void
xcpu_update(void)
{
	if (register_locks() != KERN_SUCCESS)
		return;

	/* Get all CPUs to perform the update */
	mp_broadcast(cpu_update, NULL);

	/* Update the cpuid info */
	ucode_cpuid_set_info();
}

/*
 * sysctl function
 *
 */
int
ucode_interface(uint64_t addr)
{
	int error;
	char arg[16]; 

	if (PE_parse_boot_argn("-x", arg, sizeof (arg))) {
		printf("ucode: no updates in safe mode\n");
		return EPERM;
	}

#if !DEBUG
	/*
	 * Userland may only call this once per boot. Anything else
	 * would not make sense (all updates are cumulative), and also
	 * leak memory, because we don't free previous updates.
	 */
	if (global_update)
		return EPERM;
#endif

	/* Get the whole microcode */
	error = copyin_update(addr);

	if (error)
		return error;

	/* Farm out the updates */
	xcpu_update();

	return 0;
}
