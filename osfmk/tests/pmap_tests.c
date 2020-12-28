/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <kern/ledger.h>
#include <kern/thread.h>
#if defined(__arm64__)
#include <pexpert/arm64/board_config.h>
#if XNU_MONITOR
#include <arm64/ppl/tests/shart.h>
#endif
#endif

extern ledger_template_t task_ledger_template;

extern boolean_t arm_force_fast_fault(ppnum_t, vm_prot_t, int, void*);
extern kern_return_t arm_fast_fault(pmap_t, vm_map_address_t, vm_prot_t, bool, bool);

kern_return_t test_pmap_enter_disconnect(unsigned int num_loops);
kern_return_t test_pmap_iommu_disconnect(void);
kern_return_t test_pmap_extended(void);

#define PMAP_TEST_VA (0xDEAD << PAGE_SHIFT)

typedef struct {
	pmap_t pmap;
	volatile boolean_t stop;
	ppnum_t pn;
} pmap_test_thread_args;

static pmap_t
pmap_create_wrapper(unsigned int flags)
{
	pmap_t new_pmap = NULL;
	ledger_t ledger;
	assert(task_ledger_template != NULL);
	if ((ledger = ledger_instantiate(task_ledger_template, LEDGER_CREATE_ACTIVE_ENTRIES)) == NULL) {
		return NULL;
	}
	new_pmap = pmap_create_options(ledger, 0, flags);
	ledger_dereference(ledger);
	return new_pmap;
}

static void
pmap_disconnect_thread(void *arg, wait_result_t __unused wres)
{
	pmap_test_thread_args *args = arg;
	do {
		pmap_disconnect(args->pn);
	} while (!args->stop);
	thread_wakeup((event_t)args);
}

kern_return_t
test_pmap_enter_disconnect(unsigned int num_loops)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t disconnect_thread;
	pmap_t new_pmap = pmap_create_wrapper(0);
	if (new_pmap == NULL) {
		return KERN_FAILURE;
	}
	vm_page_t m = vm_page_grab();
	if (m == VM_PAGE_NULL) {
		pmap_destroy(new_pmap);
		return KERN_FAILURE;
	}
	ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);
	pmap_test_thread_args args = {new_pmap, FALSE, phys_page};
	kern_return_t res = kernel_thread_start(pmap_disconnect_thread, &args, &disconnect_thread);
	if (res) {
		pmap_destroy(new_pmap);
		vm_page_lock_queues();
		vm_page_free(m);
		vm_page_unlock_queues();
		return res;
	}
	thread_deallocate(disconnect_thread);

	while (num_loops-- != 0) {
		kr = pmap_enter(new_pmap, PMAP_TEST_VA, phys_page,
		    VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
		assert(kr == KERN_SUCCESS);
	}

	assert_wait((event_t)&args, THREAD_UNINT);
	args.stop = TRUE;
	thread_block(THREAD_CONTINUE_NULL);

	pmap_remove(new_pmap, PMAP_TEST_VA, PMAP_TEST_VA + PAGE_SIZE);
	vm_page_lock_queues();
	vm_page_free(m);
	vm_page_unlock_queues();
	pmap_destroy(new_pmap);
	return KERN_SUCCESS;
}

kern_return_t
test_pmap_iommu_disconnect(void)
{
#if XNU_MONITOR
	kern_return_t kr = KERN_SUCCESS;
	pmap_t new_pmap = pmap_create_wrapper(0);

	vm_page_t m = vm_page_grab();

	vm_page_lock_queues();
	if (m != VM_PAGE_NULL) {
		vm_page_wire(m, VM_KERN_MEMORY_PTE, TRUE);
	}
	vm_page_unlock_queues();

	shart_ppl *iommu = NULL;
	kr = pmap_iommu_init(shart_get_desc(), "sharttest0", NULL, 0, (ppl_iommu_state**)(&iommu));

	if (kr != KERN_SUCCESS) {
		goto cleanup;
	}

	if ((new_pmap == NULL) || (m == VM_PAGE_NULL) || (iommu == NULL)) {
		kr = KERN_FAILURE;
		goto cleanup;
	}

	ppnum_t phys_page = VM_PAGE_GET_PHYS_PAGE(m);

	const ppl_iommu_seg shart_segs[] = {
		{.iova = 0,
		 .paddr = ptoa(phys_page),
		 .nbytes = PAGE_SIZE,
		 .prot = VM_PROT_READ,
		 .refcon = 0},

		{.iova = 1,
		 .paddr = ptoa(phys_page),
		 .nbytes = PAGE_SIZE,
		 .prot = VM_PROT_READ | VM_PROT_WRITE,
		 .refcon = 0},

		{.iova = 2,
		 .paddr = ptoa(phys_page),
		 .nbytes = PAGE_SIZE,
		 .prot = VM_PROT_READ,
		 .refcon = 0},

		{.iova = 3,
		 .paddr = ptoa(phys_page),
		 .nbytes = PAGE_SIZE,
		 .prot = VM_PROT_READ,
		 .refcon = 0}
	};

	/* Phase 1: one CPU mapping */
	kr = pmap_enter(new_pmap, PMAP_TEST_VA, phys_page, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(pmap_verify_free(phys_page));

	/* Phase 2: two CPU mappings */
	kr = pmap_enter(new_pmap, PMAP_TEST_VA, phys_page, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(new_pmap, PMAP_TEST_VA + PAGE_SIZE, phys_page, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(pmap_verify_free(phys_page));

	/* Phase 3: one IOMMU mapping */
	kr = pmap_iommu_map(&iommu->super, shart_segs, 1, 0, NULL);
	assert(kr == KERN_SUCCESS);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(!pmap_verify_free(phys_page));
	pmap_iommu_unmap(&iommu->super, shart_segs, 1, 0, NULL);
	assert(pmap_verify_free(phys_page));

	/* Phase 4: two IOMMU mappings */
	kr = pmap_iommu_map(&iommu->super, shart_segs, 2, 0, NULL);
	assert(kr == KERN_SUCCESS);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(!pmap_verify_free(phys_page));
	pmap_iommu_unmap(&iommu->super, &shart_segs[1], 1, 0, NULL);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(!pmap_verify_free(phys_page));
	pmap_iommu_unmap(&iommu->super, shart_segs, 1, 0, NULL);
	assert(pmap_verify_free(phys_page));

	/* Phase 5: combined CPU and IOMMU mappings */
	kr = pmap_iommu_map(&iommu->super, shart_segs, 1, 0, NULL);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(new_pmap, PMAP_TEST_VA, phys_page, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	kr = pmap_iommu_map(&iommu->super, &shart_segs[1], 2, 0, NULL);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(new_pmap, PMAP_TEST_VA + PAGE_SIZE, phys_page, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	kr = pmap_iommu_map(&iommu->super, &shart_segs[3], 1, 0, NULL);
	assert(kr == KERN_SUCCESS);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(!pmap_verify_free(phys_page));
	pmap_iommu_unmap(&iommu->super, shart_segs, 4, 0, NULL);
	assert(pmap_verify_free(phys_page));

	/* Phase 6: differently combined CPU and IOMMU mappings */
	kr = pmap_enter(new_pmap, PMAP_TEST_VA, phys_page, VM_PROT_READ | VM_PROT_WRITE, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	kr = pmap_iommu_map(&iommu->super, &shart_segs[1], 3, 0, NULL);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(new_pmap, PMAP_TEST_VA + PAGE_SIZE, phys_page, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	kr = pmap_iommu_map(&iommu->super, shart_segs, 1, 0, NULL);
	assert(kr == KERN_SUCCESS);
	kr = pmap_enter(new_pmap, PMAP_TEST_VA + (2 * PAGE_SIZE), phys_page, VM_PROT_READ, VM_PROT_NONE, VM_WIMG_USE_DEFAULT, FALSE);
	assert(kr == KERN_SUCCESS);
	assert(!pmap_verify_free(phys_page));
	pmap_iommu_unmap(&iommu->super, &shart_segs[2], 1, 0, NULL);
	assert(!pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(!pmap_verify_free(phys_page));
	pmap_iommu_unmap(&iommu->super, shart_segs, 4, 0, NULL);
	assert(pmap_verify_free(phys_page));
	pmap_disconnect(phys_page);
	assert(pmap_verify_free(phys_page));

cleanup:

	if (iommu != NULL) {
		pmap_iommu_ioctl(&iommu->super, SHART_IOCTL_TEARDOWN, NULL, 0, NULL, 0);
	}
	vm_page_lock_queues();
	if (m != VM_PAGE_NULL) {
		vm_page_free(m);
	}
	vm_page_unlock_queues();
	if (new_pmap != NULL) {
		pmap_destroy(new_pmap);
	}

	return kr;
#else
	return KERN_SUCCESS;
#endif
}

kern_return_t
test_pmap_extended(void)
{
	return KERN_SUCCESS;
}
