/*
 * Test voucher trap APIs.
 * There was an unfortunate bug in the trap interface that used the user space
 * _address_ of a trap parameter as a copyin size. This test validates there
 * are no other kernel panics in the voucher create and voucher attribute
 * extraction mach traps.
 *
 * clang -o voucher_traps voucher_traps.c -ldarwintest -Weverything -Wno-gnu-flexible-array-initializer
 *
 * <rdar://problem/29379175>
 */

#include <stdint.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_traps.h>

#include <atm/atm_types.h>

#include <darwintest.h>


static mach_port_t
get_atm_voucher(void)
{
	mach_voucher_attr_recipe_data_t r = {
		.key = MACH_VOUCHER_ATTR_KEY_ATM,
		.command = MACH_VOUCHER_ATTR_ATM_CREATE
	};
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = host_create_mach_voucher(mach_host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&r,
	    sizeof(r), &port);
	T_ASSERT_MACH_SUCCESS(kr, "Create ATM voucher: 0x%x", (unsigned int)port);

	return port;
}


T_DECL(voucher_extract_attr_recipe, "voucher_extract_attr_recipe")
{
	kern_return_t kr;
	mach_vm_size_t alloc_sz;
	mach_port_t port;
	mach_vm_address_t alloc_addr;

	/* map at least a page of memory at some arbitrary location */
	alloc_sz = (mach_vm_size_t)round_page(MACH_VOUCHER_TRAP_STACK_LIMIT + 1);

	/*
	 * We could theoretically ask for a fixed location, but this is more
	 * reliable, and we're not actually trying to exploit anything - a
	 * kernel panic on failure should suffice :-)
	 */
	alloc_addr = (mach_vm_address_t)round_page(MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE + 1);
	kr = mach_vm_allocate(mach_task_self(), &alloc_addr,
	    alloc_sz, VM_FLAGS_ANYWHERE);

	/*
	 * Make sure that the address of the allocation is larger than the
	 * maximum recipe size: this will test for the bug that was fixed in
	 * <rdar://problem/29379175>.
	 */
	T_ASSERT_GT_ULLONG((uint64_t)alloc_addr,
	    (uint64_t)MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE,
	    "Recipe addr (%llu bytes): 0x%llx > max recipe sz: %llu",
	    (uint64_t)alloc_sz, (uint64_t)alloc_addr,
	    (uint64_t)MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE);

	/* make the allocation look like a pointer to an int */
	mach_msg_type_number_t *recipe_size;
	recipe_size = (mach_msg_type_number_t *)((uintptr_t)alloc_addr);
	bzero(recipe_size, (unsigned long)alloc_sz);
	if (alloc_sz > MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE) {
		*recipe_size = MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE;
	} else {
		*recipe_size = (mach_msg_type_number_t)alloc_sz;
	}

	/* recipe buffer on the heap: memset it so panics show up loudly */
	size_t size = (size_t)(10 * 1024 * 1024);
	void *recipe = malloc(size);
	memset(recipe, 0x41, size);

	port = get_atm_voucher();

	/*
	 * This should try to extract the ATM attribute using a buffer on the
	 * kernel heap (probably zone memory).
	 */
	kr = mach_voucher_extract_attr_recipe_trap(port, MACH_VOUCHER_ATTR_KEY_ATM,
	    recipe, recipe_size);
	T_ASSERT_MACH_SUCCESS(kr, "Extract attribute data with recipe: heap");

	/* reset the recipe memory */
	memset(recipe, 0x41, size);
	/* reduce the size to get an allocation on the kernel stack */
	*recipe_size = MACH_VOUCHER_TRAP_STACK_LIMIT - 1;

	/*
	 * This should try to extract the ATM attribute using a buffer on the
	 * kernel stack.
	 */
	kr = mach_voucher_extract_attr_recipe_trap(port, MACH_VOUCHER_ATTR_KEY_ATM,
	    recipe, recipe_size);
	T_ASSERT_MACH_SUCCESS(kr, "Extract attribute data with recipe: stack");

	/* cleanup */

	free(recipe);
	kr = mach_vm_deallocate(mach_task_self(), alloc_addr, alloc_sz);
	T_ASSERT_MACH_SUCCESS(kr, "Deallocate recipe buffers");
}
