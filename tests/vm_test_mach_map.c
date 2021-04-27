/* Mach vm map miscellaneous unit tests
 *
 * This test program serves to be a regression test suite for legacy
 * vm issues, ideally each test will be linked to a radar number and
 * perform a set of certain validations.
 *
 */
#include <darwintest.h>

#include <dlfcn.h>
#include <errno.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>

#include <mach/mach_error.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/shared_region.h>
#include <machine/cpu_capabilities.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"),
    T_META_RUN_CONCURRENTLY(true));

static void
test_memory_entry_tagging(int override_tag)
{
	int                     pass;
	int                     do_copy;
	kern_return_t           kr;
	mach_vm_address_t       vmaddr_orig, vmaddr_shared, vmaddr_copied;
	mach_vm_size_t          vmsize_orig, vmsize_shared, vmsize_copied;
	mach_vm_address_t       *vmaddr_ptr;
	mach_vm_size_t          *vmsize_ptr;
	mach_vm_address_t       vmaddr_chunk;
	mach_vm_size_t          vmsize_chunk;
	mach_vm_offset_t        vmoff;
	mach_port_t             mem_entry_copied, mem_entry_shared;
	mach_port_t             *mem_entry_ptr;
	int                     i;
	vm_region_submap_short_info_data_64_t ri;
	mach_msg_type_number_t  ri_count;
	unsigned int            depth;
	int                     vm_flags;
	int                     expected_tag;

	vmaddr_copied = 0;
	vmaddr_shared = 0;
	vmsize_copied = 0;
	vmsize_shared = 0;
	vmaddr_chunk = 0;
	vmsize_chunk = 16 * 1024;
	vmaddr_orig = 0;
	vmsize_orig = 3 * vmsize_chunk;
	mem_entry_copied = MACH_PORT_NULL;
	mem_entry_shared = MACH_PORT_NULL;
	pass = 0;

	vmaddr_orig = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr_orig,
	    vmsize_orig,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d] vm_allocate(%lld)",
	    override_tag, vmsize_orig);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (i = 0; i < vmsize_orig / vmsize_chunk; i++) {
		vmaddr_chunk = vmaddr_orig + (i * vmsize_chunk);
		kr = mach_vm_allocate(mach_task_self(),
		    &vmaddr_chunk,
		    vmsize_chunk,
		    (VM_FLAGS_FIXED |
		    VM_FLAGS_OVERWRITE |
		    VM_MAKE_TAG(100 + i)));
		T_QUIET;
		T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d] vm_allocate(%lld)",
		    override_tag, vmsize_chunk);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}

	for (vmoff = 0;
	    vmoff < vmsize_orig;
	    vmoff += PAGE_SIZE) {
		*((unsigned char *)(uintptr_t)(vmaddr_orig + vmoff)) = 'x';
	}

	do_copy = time(NULL) & 1;
again:
	*((unsigned char *)(uintptr_t)vmaddr_orig) = 'x';
	if (do_copy) {
		mem_entry_ptr = &mem_entry_copied;
		vmsize_copied = vmsize_orig;
		vmsize_ptr = &vmsize_copied;
		vmaddr_copied = 0;
		vmaddr_ptr = &vmaddr_copied;
		vm_flags = MAP_MEM_VM_COPY;
	} else {
		mem_entry_ptr = &mem_entry_shared;
		vmsize_shared = vmsize_orig;
		vmsize_ptr = &vmsize_shared;
		vmaddr_shared = 0;
		vmaddr_ptr = &vmaddr_shared;
		vm_flags = MAP_MEM_VM_SHARE;
	}
	kr = mach_make_memory_entry_64(mach_task_self(),
	    vmsize_ptr,
	    vmaddr_orig,                            /* offset */
	    (vm_flags |
	    VM_PROT_READ | VM_PROT_WRITE),
	    mem_entry_ptr,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d][do_copy:%d] mach_make_memory_entry()",
	    override_tag, do_copy);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_EQ(*vmsize_ptr, vmsize_orig, "[override_tag:%d][do_copy:%d] vmsize (0x%llx) != vmsize_orig (0x%llx)",
	    override_tag, do_copy, (uint64_t) *vmsize_ptr, (uint64_t) vmsize_orig);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_NOTNULL(*mem_entry_ptr, "[override_tag:%d][do_copy:%d] mem_entry == 0x%x",
	    override_tag, do_copy, *mem_entry_ptr);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	*vmaddr_ptr = 0;
	if (override_tag) {
		vm_flags = VM_MAKE_TAG(200);
	} else {
		vm_flags = 0;
	}
	kr = mach_vm_map(mach_task_self(),
	    vmaddr_ptr,
	    vmsize_orig,
	    0,              /* mask */
	    vm_flags | VM_FLAGS_ANYWHERE,
	    *mem_entry_ptr,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d][do_copy:%d] mach_vm_map()",
	    override_tag, do_copy);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	*((unsigned char *)(uintptr_t)vmaddr_orig) = 'X';
	if (*(unsigned char *)(uintptr_t)*vmaddr_ptr == 'X') {
		T_QUIET;
		T_EXPECT_EQ(do_copy, 0, "[override_tag:%d][do_copy:%d] memory shared instead of copied",
		    override_tag, do_copy);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	} else {
		T_QUIET;
		T_EXPECT_NE(do_copy, 0, "[override_tag:%d][do_copy:%d] memory copied instead of shared",
		    override_tag, do_copy);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}

	for (i = 0; i < vmsize_orig / vmsize_chunk; i++) {
		mach_vm_address_t       vmaddr_info;
		mach_vm_size_t          vmsize_info;

		vmaddr_info = *vmaddr_ptr + (i * vmsize_chunk);
		vmsize_info = 0;
		depth = 1;
		ri_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr_info,
		    &vmsize_info,
		    &depth,
		    (vm_region_recurse_info_t) &ri,
		    &ri_count);
		T_QUIET;
		T_EXPECT_MACH_SUCCESS(kr, "[override_tag:%d][do_copy:%d] mach_vm_region_recurse(0x%llx+0x%llx)",
		    override_tag, do_copy, *vmaddr_ptr, i * vmsize_chunk);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
		T_QUIET;
		T_EXPECT_EQ(vmaddr_info, *vmaddr_ptr + (i * vmsize_chunk), "[override_tag:%d][do_copy:%d] mach_vm_region_recurse(0x%llx+0x%llx) returned addr 0x%llx",
		    override_tag, do_copy, *vmaddr_ptr, i * vmsize_chunk, vmaddr_info);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
		T_QUIET;
		T_EXPECT_EQ(vmsize_info, vmsize_chunk, "[override_tag:%d][do_copy:%d] mach_vm_region_recurse(0x%llx+0x%llx) returned size 0x%llx expected 0x%llx",
		    override_tag, do_copy, *vmaddr_ptr, i * vmsize_chunk, vmsize_info, vmsize_chunk);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
		if (override_tag) {
			expected_tag = 200;
		} else {
			expected_tag = 100 + i;
		}
		T_QUIET;
		T_EXPECT_EQ(ri.user_tag, expected_tag, "[override_tag:%d][do_copy:%d] i=%d tag=%d expected %d",
		    override_tag, do_copy, i, ri.user_tag, expected_tag);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}

	if (++pass < 2) {
		do_copy = !do_copy;
		goto again;
	}

done:
	if (vmaddr_orig != 0) {
		mach_vm_deallocate(mach_task_self(),
		    vmaddr_orig,
		    vmsize_orig);
		vmaddr_orig = 0;
		vmsize_orig = 0;
	}
	if (vmaddr_copied != 0) {
		mach_vm_deallocate(mach_task_self(),
		    vmaddr_copied,
		    vmsize_copied);
		vmaddr_copied = 0;
		vmsize_copied = 0;
	}
	if (vmaddr_shared != 0) {
		mach_vm_deallocate(mach_task_self(),
		    vmaddr_shared,
		    vmsize_shared);
		vmaddr_shared = 0;
		vmsize_shared = 0;
	}
	if (mem_entry_copied != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), mem_entry_copied);
		mem_entry_copied = MACH_PORT_NULL;
	}
	if (mem_entry_shared != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), mem_entry_shared);
		mem_entry_shared = MACH_PORT_NULL;
	}

	return;
}

static void
test_map_memory_entry(void)
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize1, vmsize2;
	mach_port_t             mem_entry;
	unsigned char           *cp1, *cp2;

	vmaddr1 = 0;
	vmsize1 = 0;
	vmaddr2 = 0;
	vmsize2 = 0;
	mem_entry = MACH_PORT_NULL;

	vmsize1 = 1;
	vmaddr1 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate(%lld)", vmsize1);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	cp1 = (unsigned char *)(uintptr_t)vmaddr1;
	*cp1 = '1';

	vmsize2 = 1;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &vmsize2,
	    vmaddr1,                            /* offset */
	    (MAP_MEM_VM_COPY |
	    VM_PROT_READ | VM_PROT_WRITE),
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "mach_make_memory_entry()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_GE(vmsize2, vmsize1, "vmsize2 (0x%llx) < vmsize1 (0x%llx)",
	    (uint64_t) vmsize2, (uint64_t) vmsize1);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}
	T_QUIET;
	T_EXPECT_NOTNULL(mem_entry, "mem_entry == 0x%x", mem_entry);
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	vmaddr2 = 0;
	kr = mach_vm_map(mach_task_self(),
	    &vmaddr2,
	    vmsize2,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    TRUE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_map()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	cp2 = (unsigned char *)(uintptr_t)vmaddr2;
	T_QUIET;
	T_EXPECT_TRUE(((*cp1 == '1') && (*cp2 == '1')), "*cp1/*cp2 0x%x/0x%x expected 0x%x/0x%x",
	    *cp1, *cp2, '1', '1');
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	*cp2 = '2';
	T_QUIET;
	T_EXPECT_TRUE(((*cp1 == '1') && (*cp2 == '2')), "*cp1/*cp2 0x%x/0x%x expected 0x%x/0x%x",
	    *cp1, *cp2, '1', '2');
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr1 != 0) {
		mach_vm_deallocate(mach_task_self(), vmaddr1, vmsize1);
		vmaddr1 = 0;
		vmsize1 = 0;
	}
	if (vmaddr2 != 0) {
		mach_vm_deallocate(mach_task_self(), vmaddr2, vmsize2);
		vmaddr2 = 0;
		vmsize2 = 0;
	}
	if (mem_entry != MACH_PORT_NULL) {
		mach_port_deallocate(mach_task_self(), mem_entry);
		mem_entry = MACH_PORT_NULL;
	}

	return;
}

T_DECL(memory_entry_tagging, "test mem entry tag for rdar://problem/23334087 \
    VM memory tags should be propagated through memory entries",
    T_META_ALL_VALID_ARCHS(true))
{
	test_memory_entry_tagging(0);
	test_memory_entry_tagging(1);
}

T_DECL(map_memory_entry, "test mapping mem entry for rdar://problem/22611816 \
    mach_make_memory_entry(MAP_MEM_VM_COPY) should never use a KERNEL_BUFFER \
    copy", T_META_ALL_VALID_ARCHS(true))
{
	test_map_memory_entry();
}

static char *vm_purgable_state[4] = { "NONVOLATILE", "VOLATILE", "EMPTY", "DENY" };

static uint64_t
task_footprint(void)
{
	task_vm_info_data_t ti;
	kern_return_t kr;
	mach_msg_type_number_t count;

	count = TASK_VM_INFO_COUNT;
	kr = task_info(mach_task_self(),
	    TASK_VM_INFO,
	    (task_info_t) &ti,
	    &count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "task_info()");
#if defined(__arm64__) || defined(__arm__)
	T_QUIET;
	T_ASSERT_EQ(count, TASK_VM_INFO_COUNT, "task_info() count = %d (expected %d)",
	    count, TASK_VM_INFO_COUNT);
#endif /* defined(__arm64__) || defined(__arm__) */
	return ti.phys_footprint;
}

T_DECL(purgeable_empty_to_volatile, "test task physical footprint when \
    emptying, volatilizing purgeable vm")
{
	kern_return_t kr;
	mach_vm_address_t vm_addr;
	mach_vm_size_t vm_size;
	char *cp;
	int ret;
	vm_purgable_t state;
	uint64_t footprint[8];

	vm_addr = 0;
	vm_size = 1 * 1024 * 1024;
	T_LOG("--> allocate %llu bytes", vm_size);
	kr = mach_vm_allocate(mach_task_self(),
	    &vm_addr,
	    vm_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	/* footprint0 */
	footprint[0] = task_footprint();
	T_LOG("    footprint[0] = %llu", footprint[0]);

	T_LOG("--> access %llu bytes", vm_size);
	for (cp = (char *) vm_addr;
	    cp < (char *) (vm_addr + vm_size);
	    cp += vm_kernel_page_size) {
		*cp = 'x';
	}
	/* footprint1 == footprint0 + vm_size */
	footprint[1] = task_footprint();
	T_LOG("    footprint[1] = %llu", footprint[1]);
	if (footprint[1] != footprint[0] + vm_size) {
		T_LOG("WARN: footprint[1] != footprint[0] + vm_size");
	}

	T_LOG("--> wire %llu bytes", vm_size / 2);
	ret = mlock((char *)vm_addr, (size_t) (vm_size / 2));
	T_ASSERT_POSIX_SUCCESS(ret, "mlock()");

	/* footprint2 == footprint1 */
	footprint[2] = task_footprint();
	T_LOG("    footprint[2] = %llu", footprint[2]);
	if (footprint[2] != footprint[1]) {
		T_LOG("WARN: footprint[2] != footprint[1]");
	}

	T_LOG("--> VOLATILE");
	state = VM_PURGABLE_VOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(VOLATILE)");
	T_ASSERT_EQ(state, VM_PURGABLE_NONVOLATILE, "NONVOLATILE->VOLATILE: state was %s",
	    vm_purgable_state[state]);
	/* footprint3 == footprint2 - (vm_size / 2) */
	footprint[3] = task_footprint();
	T_LOG("    footprint[3] = %llu", footprint[3]);
	if (footprint[3] != footprint[2] - (vm_size / 2)) {
		T_LOG("WARN: footprint[3] != footprint[2] - (vm_size / 2)");
	}

	T_LOG("--> EMPTY");
	state = VM_PURGABLE_EMPTY;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(EMPTY)");
	if (state != VM_PURGABLE_VOLATILE &&
	    state != VM_PURGABLE_EMPTY) {
		T_ASSERT_FAIL("VOLATILE->EMPTY: state was %s",
		    vm_purgable_state[state]);
	}
	/* footprint4 == footprint3 */
	footprint[4] = task_footprint();
	T_LOG("    footprint[4] = %llu", footprint[4]);
	if (footprint[4] != footprint[3]) {
		T_LOG("WARN: footprint[4] != footprint[3]");
	}

	T_LOG("--> unwire %llu bytes", vm_size / 2);
	ret = munlock((char *)vm_addr, (size_t) (vm_size / 2));
	T_ASSERT_POSIX_SUCCESS(ret, "munlock()");

	/* footprint5 == footprint4 - (vm_size/2) (unless memory pressure) */
	/* footprint5 == footprint0 */
	footprint[5] = task_footprint();
	T_LOG("    footprint[5] = %llu", footprint[5]);
	if (footprint[5] != footprint[4] - (vm_size / 2)) {
		T_LOG("WARN: footprint[5] != footprint[4] - (vm_size/2)");
	}
	if (footprint[5] != footprint[0]) {
		T_LOG("WARN: footprint[5] != footprint[0]");
	}

	T_LOG("--> VOLATILE");
	state = VM_PURGABLE_VOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(VOLATILE)");
	T_ASSERT_EQ(state, VM_PURGABLE_EMPTY, "EMPTY->VOLATILE: state == %s",
	    vm_purgable_state[state]);
	/* footprint6 == footprint5 */
	/* footprint6 == footprint0 */
	footprint[6] = task_footprint();
	T_LOG("    footprint[6] = %llu", footprint[6]);
	if (footprint[6] != footprint[5]) {
		T_LOG("WARN: footprint[6] != footprint[5]");
	}
	if (footprint[6] != footprint[0]) {
		T_LOG("WARN: footprint[6] != footprint[0]");
	}

	T_LOG("--> NONVOLATILE");
	state = VM_PURGABLE_NONVOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(),
	    vm_addr,
	    VM_PURGABLE_SET_STATE,
	    &state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(NONVOLATILE)");
	T_ASSERT_EQ(state, VM_PURGABLE_EMPTY, "EMPTY->NONVOLATILE: state == %s",
	    vm_purgable_state[state]);
	/* footprint7 == footprint6 */
	/* footprint7 == footprint0 */
	footprint[7] = task_footprint();
	T_LOG("    footprint[7] = %llu", footprint[7]);
	if (footprint[7] != footprint[6]) {
		T_LOG("WARN: footprint[7] != footprint[6]");
	}
	if (footprint[7] != footprint[0]) {
		T_LOG("WARN: footprint[7] != footprint[0]");
	}
}

T_DECL(madvise_shared, "test madvise shared for rdar://problem/2295713 logging \
    rethink needs madvise(MADV_FREE_HARDER)",
    T_META_ALL_VALID_ARCHS(true))
{
	vm_address_t            vmaddr = 0, vmaddr2 = 0;
	vm_size_t               vmsize;
	kern_return_t           kr;
	char                    *cp;
	vm_prot_t               curprot, maxprot;
	int                     ret;
	task_vm_info_data_t     ti;
	mach_msg_type_number_t  ti_count;

	vmsize = 10 * 1024 * 1024; /* 10MB */
	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (cp = (char *)(uintptr_t)vmaddr;
	    cp < (char *)(uintptr_t)(vmaddr + vmsize);
	    cp++) {
		*cp = 'x';
	}

	kr = vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,           /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr,
	    FALSE,           /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_remap()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (cp = (char *)(uintptr_t)vmaddr2;
	    cp < (char *)(uintptr_t)(vmaddr2 + vmsize);
	    cp++) {
		T_QUIET;
		T_EXPECT_EQ(*cp, 'x', "vmaddr=%p vmaddr2=%p %p:0x%x",
		    (void *)(uintptr_t)vmaddr,
		    (void *)(uintptr_t)vmaddr2,
		    (void *)cp,
		    (unsigned char)*cp);
		if (T_RESULT == T_RESULT_FAIL) {
			goto done;
		}
	}
	cp = (char *)(uintptr_t)vmaddr;
	*cp = 'X';
	cp = (char *)(uintptr_t)vmaddr2;
	T_QUIET;
	T_EXPECT_EQ(*cp, 'X', "memory was not properly shared");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

#if defined(__x86_64__) || defined(__i386__)
	if (COMM_PAGE_READ(uint64_t, CPU_CAPABILITIES64) & kIsTranslated) {
		T_LOG("Skipping madvise reusable tests because we're running under translation.");
		goto done;
	}
#endif /* defined(__x86_64__) || defined(__i386__) */
	ret = madvise((char *)(uintptr_t)vmaddr,
	    vmsize,
	    MADV_FREE_REUSABLE);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "madvise()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	ti_count = TASK_VM_INFO_COUNT;
	kr = task_info(mach_task_self(),
	    TASK_VM_INFO,
	    (task_info_t) &ti,
	    &ti_count);
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "task_info()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	T_QUIET;
	T_EXPECT_EQ(ti.reusable, 2ULL * vmsize, "ti.reusable=%lld expected %lld",
	    ti.reusable, (uint64_t)(2 * vmsize));
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr != 0) {
		vm_deallocate(mach_task_self(), vmaddr, vmsize);
		vmaddr = 0;
	}
	if (vmaddr2 != 0) {
		vm_deallocate(mach_task_self(), vmaddr2, vmsize);
		vmaddr2 = 0;
	}
}

T_DECL(madvise_purgeable_can_reuse, "test madvise purgeable can reuse for \
    rdar://problem/37476183 Preview Footprint memory regressions ~100MB \
    [ purgeable_malloc became eligible for reuse ]",
    T_META_ALL_VALID_ARCHS(true))
{
#if defined(__x86_64__) || defined(__i386__)
	if (COMM_PAGE_READ(uint64_t, CPU_CAPABILITIES64) & kIsTranslated) {
		T_SKIP("madvise reusable is not supported under Rosetta translation. Skipping.)");
	}
#endif /* defined(__x86_64__) || defined(__i386__) */
	vm_address_t            vmaddr = 0;
	vm_size_t               vmsize;
	kern_return_t           kr;
	char                    *cp;
	int                     ret;

	vmsize = 10 * 1024 * 1024; /* 10MB */
	kr = vm_allocate(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    (VM_FLAGS_ANYWHERE |
	    VM_FLAGS_PURGABLE |
	    VM_MAKE_TAG(VM_MEMORY_MALLOC)));
	T_QUIET;
	T_EXPECT_MACH_SUCCESS(kr, "vm_allocate()");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

	for (cp = (char *)(uintptr_t)vmaddr;
	    cp < (char *)(uintptr_t)(vmaddr + vmsize);
	    cp++) {
		*cp = 'x';
	}

	ret = madvise((char *)(uintptr_t)vmaddr,
	    vmsize,
	    MADV_CAN_REUSE);
	T_QUIET;
	T_EXPECT_TRUE(((ret == -1) && (errno == EINVAL)), "madvise(): purgeable vm can't be adviced to reuse");
	if (T_RESULT == T_RESULT_FAIL) {
		goto done;
	}

done:
	if (vmaddr != 0) {
		vm_deallocate(mach_task_self(), vmaddr, vmsize);
		vmaddr = 0;
	}
}

#define DEST_PATTERN 0xFEDCBA98

T_DECL(map_read_overwrite, "test overwriting vm map from other map - \
    rdar://31075370",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize1, vmsize2;
	int                     *ip;
	int                     i;

	vmaddr1 = 0;
	vmsize1 = 4 * 4096;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	ip = (int *)(uintptr_t)vmaddr1;
	for (i = 0; i < vmsize1 / sizeof(*ip); i++) {
		ip[i] = i;
	}

	vmaddr2 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr2,
	    vmsize1,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	ip = (int *)(uintptr_t)vmaddr2;
	for (i = 0; i < vmsize1 / sizeof(*ip); i++) {
		ip[i] = DEST_PATTERN;
	}

	vmsize2 = vmsize1 - 2 * (sizeof(*ip));
	kr = mach_vm_read_overwrite(mach_task_self(),
	    vmaddr1 + sizeof(*ip),
	    vmsize2,
	    vmaddr2 + sizeof(*ip),
	    &vmsize2);
	T_ASSERT_MACH_SUCCESS(kr, "vm_read_overwrite()");

	ip = (int *)(uintptr_t)vmaddr2;
	for (i = 0; i < 1; i++) {
		T_QUIET;
		T_ASSERT_EQ(ip[i], DEST_PATTERN, "vmaddr2[%d] = 0x%x instead of 0x%x",
		    i, ip[i], DEST_PATTERN);
	}
	for (; i < (vmsize1 - 2) / sizeof(*ip); i++) {
		T_QUIET;
		T_ASSERT_EQ(ip[i], i, "vmaddr2[%d] = 0x%x instead of 0x%x",
		    i, ip[i], i);
	}
	for (; i < vmsize1 / sizeof(*ip); i++) {
		T_QUIET;
		T_ASSERT_EQ(ip[i], DEST_PATTERN, "vmaddr2[%d] = 0x%x instead of 0x%x",
		    i, ip[i], DEST_PATTERN);
	}
}

T_DECL(copy_none_use_pmap, "test copy-on-write remapping of COPY_NONE vm \
    objects - rdar://35610377",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2, vmaddr3;
	mach_vm_size_t          vmsize;
	vm_prot_t               curprot, maxprot;

	vmsize = 32 * 1024 * 1024;

	vmaddr1 = 0;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	memset((void *)(uintptr_t)vmaddr1, 'x', vmsize);

	vmaddr2 = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,                /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr1,
	    TRUE,                /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_remap() #1");

	vmaddr3 = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr3,
	    vmsize,
	    0,                /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr2,
	    TRUE,                /* copy */
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_remap() #2");
}

T_DECL(purgable_deny, "test purgeable memory is not allowed to be converted to \
    non-purgeable - rdar://31990033",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t   kr;
	vm_address_t    vmaddr;
	vm_purgable_t   state;

	vmaddr = 0;
	kr = vm_allocate(mach_task_self(), &vmaddr, 1,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	state = VM_PURGABLE_DENY;
	kr = vm_purgable_control(mach_task_self(), vmaddr,
	    VM_PURGABLE_SET_STATE, &state);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT,
	    "vm_purgable_control(VM_PURGABLE_DENY) -> 0x%x (%s)",
	    kr, mach_error_string(kr));

	kr = vm_deallocate(mach_task_self(), vmaddr, 1);
	T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate()");
}

#define VMSIZE 0x10000

T_DECL(vm_remap_zero, "test vm map of zero size - rdar://33114981",
    T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr1, vmaddr2;
	mach_vm_size_t          vmsize;
	vm_prot_t               curprot, maxprot;

	vmaddr1 = 0;
	vmsize = VMSIZE;
	kr = mach_vm_allocate(mach_task_self(),
	    &vmaddr1,
	    vmsize,
	    VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate()");

	vmaddr2 = 0;
	vmsize = 0;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr1,
	    FALSE,
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_remap(size=0x%llx) 0x%x (%s)",
	    vmsize, kr, mach_error_string(kr));

	vmaddr2 = 0;
	vmsize = (mach_vm_size_t)-2;
	kr = mach_vm_remap(mach_task_self(),
	    &vmaddr2,
	    vmsize,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    vmaddr1,
	    FALSE,
	    &curprot,
	    &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_INVALID_ARGUMENT, "vm_remap(size=0x%llx) 0x%x (%s)",
	    vmsize, kr, mach_error_string(kr));
}

extern int __shared_region_check_np(uint64_t *);

T_DECL(nested_pmap_trigger, "nested pmap should only be triggered from kernel \
    - rdar://problem/41481703",
    T_META_ALL_VALID_ARCHS(true))
{
	int                     ret;
	kern_return_t           kr;
	mach_vm_address_t       sr_start;
	mach_vm_size_t          vmsize;
	mach_vm_address_t       vmaddr;
	mach_port_t             mem_entry;

	ret = __shared_region_check_np(&sr_start);
	if (ret != 0) {
		int saved_errno;
		saved_errno = errno;

		T_ASSERT_EQ(saved_errno, ENOMEM, "__shared_region_check_np() %d (%s)",
		    saved_errno, strerror(saved_errno));
		T_END;
	}

	vmsize = PAGE_SIZE;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &vmsize,
	    sr_start,
	    MAP_MEM_VM_SHARE | VM_PROT_READ,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "make_memory_entry(0x%llx)", sr_start);

	vmaddr = 0;
	kr = mach_vm_map(mach_task_self(),
	    &vmaddr,
	    vmsize,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,
	    FALSE,
	    VM_PROT_READ,
	    VM_PROT_READ,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
}

static const char *prot_str[] = { "---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx" };
static const char *share_mode_str[] = { "---", "COW", "PRIVATE", "EMPTY", "SHARED", "TRUESHARED", "PRIVATE_ALIASED", "SHARED_ALIASED", "LARGE_PAGE" };

T_DECL(shared_region_share_writable, "sharing a writable mapping of the shared region shoudl not give write access to shared region - rdar://problem/74469953",
    T_META_ALL_VALID_ARCHS(true))
{
	int ret;
	uint64_t sr_start;
	kern_return_t kr;
	mach_vm_address_t address, tmp_address, remap_address;
	mach_vm_size_t size, tmp_size, remap_size;
	uint32_t depth;
	mach_msg_type_number_t count;
	vm_region_submap_info_data_64_t info;
	vm_prot_t cur_prot, max_prot;
	uint32_t before, after, remap;
	mach_port_t mem_entry;

	ret = __shared_region_check_np(&sr_start);
	if (ret != 0) {
		int saved_errno;
		saved_errno = errno;

		T_ASSERT_EQ(saved_errno, ENOMEM, "__shared_region_check_np() %d (%s)",
		    saved_errno, strerror(saved_errno));
		T_END;
	}
	T_LOG("SHARED_REGION_BASE 0x%llx", SHARED_REGION_BASE);
	T_LOG("SHARED_REGION_SIZE 0x%llx", SHARED_REGION_SIZE);
	T_LOG("shared region starts at 0x%llx", sr_start);
	T_QUIET; T_ASSERT_GE(sr_start, SHARED_REGION_BASE,
	    "shared region starts below BASE");
	T_QUIET; T_ASSERT_LT(sr_start, SHARED_REGION_BASE + SHARED_REGION_SIZE,
	    "shared region starts above BASE+SIZE");

	/*
	 * Step 1 - check that one can not get write access to a read-only
	 * mapping in the shared region.
	 */
	size = 0;
	for (address = SHARED_REGION_BASE;
	    address < SHARED_REGION_BASE + SHARED_REGION_SIZE;
	    address += size) {
		size = 0;
		depth = 99;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &address,
		    &size,
		    &depth,
		    (vm_region_recurse_info_t)&info,
		    &count);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_region_recurse()");
		if (kr == KERN_INVALID_ADDRESS) {
			T_SKIP("could not find read-only nested mapping");
			T_END;
		}
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
		T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
		    address, address + size, depth,
		    prot_str[info.protection],
		    prot_str[info.max_protection],
		    share_mode_str[info.share_mode],
		    info.object_id);
		if (depth > 0 &&
		    (info.protection == VM_PROT_READ) &&
		    (info.max_protection == VM_PROT_READ)) {
			/* nested and read-only: bingo! */
			break;
		}
	}
	if (address >= SHARED_REGION_BASE + SHARED_REGION_SIZE) {
		T_SKIP("could not find read-only nested mapping");
		T_END;
	}

	/* test vm_remap() of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	kr = mach_vm_remap(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
//	T_QUIET; T_ASSERT_EQ(cur_prot, VM_PROT_READ, "cur_prot is read-only");
//	T_QUIET; T_ASSERT_EQ(max_prot, VM_PROT_READ, "max_prot is read-only");
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
//	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	/* check that new mapping is read-only */
	tmp_address = remap_address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, remap_address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "new cur_prot read-only");
//	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "new max_prot read-only");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
// this would crash if actually read-only:
//	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap(): 0x%llx 0x%x -> 0x%x", address, before, after);
//	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap() did not bypass copy-on-write");
	}
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	T_PASS("vm_remap() read-only");

#if defined(VM_MEMORY_ROSETTA)
	if (dlsym(RTLD_DEFAULT, "mach_vm_remap_new") == NULL) {
		T_PASS("vm_remap_new() is not present");
		goto skip_vm_remap_new_ro;
	}
	/* test vm_remap_new() of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	cur_prot = VM_PROT_READ | VM_PROT_WRITE;
	max_prot = VM_PROT_READ | VM_PROT_WRITE;
	kr = mach_vm_remap_new(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap_new()");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_vm_remap_new_ro;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap_new()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap_new(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap_new() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap_new() did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	T_PASS("vm_remap_new() read-only");
skip_vm_remap_new_ro:
#else /* defined(VM_MEMORY_ROSETTA) */
	/* pre-BigSur SDK: no vm_remap_new() */
	T_LOG("No vm_remap_new() to test");
#endif /* defined(VM_MEMORY_ROSETTA) */

	/* test mach_make_memory_entry_64(VM_SHARE) of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_mem_entry_vm_share_ro;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("mem_entry(VM_SHARE): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("mem_entry(VM_SHARE) bypassed copy-on-write");
	} else {
		T_PASS("mem_entry(VM_SHARE) did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	/* check that new mapping is a copy */
	tmp_address = remap_address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, remap_address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(depth, 0, "new mapping is unnested");
//	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "new cur_prot read-only");
//	T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "new max_prot read-only");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	T_PASS("mem_entry(VM_SHARE) read-only");
skip_mem_entry_vm_share_ro:

	/* test mach_make_memory_entry_64() of RO */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_ASSERT_EQ(kr, KERN_PROTECTION_FAILURE, "mach_make_memory_entry_64()");
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
//	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_READ, "cur_prot still read-only");
	if (depth > 0) {
		T_QUIET; T_ASSERT_EQ(info.max_protection, VM_PROT_READ, "max_prot still read-only");
	}
	T_PASS("mem_entry() read-only");


	/*
	 * Step 2 - check that one can not share write access with a writable
	 * mapping in the shared region.
	 */
	size = 0;
	for (address = SHARED_REGION_BASE;
	    address < SHARED_REGION_BASE + SHARED_REGION_SIZE;
	    address += size) {
		size = 0;
		depth = 99;
		count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &address,
		    &size,
		    &depth,
		    (vm_region_recurse_info_t)&info,
		    &count);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_region_recurse()");
		if (kr == KERN_INVALID_ADDRESS) {
			T_SKIP("could not find writable nested mapping");
			T_END;
		}
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
		T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
		    address, address + size, depth,
		    prot_str[info.protection],
		    prot_str[info.max_protection],
		    share_mode_str[info.share_mode],
		    info.object_id);
		if (depth > 0 && (info.protection & VM_PROT_WRITE)) {
			/* nested and writable: bingo! */
			break;
		}
	}
	if (address >= SHARED_REGION_BASE + SHARED_REGION_SIZE) {
		T_SKIP("could not find writable nested mapping");
		T_END;
	}

	/* test vm_remap() of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	kr = mach_vm_remap(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap()");
	if (!(cur_prot & VM_PROT_WRITE)) {
		T_LOG("vm_remap(): 0x%llx not writable %s/%s",
		    remap_address, prot_str[cur_prot], prot_str[max_prot]);
		T_ASSERT_FAIL("vm_remap() remapping not writable");
	}
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap() did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");

#if defined(VM_MEMORY_ROSETTA)
	if (dlsym(RTLD_DEFAULT, "mach_vm_remap_new") == NULL) {
		T_PASS("vm_remap_new() is not present");
		goto skip_vm_remap_new_rw;
	}
	/* test vm_remap_new() of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_address = 0;
	remap_size = size;
	cur_prot = VM_PROT_READ | VM_PROT_WRITE;
	max_prot = VM_PROT_READ | VM_PROT_WRITE;
	kr = mach_vm_remap_new(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(),
	    address,
	    FALSE,
	    &cur_prot,
	    &max_prot,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_remap_new()");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_vm_remap_new_rw;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_remap_new()");
	if (!(cur_prot & VM_PROT_WRITE)) {
		T_LOG("vm_remap_new(): 0x%llx not writable %s/%s",
		    remap_address, prot_str[cur_prot], prot_str[max_prot]);
		T_ASSERT_FAIL("vm_remap_new() remapping not writable");
	}
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("vm_remap_new(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("vm_remap_new() bypassed copy-on-write");
	} else {
		T_PASS("vm_remap_new() did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
skip_vm_remap_new_rw:
#else /* defined(VM_MEMORY_ROSETTA) */
	/* pre-BigSur SDK: no vm_remap_new() */
	T_LOG("No vm_remap_new() to test");
#endif /* defined(VM_MEMORY_ROSETTA) */

	/* test mach_make_memory_entry_64(VM_SHARE) of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	if (kr == KERN_PROTECTION_FAILURE) {
		/* wrong but not a security issue... */
		goto skip_mem_entry_vm_share_rw;
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(VM_SHARE)");
	T_QUIET; T_ASSERT_EQ(remap_size, size, "mem_entry(VM_SHARE) should cover whole mapping");
//	T_LOG("AFTER MAKE_MEM_ENTRY(VM_SHARE) 0x%llx...", address); fflush(stdout); fflush(stderr); getchar();
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
//	T_LOG("AFTER VM_MAP 0x%llx...", remap_address); fflush(stdout); fflush(stderr); getchar();
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
//	T_LOG("AFTER WRITE 0x%llx...", remap_address); fflush(stdout); fflush(stderr); getchar();
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("mem_entry(VM_SHARE): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	if (before != after) {
		T_FAIL("mem_entry(VM_SHARE) bypassed copy-on-write");
	} else {
		T_PASS("mem_entry(VM_SHARE) did not bypass copy-on-write");
	}
	/* check that region is still nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_GT(depth, 0, "still nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	mach_port_deallocate(mach_task_self(), mem_entry);
skip_mem_entry_vm_share_rw:

	/* test mach_make_memory_entry_64() of RW */
	before = *(uint32_t *)(uintptr_t)address;
	remap_size = size;
	mem_entry = MACH_PORT_NULL;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &remap_size,
	    address,
	    VM_PROT_READ | VM_PROT_WRITE,
	    &mem_entry,
	    MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64()");
	remap_address = 0;
	kr = mach_vm_map(mach_task_self(),
	    &remap_address,
	    remap_size,
	    0,              /* mask */
	    VM_FLAGS_ANYWHERE,
	    mem_entry,
	    0,              /* offset */
	    FALSE,              /* copy */
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_PROT_READ | VM_PROT_WRITE,
	    VM_INHERIT_DEFAULT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_map()");
	remap = *(uint32_t *)(uintptr_t)remap_address;
	T_QUIET; T_ASSERT_EQ(remap, before, "remap matches original");
	*(uint32_t *)(uintptr_t)remap_address = before + 1;
	after = *(uint32_t *)(uintptr_t)address;
	T_LOG("mem_entry(): 0x%llx 0x%x -> 0x%x", address, before, after);
	*(uint32_t *)(uintptr_t)remap_address = before;
	/* check that region is no longer nested */
	tmp_address = address;
	tmp_size = 0;
	depth = 99;
	count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &tmp_address,
	    &tmp_size,
	    &depth,
	    (vm_region_recurse_info_t)&info,
	    &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse()");
	T_LOG("0x%llx - 0x%llx depth:%d %s/%s %s 0x%x",
	    tmp_address, tmp_address + tmp_size, depth,
	    prot_str[info.protection],
	    prot_str[info.max_protection],
	    share_mode_str[info.share_mode],
	    info.object_id);
	if (before != after) {
		if (depth == 0) {
			T_PASS("mem_entry() honored copy-on-write");
		} else {
			T_FAIL("mem_entry() did not trigger copy-on_write");
		}
	} else {
		T_FAIL("mem_entry() did not honor copy-on-write");
	}
	T_QUIET; T_ASSERT_EQ(tmp_address, address, "address hasn't changed");
//	T_QUIET; T_ASSERT_EQ(tmp_size, size, "size hasn't changed");
	T_QUIET; T_ASSERT_EQ(depth, 0, "no longer nested");
	T_QUIET; T_ASSERT_EQ(info.protection, VM_PROT_DEFAULT, "cur_prot still writable");
	T_QUIET; T_ASSERT_EQ((info.max_protection & VM_PROT_WRITE), VM_PROT_WRITE, "max_prot still writable");
	/* cleanup */
	kr = mach_vm_deallocate(mach_task_self(), remap_address, remap_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "vm_deallocate()");
	mach_port_deallocate(mach_task_self(), mem_entry);
}

T_DECL(copyoverwrite_submap_protection, "test copywrite vm region submap \
    protection", T_META_ALL_VALID_ARCHS(true))
{
	kern_return_t           kr;
	mach_vm_address_t       vmaddr;
	mach_vm_size_t          vmsize;
	natural_t               depth;
	vm_region_submap_short_info_data_64_t region_info;
	mach_msg_type_number_t  region_info_count;

	for (vmaddr = SHARED_REGION_BASE;
	    vmaddr < SHARED_REGION_BASE + SHARED_REGION_SIZE;
	    vmaddr += vmsize) {
		depth = 99;
		region_info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr,
		    &vmsize,
		    &depth,
		    (vm_region_info_t) &region_info,
		    &region_info_count);
		if (kr == KERN_INVALID_ADDRESS) {
			break;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_region_recurse(0x%llx)", vmaddr);
		T_ASSERT_EQ(region_info_count,
		    VM_REGION_SUBMAP_SHORT_INFO_COUNT_64,
		    "vm_region_recurse(0x%llx) count = %d expected %d",
		    vmaddr, region_info_count,
		    VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);

		T_LOG("--> region: vmaddr 0x%llx depth %d prot 0x%x/0x%x",
		    vmaddr, depth, region_info.protection,
		    region_info.max_protection);
		if (depth == 0) {
			/* not a submap mapping: next mapping */
			continue;
		}
		if (vmaddr >= SHARED_REGION_BASE + SHARED_REGION_SIZE) {
			break;
		}
		kr = mach_vm_copy(mach_task_self(),
		    vmaddr,
		    vmsize,
		    vmaddr);
		if (kr == KERN_PROTECTION_FAILURE) {
			T_PASS("vm_copy(0x%llx,0x%llx) expected prot error 0x%x (%s)",
			    vmaddr, vmsize, kr, mach_error_string(kr));
			continue;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_copy(0x%llx,0x%llx) prot 0x%x",
		    vmaddr, vmsize, region_info.protection);
		depth = 0;
		region_info_count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		kr = mach_vm_region_recurse(mach_task_self(),
		    &vmaddr,
		    &vmsize,
		    &depth,
		    (vm_region_info_t) &region_info,
		    &region_info_count);
		T_ASSERT_MACH_SUCCESS(kr, "m_region_recurse(0x%llx)", vmaddr);
		T_ASSERT_EQ(region_info_count,
		    VM_REGION_SUBMAP_SHORT_INFO_COUNT_64,
		    "vm_region_recurse() count = %d expected %d",
		    region_info_count, VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);

		T_ASSERT_EQ(depth, 0, "vm_region_recurse(0x%llx): depth = %d expected 0",
		    vmaddr, depth);
		T_ASSERT_EQ((region_info.protection & VM_PROT_EXECUTE),
		    0, "vm_region_recurse(0x%llx): prot 0x%x",
		    vmaddr, region_info.protection);
	}
}

T_DECL(wire_text, "test wired text for rdar://problem/16783546 Wiring code in \
    the shared region triggers code-signing violations",
    T_META_ALL_VALID_ARCHS(true))
{
	uint32_t *addr, before, after;
	int retval;
	int saved_errno;
	kern_return_t kr;
	vm_address_t map_addr, remap_addr;
	vm_prot_t curprot, maxprot;

	addr = (uint32_t *)&printf;
#if __has_feature(ptrauth_calls)
	map_addr = (vm_address_t)(uintptr_t)ptrauth_strip(addr, ptrauth_key_function_pointer);
#else /* __has_feature(ptrauth_calls) */
	map_addr = (vm_address_t)(uintptr_t)addr;
#endif /* __has_feature(ptrauth_calls) */
	remap_addr = 0;
	kr = vm_remap(mach_task_self(), &remap_addr, 4096,
	    0,           /* mask */
	    VM_FLAGS_ANYWHERE,
	    mach_task_self(), map_addr,
	    FALSE,           /* copy */
	    &curprot, &maxprot,
	    VM_INHERIT_DEFAULT);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "vm_remap error 0x%x (%s)",
	    kr, mach_error_string(kr));
	before = *addr;
	retval = mlock(addr, 4096);
	after = *addr;
	if (retval != 0) {
		saved_errno = errno;
		T_ASSERT_EQ(saved_errno, EACCES, "wire shared text error %d (%s), expected: %d",
		    saved_errno, strerror(saved_errno), EACCES);
	} else if (after != before) {
		T_ASSERT_FAIL("shared text changed by wiring at %p 0x%x -> 0x%x", addr, before, after);
	} else {
		T_PASS("wire shared text");
	}

	addr = (uint32_t *) &fprintf;
	before = *addr;
	retval = mlock(addr, 4096);
	after = *addr;
	if (retval != 0) {
		saved_errno = errno;
		T_ASSERT_EQ(saved_errno, EACCES, "wire shared text error %d (%s), expected: %d",
		    saved_errno, strerror(saved_errno), EACCES);
	} else if (after != before) {
		T_ASSERT_FAIL("shared text changed by wiring at %p 0x%x -> 0x%x", addr, before, after);
	} else {
		T_PASS("wire shared text");
	}

	addr = (uint32_t *) &testmain_wire_text;
	before = *addr;
	retval = mlock(addr, 4096);
	after = *addr;
	if (retval != 0) {
		saved_errno = errno;
		T_ASSERT_EQ(saved_errno, EACCES, "wire text error return error %d (%s)",
		    saved_errno, strerror(saved_errno));
	} else if (after != before) {
		T_ASSERT_FAIL("text changed by wiring at %p 0x%x -> 0x%x", addr, before, after);
	} else {
		T_PASS("wire text");
	}
}
