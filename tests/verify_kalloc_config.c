#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach_debug/mach_debug.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false)
);

static void run_test(void);

static void run_test(void)
{
	kern_return_t kr;
	uint64_t size, i;
	mach_zone_name_t *name = NULL;
	unsigned int nameCnt = 0;
	mach_zone_info_t *info = NULL;
	unsigned int infoCnt = 0;
	mach_memory_info_t *wiredInfo = NULL;
	unsigned int wiredInfoCnt = 0;
	const char kalloc_str[] = "kalloc.";

	kr = mach_memory_info(mach_host_self(),
			&name, &nameCnt, &info, &infoCnt,
			&wiredInfo, &wiredInfoCnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_memory_info");
	T_QUIET; T_ASSERT_EQ(nameCnt, infoCnt, "zone name and info counts don't match");

	/* Match the names of the kalloc zones against their element sizes. */
	for (i = 0; i < nameCnt; i++) {
		if (strncmp(name[i].mzn_name, kalloc_str, strlen(kalloc_str)) == 0) {
			size = strtoul(&(name[i].mzn_name[strlen(kalloc_str)]), NULL, 10);
			T_LOG("ZONE NAME: %-25s ELEMENT SIZE: %llu", name[i].mzn_name, size);
			T_QUIET; T_ASSERT_EQ(size, info[i].mzi_elem_size, "kalloc zone name and element size don't match");
		}
	}

	if ((name != NULL) && (nameCnt != 0)) {
		kr = vm_deallocate(mach_task_self(), (vm_address_t) name,
				(vm_size_t) (nameCnt * sizeof *name));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate name");
	}

	if ((info != NULL) && (infoCnt != 0)) {
		kr = vm_deallocate(mach_task_self(), (vm_address_t) info,
				(vm_size_t) (infoCnt * sizeof *info));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate info");
	}

	if ((wiredInfo != NULL) && (wiredInfoCnt != 0)) {
		kr = vm_deallocate(mach_task_self(), (vm_address_t) wiredInfo,
				(vm_size_t) (wiredInfoCnt * sizeof *wiredInfo));
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate wiredInfo");
	}

	T_END;
}

T_DECL( verify_kalloc_config,
		"verifies that the kalloc zones are configured correctly",
		T_META_ASROOT(true))
{
	run_test();
}

