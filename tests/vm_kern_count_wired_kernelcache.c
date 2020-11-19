#include <unistd.h>
#include <errno.h>

#include <vm_statistics.h>
#include <mach/mach.h>
#include <mach_debug/mach_debug.h>

#include <darwintest.h>

/*
 * Ensure that mach_memory_info includes a counter for the kernelcache size.
 */

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"));

T_DECL(vm_kern_count_wired_kernelcache,
    "mach_memory_info returns a counter for for kernelcache",
    T_META_ASROOT(true))
{
	kern_return_t kr;
	uint64_t i;
	mach_zone_name_t *name = NULL;
	unsigned int nameCnt = 0;
	mach_zone_info_t *info = NULL;
	unsigned int infoCnt = 0;
	mach_memory_info_t *wiredInfo = NULL;
	unsigned int wiredInfoCnt = 0;

	kr = mach_memory_info(mach_host_self(), &name, &nameCnt, &info, &infoCnt,
	    &wiredInfo, &wiredInfoCnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_memory_info");

	bool found_kernelcache_counter = false;
	uint64_t static_kernelcache_size = 0;
	uint64_t wired_memory_boot = 0;
	for (i = 0; i < wiredInfoCnt; i++) {
		const mach_memory_info_t *curr = &wiredInfo[i];
		uint32_t type = curr->flags & VM_KERN_SITE_TYPE;
		if (type == VM_KERN_SITE_COUNTER) {
			if (curr->site == VM_KERN_COUNT_WIRED_STATIC_KERNELCACHE) {
				found_kernelcache_counter = true;
				static_kernelcache_size = curr->size;
			} else if (curr->site == VM_KERN_COUNT_WIRED_BOOT) {
				wired_memory_boot = curr->size;
			}
		}
	}
	T_QUIET; T_ASSERT_TRUE(found_kernelcache_counter, "mach_memory_info returned kernelcache counter.");
	// Sanity check that the counter isn't 0.
	T_QUIET; T_ASSERT_GT(static_kernelcache_size, 0ULL, "kernelcache counter > 0");
	// Sanity check that the counter is less than the amount of wired memory
	// at boot.
	T_QUIET; T_ASSERT_LE(static_kernelcache_size, wired_memory_boot, "kernelcache counter <= VM_KERN_COUNT_WIRED_BOOT");

	// Cleanup
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
}
