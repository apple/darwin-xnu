#include <darwintest.h>
#include <sys/sysctl.h>
#include <sys/errno.h>

#define MAX_TASK_PMEM "kern.max_task_pmem"
#define HW_MEMSIZE_STR "hw.memsize"
#define HW_MEMSIZE_THRESHOLD 600 * 1024 * 1024

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"));

/*
 * Embedded Device having physical memory greater than 600MB should have positive
 * value for kern.max_task_pmem if present.
 * Strategy:
 *  Fetch hw.memsize for the device.
 *  If hw.memsize > 600MB, and kern.max_task_pmem is present, assert that
 *  kern.max_task_pmem is set to value > 0.
 */
T_DECL(kern_max_task_pmem, "Embedded platforms should have a positive value for kern.max_task_pmem when hw.memsize > 600MB")
{
	int kern_max_task_pmem = 0;
	size_t pmem_size = sizeof(kern_max_task_pmem);

	uint64_t hw_memsize = 0;
	size_t size_hw_memsize = sizeof(hw_memsize);

	int ret = 0;

	ret = sysctlbyname(HW_MEMSIZE_STR, &hw_memsize, &size_hw_memsize, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get hardware mem size.");

	T_LOG("Checking if %s > %d", HW_MEMSIZE_STR, HW_MEMSIZE_THRESHOLD);
	if (hw_memsize <= HW_MEMSIZE_THRESHOLD) {
		T_SKIP("Device has hw.memsize = %lld. Skipping the check for %s", hw_memsize, MAX_TASK_PMEM);
	}

	T_LOG("Device has %s = %lld", HW_MEMSIZE_STR, hw_memsize);
	T_LOG("Testing for %s ...", MAX_TASK_PMEM);

	ret = sysctlbyname(MAX_TASK_PMEM, &kern_max_task_pmem, &pmem_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "call sysctlbyname to get max task physical memory");

	T_LOG("%s = %d", MAX_TASK_PMEM, kern_max_task_pmem);
	T_ASSERT_GT_INT(kern_max_task_pmem, 0, "%s should be greater than 0", MAX_TASK_PMEM);
}
