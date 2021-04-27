#include <sys/sysctl.h>
#include <time.h>

#include <darwintest.h>

/*
 * trying phys offsets from start of dram of:
 * watchOS 512Meg
 * macOS 3Gig
 * iOS,etc. 750Meg
 */
#if TARGET_OS_WATCH
#define USEBOOTARG "bad_ram_pages=536870912 bad_static_mfree=1"
#elif TARGET_OS_OSX
#define USEBOOTARG "bad_ram_pages=3221225472 bad_static_mfree=1"
#else
#define USEBOOTARG "bad_ram_pages=786432000 bad_static_mfree=1"
#endif

T_DECL(retired_pages_test,
    "Test retiring pages at boot",
    T_META_NAMESPACE("xnu.vm"),
    T_META_BOOTARGS_SET(USEBOOTARG),
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false))
{
	int err;
	unsigned int count = 0;
	size_t s = sizeof(count);

#if !defined(__arm64__) || TARGET_OS_BRIDGE
	T_SKIP("No page retirement on x86, arm32 or bridgeOS kernels");
#endif
	/*
	 * Get the number of pages retired from the kernel
	 */
	err = sysctlbyname("vm.retired_pages_count", &count, &s, NULL, 0);

	/* If the sysctl isn't supported, test succeeds */
	if (err == ENOENT) {
		T_SKIP("sysctl vm.retired_pages_count not found, skipping test");
	}
	T_ASSERT_POSIX_SUCCESS(err, "sysctl vm.retired_pages_count");

	T_ASSERT_GT_INT(count, 0, "Expect retired pages");
}
