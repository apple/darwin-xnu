#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define GB (1ULL * 1024 * 1024 * 1024)

/*
 * This test expects the entitlement to be the enabling factor for a process to
 * allocate at least this many GB of VA space. i.e. with the entitlement, n GB
 * must be allocatable; whereas without it, it must be less.
 * This value was determined experimentally to fit on applicable devices and to
 * be clearly distinguishable from the default VA limit.
 */
#define ALLOC_TEST_GB 53

T_DECL(TESTNAME,
	"Verify that a required entitlement is present in order to be granted an extra-large "
	"VA space on arm64",
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false))
{
	int	i;
	void	*res;

	if (!dt_64_bit_kernel()) {
		T_SKIP("This test is only applicable to arm64");
	}

	T_LOG("Attemping to allocate VA space in 1 GB chunks.");

	for (i = 0; i < (ALLOC_TEST_GB * 2); i++) {
		res = mmap(NULL, 1 * GB, PROT_NONE, MAP_PRIVATE | MAP_ANON, 0, 0);
		if (res == MAP_FAILED) {
			if (errno != ENOMEM) {
				T_WITH_ERRNO;
				T_LOG("mmap failed: stopped at %d of %d GB allocated", i, ALLOC_TEST_GB);
			}
			break;
		} else {
			T_LOG("%d: %p\n", i, res);
		}
	}

#if defined(ENTITLED)
	T_EXPECT_GE_INT(i, ALLOC_TEST_GB, "Allocate at least %d GB of VA space", ALLOC_TEST_GB);
#else
	T_EXPECT_LT_INT(i, ALLOC_TEST_GB, "Not permitted to allocate %d GB of VA space", ALLOC_TEST_GB);
#endif
}
