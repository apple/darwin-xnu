#include <sys/sysctl.h>
#include <time.h>

#include <darwintest.h>
#include <darwintest_utils.h>


static void *
gc_thread_func(__unused void *arg)
{
	int err;
	unsigned int count = 1;
	size_t s = sizeof(count);
	time_t start = time(NULL);
	time_t end = time(NULL);

	/*
	 * Keep kicking the test for 15 seconds to see if we can panic() the kernel
	 */
	while (time(&end) < start + 15) {
		err = sysctlbyname("kern.zone_gc_replenish_test", &count, &s, &count, s);

		/* If the sysctl isn't supported, test succeeds */
		if (err != 0) {
			T_SKIP("sysctl kern.zone_gc_replenish_test not found, skipping test");
			break;
		}
	}
	return NULL;
}

static void *
alloc_thread_func(__unused void *arg)
{
	int err;
	unsigned int count = 1;
	size_t s = sizeof(count);
	time_t start = time(NULL);
	time_t end = time(NULL);

	/*
	 * Keep kicking the test for 15 seconds to see if we can panic() the kernel
	 */
	while (time(&end) < start + 15) {
		err = sysctlbyname("kern.zone_alloc_replenish_test", &count, &s, &count, s);

		/* If the sysctl isn't supported, test succeeds */
		if (err != 0) {
			T_SKIP("sysctl kern.zone_alloc_replenish_test not found, skipping test");
			break;
		}
	}
	return NULL;
}

T_DECL(zone_gc_replenish_test,
    "Test zone garbage collection, exhaustion and replenishment",
    T_META_NAMESPACE("xnu.vm"),
    T_META_CHECK_LEAKS(false))
{
	pthread_attr_t attr;
	pthread_t gc_thread;
	pthread_t alloc_thread;
	int ret;

	ret = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_attr_init");

	ret = pthread_create(&gc_thread, &attr, gc_thread_func, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "gc pthread_create");

	ret = pthread_create(&alloc_thread, &attr, alloc_thread_func, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "alloc pthread_create");

	T_ASSERT_POSIX_ZERO(pthread_join(gc_thread, NULL), NULL);
	T_ASSERT_POSIX_ZERO(pthread_join(alloc_thread, NULL), NULL);
	T_PASS("Ran 15 seconds with no panic");
}
