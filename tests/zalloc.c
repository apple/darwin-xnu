#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_DECL(basic_zone_test, "General zalloc test",
    T_META_NAMESPACE("xnu.vm"),
    T_META_CHECK_LEAKS(false))
{
	unsigned int count = 1;
	size_t s = sizeof(count);
	int rc;

	rc = sysctlbyname("kern.run_zone_test", &count, &s, &count, s);
	T_ASSERT_POSIX_SUCCESS(rc, "run_zone_test");
}
