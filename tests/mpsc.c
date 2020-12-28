/*
 * mpsc: test the MPSC interface
 */

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <sys/sysctl.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.mpsc"),
    T_META_RUN_CONCURRENTLY(true));

T_DECL(pingpong, "mpsc_pingpong")
{
	uint64_t count = 100 * 1000, nsecs = 0;
	size_t nlen = sizeof(nsecs);
	int error;

	error = sysctlbyname("kern.mpsc_test_pingpong", &nsecs, &nlen,
	    &count, sizeof(count));
	T_ASSERT_POSIX_SUCCESS(error, "sysctlbyname");
	T_LOG("%lld asyncs in %lld ns (%g us/async)", count, nsecs,
	    (nsecs / 1e3) / count);
}
