#include <darwintest.h>
#include <sys/sysctl.h>

T_DECL(sbuf_tests, "invoke the sbuf unit tests")
{
	char buf[5] = { 'A', 'B', 'C', 'D', 0 };
	int ret;

	ret = sysctlbyname("kern.sbuf_test", NULL, NULL, buf, sizeof(buf) - 1);
	T_ASSERT_POSIX_SUCCESS(ret, "kernel sbuf tests failed");
}
