#include <darwintest.h>
#include <sys/sysctl.h>

T_DECL(sysctl_hw_cpu, "ensure vital product and CPU-related sysctls exist")
{
	char buffer[64] = "";
	size_t buffer_size = sizeof(buffer);

	int ret = sysctlbyname("hw.target", buffer,
	    &buffer_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "hw.target sysctl");
	T_LOG("hw.target = %s", buffer);

	buffer_size = sizeof(buffer);

	ret = sysctlbyname("hw.product", buffer,
	    &buffer_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "hw.product sysctl");
	T_LOG("hw.product = %s", buffer);

	buffer_size = sizeof(buffer);

	ret = sysctlbyname("machdep.cpu.brand_string", buffer,
	    &buffer_size, NULL, 0);

	T_ASSERT_POSIX_SUCCESS(ret, "machdep.cpu.brand_string sysctl");
	T_LOG("machdep.cpu.brand_string = %s", buffer);
}
