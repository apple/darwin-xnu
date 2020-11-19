#include <darwintest.h>
#include <sys/sysctl.h>

T_DECL(sysctl_hw_target_product, "ensure the hw.target and hw.product sysctls exist")
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
}
