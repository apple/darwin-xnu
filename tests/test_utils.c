#include <sys/kern_sysctl.h>
#include <sys/sysctl.h>
#include <dispatch/dispatch.h>
#include <darwintest.h>

#include "test_utils.h"

bool
is_development_kernel()
{
	static dispatch_once_t is_development_once;
	static bool is_development;

	dispatch_once(&is_development_once, ^{
		int dev;
		size_t dev_size = sizeof(dev);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.development", &dev,
		&dev_size, NULL, 0), NULL);
		is_development = (dev != 0);
	});

	return is_development;
}
