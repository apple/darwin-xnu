#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/kern_sysctl.h>

#include "counter/common.h"

int
init_scalable_counter_test()
{
	kern_return_t result;
	int value = 1;

	result = sysctlbyname("kern.scalable_counter_test_start", NULL, NULL, &value, sizeof(value));
	return result;
}

int
fini_scalable_counter_test()
{
	kern_return_t result;
	int value = 1;
	result = sysctlbyname("kern.scalable_counter_test_finish", NULL, NULL, &value, sizeof(value));
	return result;
}
