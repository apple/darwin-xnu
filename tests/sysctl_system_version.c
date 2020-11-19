#include <darwintest.h>
#include <sys/sysctl.h>

T_DECL(sysctl_osreleasetype_nowrite,
    "ensure the osreleasetype sysctl is not writeable by normal processes")
{
	char nice_try[32] = "FactoryToAvoidSandbox!";
	int ret = sysctlbyname("kern.osreleasetype", NULL, NULL, nice_try,
	    sizeof(nice_try));
	T_ASSERT_POSIX_FAILURE(ret, EPERM, "try to set kern.osreleasetype sysctl");
}

T_DECL(sysctl_osreleasetype_exists, "ensure the osreleasetype sysctl exists")
{
	char release_type[64] = "";
	size_t release_type_size = sizeof(release_type);
	int ret = sysctlbyname("kern.osreleasetype", release_type,
	    &release_type_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "kern.osreleasetype sysctl");
	T_LOG("kern.osreleasetype = %s", release_type);
}
