#include <darwintest.h>
#include <sys/sysctl.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.arm"));

T_DECL(ptrauth_data_tests, "invoke the PAC unit tests", T_META_ASROOT(true))
{
#if __has_feature(ptrauth_calls)
	int ret, dummy = 1;
	ret = sysctlbyname("kern.run_ptrauth_data_tests", NULL, NULL, &dummy, sizeof(dummy));
	T_ASSERT_POSIX_SUCCESS(ret, "run ptrauth data tests");
#else
	T_SKIP("Running on non-ptrauth system. Skipping...");
#endif //__has_feature(ptrauth_calls)
}
