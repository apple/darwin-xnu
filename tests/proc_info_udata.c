#include <darwintest.h>
#include "../bsd/sys/proc_info.h"
#include "../libsyscall/wrappers/libproc/libproc.h"
#include <stdio.h>
#include <unistd.h>
#include <TargetConditionals.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(proc_udata_info, "Get and set a proc udata token"){
	uint64_t token = mach_absolute_time();
	proc_info_udata_t udata;
	int ret;

	udata = token;
	ret = proc_udata_info(getpid(), PROC_UDATA_INFO_SET, &udata, sizeof(udata));

#if !TARGET_OS_OSX
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(ret, -1, "proc_udata_info PROC_UDATA_INFO_SET returns error on non-supported platforms");
	T_SKIP("Remaining tests are only supported on platforms with CONFIG_PROC_UDATA_STORAGE configured");
#endif

	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(ret, 0, "proc_udata_info PROC_UDATA_INFO_SET");

	T_LOG("udata set to %#llx", udata);

	bzero(&udata, sizeof(udata));
	ret = proc_udata_info(getpid(), PROC_UDATA_INFO_GET, &udata, sizeof(udata));
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(ret, 0, "proc_udata_info PROC_UDATA_INFO_GET");

	T_ASSERT_EQ_ULLONG(token, udata, "proc_udata_info(): retrieved value matches token");

	ret = proc_udata_info(getpid(), PROC_UDATA_INFO_SET, &udata, sizeof(uint32_t));
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(ret, -1, "proc_udata_info PROC_UDATA_INFO_SET with invalid size returned -1");
	T_ASSERT_EQ_INT(errno, EINVAL, "proc_udata_info PROC_UDATA_INFO_SET with invalid size returned EINVAL");

	ret = proc_udata_info(getppid(), PROC_UDATA_INFO_GET, &udata, sizeof(udata));
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(ret, -1, "proc_udata_info PROC_UDATA_INFO_GET returned -1 on attempt against non-self pid");
	T_ASSERT_EQ_INT(errno, EACCES, "proc_udata_info PROC_UDATA_INFO_GET set errno to EACCES on attempt against non-self pid");

	ret = proc_udata_info(getppid(), PROC_UDATA_INFO_SET, &udata, sizeof(udata));
	T_WITH_ERRNO;
	T_ASSERT_EQ_INT(ret, -1, "proc_udata_info PROC_UDATA_INFO_SET returned -1 on attempt against non-self pid");
	T_ASSERT_EQ_INT(errno, EACCES, "proc_udata_info PROC_UDATA_INFO_SET set errno to EACCES on attempt against non-self pid");
}
