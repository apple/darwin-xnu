#include <darwintest.h>
#include <pthread/private.h>
#include <sys/sysctl.h>
#include "exc_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(true));

static size_t
exc_immovable_handler(
	mach_port_t task,
	mach_port_t thread,
	__unused exception_type_t type,
	__unused mach_exception_data_t codes)
{
	T_EXPECT_EQ(task, mach_task_self(), "Received immovable task port");
	T_EXPECT_EQ(thread, pthread_mach_thread_np(pthread_main_thread_np()),
	    "Received immovable thread port");
	T_END;
}

T_DECL(exc_immovable, "Test that exceptions receive immovable ports")
{
	mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_ACCESS);
	uint32_t opts = 0;
	size_t size = sizeof(&opts);
	mach_port_t mp;
	kern_return_t kr;

	T_LOG("Check if task_exc_guard exception has been enabled\n");
	int ret = sysctlbyname("kern.ipc_control_port_options", &opts, &size, NULL, 0);
	T_EXPECT_POSIX_SUCCESS(ret, "sysctlbyname(kern.ipc_control_port_options)");

	if ((opts & 0x30) == 0) {
		T_SKIP("immovable rights aren't enabled");
	}

	kr = task_get_special_port(mach_task_self(), TASK_KERNEL_PORT, &mp);
	T_EXPECT_MACH_SUCCESS(kr, "task_get_special_port");
	T_EXPECT_NE(mp, mach_task_self(), "should receive movable port");

	/*
	 * do not deallocate the port we received on purpose to check
	 * that the exception will not coalesce with the movable port
	 * we have in our space now
	 */

	run_exception_handler(exc_port, exc_immovable_handler);
	*(void *volatile*)0 = 0;
}
