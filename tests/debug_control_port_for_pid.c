#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(debug_control_port_for_pid_success,
    "Verify that with debug_port entitlement you can call debug_control_port_for_pid",
    T_META_ASROOT(true), T_META_CHECK_LEAKS(false))
{
	if (geteuid() != 0) {
		T_SKIP("test requires root privileges to run.");
	}

	mach_port_t port = MACH_PORT_NULL;
	T_ASSERT_MACH_SUCCESS(debug_control_port_for_pid(mach_task_self(), 1, &port), "debug_control_port_for_pid");
	T_EXPECT_NE(port, MACH_PORT_NULL, "debug_port");
	mach_port_deallocate(mach_task_self(), port);
}
