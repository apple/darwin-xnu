#include <darwintest.h>
#include <stdio.h>
#include <mach/mach.h>
#include <mach/host_priv.h>


T_DECL(regression_17272465,
    "Test for host_set_special_port Mach port over-release, rdr: 17272465", T_META_CHECK_LEAKS(false))
{
	kern_return_t kr;
	mach_port_t port = MACH_PORT_NULL;

	T_SETUPBEGIN;
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port), NULL);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND), NULL);
	T_SETUPEND;

	(void)host_set_special_port(mach_host_self(), 30, port);
	(void)host_set_special_port(mach_host_self(), 30, port);
	(void)host_set_special_port(mach_host_self(), 30, port);

	T_PASS("No panic occurred");
}
