#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mk_timer.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(mktimer_kobject, "mktimer_kobject()", T_META_ALL_VALID_ARCHS(true))
{
	mach_port_t timer_port = MACH_PORT_NULL;
	mach_port_t notify_port = MACH_PORT_NULL;

	kern_return_t kr = KERN_SUCCESS;

	// timer port
	// This is a receive right which is also a kobject
	timer_port = mk_timer_create();
	T_ASSERT_NE(timer_port, (mach_port_t)MACH_PORT_NULL, "mk_timer_create: %s", mach_error_string(kr));

	mach_port_set_context(mach_task_self(), timer_port, (mach_port_context_t) 0x1);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_set_context(timer_port): %s", mach_error_string(kr));

	// notification port for the mk_timer port to come back on
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify_port);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_allocate(notify_port): %s", mach_error_string(kr));

	kr = mach_port_set_context(mach_task_self(), notify_port, (mach_port_context_t) 0x2);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_set_context(notify_port): %s", mach_error_string(kr));

	T_LOG("timer: 0x%x, notify: 0x%x", timer_port, notify_port);

	mach_port_t previous = MACH_PORT_NULL;

	// request a port-destroyed notification on the timer port
	kr = mach_port_request_notification(mach_task_self(), timer_port, MACH_NOTIFY_PORT_DESTROYED,
	    0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
	// this should fail!
	T_ASSERT_NE(kr, KERN_SUCCESS, "notifications should NOT work on mk_timer ports!");

	// destroy the timer port to send the notification
	mach_port_mod_refs(mach_task_self(), timer_port, MACH_PORT_RIGHT_RECEIVE, -1);

	// destroy the notification port
	mach_port_mod_refs(mach_task_self(), notify_port, MACH_PORT_RIGHT_RECEIVE, -1);

	T_LOG("done");
}
