#include <stdio.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <darwintest.h>

T_DECL(mach_port_insert_right, "insert send right for an existing right", T_META_CHECK_LEAKS(false))
{
	mach_port_t port = MACH_PORT_NULL;
	mach_port_t port2 = MACH_PORT_NULL;
	kern_return_t retval;

	mach_port_t task = mach_task_self();

	retval = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
	T_ASSERT_MACH_SUCCESS(retval, "allocate a port=[%d]", port);

	mach_port_name_t name = 123;

	retval = mach_port_insert_right(task, name, port, MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_ERROR(retval, KERN_FAILURE, "insert a send right for port=[%d] with name=[%d]", port, name);

	name = port + 1;
	retval = mach_port_insert_right(task, name, port, MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_ERROR(retval, KERN_FAILURE, "insert a send right for port=[%d] with name=[%d]", port, name);

	retval = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port2);
	T_ASSERT_MACH_SUCCESS(retval, "allocate a port=[%d]", port2);

	name = port;
	retval = mach_port_insert_right(task, name, port2, MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_ERROR(retval, KERN_RIGHT_EXISTS, "insert a send right for port=[%d] with name=[%d]", port2, name);
}
