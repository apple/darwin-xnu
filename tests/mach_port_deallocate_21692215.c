#define T_NAMESPACE "xnu.ipc"
#include <darwintest.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>

#define NR_PORTS 4

T_DECL(mach_port_deallocate, "mach_port_deallocate deallocates also PORT_SET"){
	mach_port_t port_set;
	mach_port_t port[NR_PORTS];
	int i, ret;

	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &port_set);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_allocate MACH_PORT_RIGHT_PORT_SET");

	for (i = 0; i < NR_PORTS; i++) {
		ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port[i]);
		T_ASSERT_MACH_SUCCESS(ret, "mach_port_allocate MACH_PORT_RIGHT_RECEIVE");

		ret = mach_port_move_member(mach_task_self(), port[i], port_set);
		T_ASSERT_MACH_SUCCESS(ret, "mach_port_move_member");
	}

	T_LOG("Ports created");

	/* do something */

	for (i = 0; i < NR_PORTS; i++) {
		ret = mach_port_mod_refs(mach_task_self(), port[i], MACH_PORT_RIGHT_RECEIVE, -1);
		T_ASSERT_MACH_SUCCESS(ret, "mach_port_mod_refs -1 RIGHT_RECEIVE");
	}

	ret = mach_port_deallocate(mach_task_self(), port_set);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_deallocate PORT_SET");

	T_LOG("Ports erased");
}
