#include <darwintest.h>
#include <darwintest_utils.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/mach_error.h>
#include <mach/task_special_ports.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

T_DECL(task_ident, "test task identity token")
{
	kern_return_t kr;
	task_id_token_t token;
	mach_port_t port1, port2;

	kr = task_create_identity_token(mach_task_self(), &token);
	T_ASSERT_MACH_SUCCESS(kr, "task_create_identity_token()");

	port1 = mach_task_self();
	kr = task_identity_token_get_task_port(token, TASK_FLAVOR_CONTROL, &port2); /* Immovable control port for self */
	T_ASSERT_MACH_SUCCESS(kr, "task_identity_token_get_task_port() - CONTROL");
	T_EXPECT_EQ(port1, port2, "Control port does not match!");

	mach_port_deallocate(mach_task_self(), port2);

	kr = task_get_special_port(mach_task_self(), TASK_READ_PORT, &port1);
	T_ASSERT_MACH_SUCCESS(kr, "task_get_special_port() - READ");
	kr = task_identity_token_get_task_port(token, TASK_FLAVOR_READ, &port2);
	T_ASSERT_MACH_SUCCESS(kr, "task_identity_token_get_task_port() - read");
	T_EXPECT_EQ(port1, port2, "Read port does not match!");

	mach_port_deallocate(mach_task_self(), port1);
	mach_port_deallocate(mach_task_self(), port2);

	kr = task_get_special_port(mach_task_self(), TASK_INSPECT_PORT, &port1);
	T_ASSERT_MACH_SUCCESS(kr, "task_get_special_port() - INSPECT");
	kr = task_identity_token_get_task_port(token, TASK_FLAVOR_INSPECT, &port2);
	T_ASSERT_MACH_SUCCESS(kr, "task_identity_token_get_task_port() - inspect");
	T_EXPECT_EQ(port1, port2, "Inspect port does not match!");

	mach_port_deallocate(mach_task_self(), port1);
	mach_port_deallocate(mach_task_self(), port2);

	kr = task_get_special_port(mach_task_self(), TASK_NAME_PORT, &port1);
	T_ASSERT_MACH_SUCCESS(kr, "task_get_special_port() - NAME");
	kr = task_identity_token_get_task_port(token, TASK_FLAVOR_NAME, &port2);
	T_ASSERT_MACH_SUCCESS(kr, "task_identity_token_get_task_port() - name");
	T_EXPECT_EQ(port1, port2, "Name port does not match!");

	mach_port_deallocate(mach_task_self(), port1);
	mach_port_deallocate(mach_task_self(), port2);

	kr = task_identity_token_get_task_port(mach_thread_self(), TASK_FLAVOR_NAME, &port2);
	T_EXPECT_NE(kr, KERN_SUCCESS, "task_identity_token_get_task_port() should fail on non-token port");

	mach_port_deallocate(mach_task_self(), token);
}
