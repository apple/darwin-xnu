#include <darwintest.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <mach/port.h>
#include <mach/mach_port.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(immovable_rights, "Create a port with immovable receive rights") {
	mach_port_t imm_port;
	mach_port_options_t opts = {
		.flags = MPO_CONTEXT_AS_GUARD | MPO_IMMOVABLE_RECEIVE
	};
	kern_return_t kr;

	kr = mach_port_construct(mach_task_self(), &opts, 0x10, &imm_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	mach_port_status_t status;
	mach_msg_type_number_t status_size = MACH_PORT_RECEIVE_STATUS_COUNT;
	kr = mach_port_get_attributes(mach_task_self(), imm_port,
	    MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &status_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_get_attributes");
	T_LOG("Status flags %d", status.mps_flags);
	T_ASSERT_NE(0, (status.mps_flags & MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE), "Imm rcv bit is set");

	mach_port_t imm_port2;
	mach_port_options_t opts2 = {};

	kr = mach_port_construct(mach_task_self(), &opts2, 0, &imm_port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	kr = mach_port_guard_with_flags(mach_task_self(), imm_port2, 0x11, (uint64_t)MPG_IMMOVABLE_RECEIVE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_guard_with_flags");

	kr = mach_port_get_attributes(mach_task_self(), imm_port2,
	    MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &status_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_get_attributes");
	T_LOG("Status flags %d", status.mps_flags);
	T_ASSERT_NE(0, (status.mps_flags & MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE), "Imm rcv bit is set");

	kr = mach_port_swap_guard(mach_task_self(), imm_port2, 0x11, 0xde18);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_swap_guard");

	kr = mach_port_unguard(mach_task_self(), imm_port2, 0xde18);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_unguard");
}
