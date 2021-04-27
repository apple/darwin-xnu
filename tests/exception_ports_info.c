#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach_debug/ipc_info.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(exception_ports_info, "Test {task, thread}_get_exception_ports_info")
{
	kern_return_t kr;
	mach_port_t exc_port1, exc_port2, exc_port3;

	mach_msg_type_number_t count = EXC_TYPES_COUNT;
	exception_mask_t masks[EXC_TYPES_COUNT];
	ipc_info_port_t ports_info[EXC_TYPES_COUNT];
	exception_behavior_t behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors[EXC_TYPES_COUNT];

	mach_msg_type_number_t count2 = EXC_TYPES_COUNT;
	exception_mask_t masks2[EXC_TYPES_COUNT];
	mach_port_t ports[EXC_TYPES_COUNT];
	exception_behavior_t behaviors2[EXC_TYPES_COUNT];
	thread_state_flavor_t flavors2[EXC_TYPES_COUNT];

	unsigned int exc_port1_kotype = 0, exc_port1_kaddr = 0;
	unsigned int exc_port2_kotype = 0, exc_port2_kaddr = 0;
	unsigned int kotype = 0, kobject = 0, exc_port3_kotype = 0, exc_port3_kaddr = 0;
	boolean_t found_exc_port1 = false;
	boolean_t found_exc_port2 = false;
	boolean_t found_exc_port3 = false;

	ipc_info_space_t info_space;
	ipc_info_name_array_t table;
	ipc_info_tree_name_array_t tree;
	mach_msg_type_number_t tblcnt = 0, treecnt = 0;

	/* Create the mach port the exception messages will be sent to. */
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Allocated mach exception port");
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port2);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Allocated mach exception port");
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port3);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Allocated mach exception port");

	/*
	 * Insert a send right into the exception port that the kernel will use to
	 * send the exception thread the exception messages.
	 */
	kr = mach_port_insert_right(mach_task_self(), exc_port1, exc_port1, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Inserted a SEND right into the exception port");
	kr = mach_port_insert_right(mach_task_self(), exc_port2, exc_port2, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Inserted a SEND right into the exception port");
	kr = mach_port_insert_right(mach_task_self(), exc_port3, exc_port3, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Inserted a SEND right into the exception port");

	T_LOG("exc_port1: 0x%x", exc_port1);
	T_LOG("exc_port2: 0x%x", exc_port2);
	T_LOG("exc_port3: 0x%x", exc_port3);

	/* Tell the kernel what port to send exceptions to. */
	kr = task_set_exception_ports(
		mach_task_self(),
		EXC_MASK_GUARD,
		exc_port1,
		(exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES),
		THREAD_STATE_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Set the exception port to my custom handler");

	kr = task_set_exception_ports(
		mach_task_self(),
		EXC_MASK_RPC_ALERT,  /* why can't be EXC_CRASH or EXC_MASK_CORPSE_NOTIFY ? */
		exc_port2,
		(exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES),
		THREAD_STATE_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Set the exception port to my custom handler");

	kr = task_set_exception_ports(
		mach_task_self(),
		EXC_MASK_RESOURCE | EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL,
		exc_port3,
		(exception_behavior_t)(EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES),
		THREAD_STATE_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Set the exception port to my custom handler");

	/* now, get exception ports info */
	kr = thread_get_exception_ports(mach_thread_self(), EXC_MASK_ALL, masks2, &count2, ports, behaviors2, flavors2);
	T_EXPECT_MACH_SUCCESS(kr, "thread_get_exception_ports(): 0x%x", kr);
	T_EXPECT_EQ(count2, 0, "should have 0 exception ports");

	kr = thread_get_exception_ports_info(mach_thread_self(), EXC_MASK_ALL, masks, &count, ports_info, behaviors, flavors);
	T_EXPECT_MACH_SUCCESS(kr, "thread_get_exception_ports_info(): 0x%x", kr);
	T_EXPECT_EQ(count, 0, "should have 0 exception ports");

	count = EXC_TYPES_COUNT;
	count2 = EXC_TYPES_COUNT;

	kr = task_get_exception_ports_info(mach_task_self(), EXC_MASK_ALL, masks, &count, ports_info, behaviors, flavors);
	T_EXPECT_MACH_SUCCESS(kr, "task_get_exception_ports_info(): 0x%x", kr);
	T_EXPECT_EQ(count, 4, "should have 4 masks"); /* Returns 3 if one exc_port registers for EXC_CRASH */

	/* get exception ports */
	kr = task_get_exception_ports(mach_task_self(), EXC_MASK_ALL, masks2, &count2, ports, behaviors2, flavors2);
	T_EXPECT_MACH_SUCCESS(kr, "task_get_exception_ports(): 0x%x", kr);

	for (int i = 0; i < count2; i++) {
		T_LOG("exception port name: 0x%x", ports[i]);
	}
	T_EXPECT_EQ(count, count2, "should return same mask count");

	kr = memcmp(masks, masks2, count * sizeof(exception_mask_t));
	T_EXPECT_EQ(kr, 0, "masks should be the same");

	kr = memcmp(behaviors, behaviors2, count * sizeof(exception_behavior_t));
	T_EXPECT_EQ(kr, 0, "behaviors should be the same");

	kr = memcmp(flavors, flavors, count * sizeof(thread_state_flavor_t));
	T_EXPECT_EQ(kr, 0, "flavors should be the same");

	kr = mach_port_kernel_object(mach_task_self(), mach_task_self(), &kotype, &kobject);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_kernel_object(): 0x%x", kr);
	T_LOG("task_self kobject: 0x%x", kobject);

	T_QUIET; T_EXPECT_MACH_SUCCESS(mach_port_space_info(mach_task_self(), &info_space, &table,
	    &tblcnt, &tree, &treecnt), "mach_port_space_info(): 0x%x", kr);

	for (int i = 0; i < tblcnt; i++) {
		if (table[i].iin_name == exc_port1) {
			exc_port1_kaddr = table[i].iin_object;
		}
		if (table[i].iin_name == exc_port2) {
			exc_port2_kaddr = table[i].iin_object;
		}
		if (table[i].iin_name == exc_port3) {
			exc_port3_kaddr = table[i].iin_object;
		}
	}

	T_LOG("exc_port_1_kaddr: 0x%x", exc_port1_kaddr);
	T_LOG("exc_port_2_kaddr: 0x%x", exc_port2_kaddr);
	T_LOG("exc_port_3_kaddr: 0x%x", exc_port3_kaddr);

	for (int i = 0; i < count; i++) {
		T_LOG("ports_info[%d].iip_port_object: 0x%x", i, ports_info[i].iip_port_object);

		if (ports_info[i].iip_port_object == exc_port1_kaddr) {
			T_EXPECT_NE(ports_info[i].iip_port_object, 0,
			    "on debug/kernel, port object should be non-zero: 0x%x", ports_info[i].iip_port_object);
			T_EXPECT_EQ(ports_info[i].iip_receiver_object, kobject,
			    "receiver object should match task self kobject: 0x%x", ports_info[i].iip_receiver_object);
			T_EXPECT_EQ(masks[i], EXC_MASK_GUARD, "check if mask for exc_port1 is correct");
			found_exc_port1 = true;
		}
		if (ports_info[i].iip_port_object == exc_port2_kaddr) {
			T_EXPECT_NE(ports_info[i].iip_port_object, 0,
			    "on debug/kernel, port object should be non-zero: 0x%x", ports_info[i].iip_port_object);
			T_EXPECT_EQ(ports_info[i].iip_receiver_object, kobject,
			    "receiver object should match task self kobject: 0x%x", ports_info[i].iip_receiver_object);
			T_EXPECT_EQ(masks[i], EXC_MASK_RPC_ALERT, "check if mask for exc_port2 is correct");
			found_exc_port2 = true;
		}
		if (ports_info[i].iip_port_object == exc_port3_kaddr) {
			T_EXPECT_NE(ports_info[i].iip_port_object, 0,
			    "on debug/kernel, port object should be non-zero: 0x%x", ports_info[i].iip_port_object);
			T_EXPECT_EQ(ports_info[i].iip_receiver_object, kobject,
			    "receiver object should match task self kobject: 0x%x", ports_info[i].iip_receiver_object);
			T_EXPECT_EQ(masks[i], EXC_MASK_RESOURCE | EXC_MASK_BREAKPOINT | EXC_MASK_SYSCALL, "check if mask for exc_port3 is correct");
			found_exc_port3 = true;
		}
	}

	T_EXPECT_TRUE(found_exc_port1, "should find exc_port1");
	T_EXPECT_TRUE(found_exc_port2, "should find exc_port2");
	T_EXPECT_TRUE(found_exc_port3, "should find exc_port3");
}
