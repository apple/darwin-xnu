#include <darwintest.h>

#include <mach/host_priv.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach_debug/ipc_info.h>
#include <mach/processor_set.h>
#include <mach/task.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <TargetConditionals.h>

#define IKOT_THREAD_CONTROL             1
#define IKOT_THREAD_READ                47
#define IKOT_THREAD_INSPECT             46

#define IKOT_TASK_CONTROL               2
#define IKOT_TASK_READ                  45
#define IKOT_TASK_INSPECT               44
#define IKOT_TASK_NAME                  20


/*
 * This test verifies various security properties for task and thread
 * read/inspect interfaces. Specifically, it checks and makes sure:
 *
 * 1. Task/thread can't get higher priv'ed ports from lower ones through
 * {task, thread}_get_special_port()
 * 2. Correct level of thread ports are returned from task_threads() with
 * a given task port flavor
 * 3. Correct level of task ports are returned from processor_set_tasks()
 * 4. MIG intrans conversion and enforcement for task/thread port does not break.
 * 5. task_{, read, inspect, name}_for_pid() works for self and other process
 * 6. The new mach_vm_remap_new interface behaves correctly
 */

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE));

static void
RESULT_CHECK(
	kern_return_t kr,
	unsigned int flavor,  /* task_flavor_t or thread_flavor_t */
	unsigned int required, /* task_flavor_t or thread_flavor_t */
	char *f_name)
{
	if (flavor <= required) {
		T_EXPECT_EQ(kr, KERN_SUCCESS, "%s should succeed with task/thread flavor %d, kr: 0x%x", f_name, flavor, kr);
	} else {
		T_EXPECT_NE(kr, KERN_SUCCESS, "%s should fail with task/thread flavor %d, kr: 0x%x", f_name, flavor, kr);
	}
}

static void
test_task_get_special_port(
	task_t  tport,
	task_flavor_t flavor)
{
	kern_return_t kr;
	mach_port_t special_port = MACH_PORT_NULL;
	mach_port_t tfp_port = MACH_PORT_NULL;

	T_LOG("Testing task_get_special_port() with task flavor %d", flavor);
	/* gettable with at least control port */
	kr = task_get_special_port(tport, TASK_KERNEL_PORT, &special_port);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_CONTROL, "task_get_special_port(TASK_KERNEL_PORT)");
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	kr = task_get_special_port(tport, TASK_BOOTSTRAP_PORT, &special_port);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_CONTROL, "task_get_special_port(TASK_BOOTSTRAP_PORT)");
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	kr = task_get_special_port(tport, TASK_HOST_PORT, &special_port);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_CONTROL, "task_get_special_port(TASK_HOST_PORT)");
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	/* gettable with at least read port */
	kr = task_get_special_port(tport, TASK_READ_PORT, &special_port);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_READ, "task_get_special_port(TASK_READ_PORT)");
	if (KERN_SUCCESS == kr) {
		kr = task_read_for_pid(mach_task_self(), getpid(), &tfp_port);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_read_for_pid()");
		T_QUIET; T_EXPECT_EQ(tfp_port, special_port, "task_read_for_pid() should match TASK_READ_PORT");
		mach_port_deallocate(mach_task_self(), tfp_port);
	}
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	/* gettable with at least inspect port */
	kr = task_get_special_port(tport, TASK_INSPECT_PORT, &special_port);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_INSPECT, "task_get_special_port(TASK_INSPECT_PORT)");
	if (KERN_SUCCESS == kr) {
		kr = task_inspect_for_pid(mach_task_self(), getpid(), &tfp_port);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_inspect_for_pid()");
		T_QUIET; T_EXPECT_EQ(tfp_port, special_port, "task_inspect_for_pid() should match TASK_INSPECT_PORT");
		mach_port_deallocate(mach_task_self(), tfp_port);
	}
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	/* gettable with at least name port */
	kr = task_get_special_port(tport, TASK_NAME_PORT, &special_port);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_INSPECT, "task_get_special_port(TASK_NAME_PORT)");
	if (KERN_SUCCESS == kr) {
		kr = task_name_for_pid(mach_task_self(), getpid(), &tfp_port);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_name_for_pid()");
		T_QUIET; T_EXPECT_EQ(tfp_port, special_port, "task_name_for_pid() should match TASK_NAME_PORT");
		mach_port_deallocate(mach_task_self(), tfp_port);
	}
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;
}

static void
test_thread_get_special_port(
	thread_t  tport,
	thread_flavor_t flavor)
{
	kern_return_t kr;
	mach_port_t special_port = MACH_PORT_NULL;

	T_LOG("Testing thread_get_special_port() with thread flavor %d", flavor);
	/* gettable with at least control port */
	kr = thread_get_special_port(tport, THREAD_KERNEL_PORT, &special_port);
	RESULT_CHECK(kr, flavor, THREAD_FLAVOR_CONTROL, "thread_get_special_port(THREAD_KERNEL_PORT)");
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	/* gettable with at least read port */
	kr = thread_get_special_port(tport, THREAD_READ_PORT, &special_port);
	RESULT_CHECK(kr, flavor, THREAD_FLAVOR_READ, "thread_get_special_port(THREAD_READ_PORT)");
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;

	/* gettable with at least inspect port */
	kr = thread_get_special_port(tport, THREAD_INSPECT_PORT, &special_port);
	RESULT_CHECK(kr, flavor, THREAD_FLAVOR_INSPECT, "thread_get_special_port(THREAD_INSPECT_PORT)");
	mach_port_deallocate(mach_task_self(), special_port);
	special_port = MACH_PORT_NULL;
}

static void
test_task_threads(
	task_t  tport,
	task_flavor_t flavor)
{
	kern_return_t kr;
	thread_array_t threadList;
	mach_msg_type_number_t threadCount = 0;

	unsigned int kotype;
	unsigned int kaddr;

	T_LOG("Testing task_threads() with task flavor %d", flavor);

	kr = task_threads(tport, &threadList, &threadCount);
	RESULT_CHECK(kr, flavor, TASK_FLAVOR_INSPECT, "task_threads");

	if (kr) {
		T_LOG("task_threads failed, skipping test_task_threads()");
		return;
	}

	T_QUIET; T_ASSERT_GE(threadCount, 1, "threadCount should be at least 1");

	/*
	 * TASK_FLAVOR_CONTROL -> THREAD_FLAVOR_CONTROL
	 * TASK_FLAVOR_READ    -> THREAD_FLAVOR_READ
	 * TASK_FLAVOR_INSPECT -> THREAD_FLAVOR_INSPECT
	 * TASK_FLAOVR_NAME    -> KERN_FAILURE
	 */
	for (size_t i = 0; i < threadCount; i++) {
		kr = mach_port_kernel_object(mach_task_self(), threadList[i], &kotype, &kaddr);
		if (kr == KERN_INVALID_RIGHT) {
			/* thread port is inactive */
			T_LOG("thread port name 0x%x is inactive", threadList[i]);
			continue;
		} else if (kr) {
			T_FAIL("mach_port_kernel_object() failed with kr: 0x%x", kr);
		}
		switch (flavor) {
		case TASK_FLAVOR_CONTROL:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_THREAD_CONTROL, "Task control port should yield thread control port");
			break;
		case TASK_FLAVOR_READ:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_THREAD_READ, "Task read port should yield thread read port");
			break;
		case TASK_FLAVOR_INSPECT:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_THREAD_INSPECT, "Task inspect port should yield thread inspect port");
			break;
		default:
			T_FAIL("task_threads() returned thread ports with task name port??");
			break;
		}
	}

	for (size_t i = 0; i < threadCount; i++) {
		mach_port_deallocate(mach_task_self(), threadList[i]);
	}
}

static void
test_processor_set_tasks(
	task_flavor_t flavor)
{
	kern_return_t kr;
	processor_set_name_array_t psets;
	processor_set_t        pset_priv;
	task_array_t taskList;
	mach_msg_type_number_t pcnt = 0, tcnt = 0;
	mach_port_t host = mach_host_self();

	unsigned int kotype;
	unsigned int kaddr;

	T_LOG("Testing processor_set_tasks() with task flavor %d", flavor);

	kr = host_processor_sets(host, &psets, &pcnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_processor_sets");
	T_QUIET; T_ASSERT_GE(pcnt, 1, "should have at least 1 processor set");

	kr = host_processor_set_priv(host, psets[0], &pset_priv);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_processor_set_priv");
	for (size_t i = 0; i < pcnt; i++) {
		mach_port_deallocate(mach_task_self(), psets[i]);
	}
	mach_port_deallocate(mach_task_self(), host);

	kr = processor_set_tasks_with_flavor(pset_priv, flavor, &taskList, &tcnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "processor_set_tasks_with_flavor");
	T_QUIET; T_ASSERT_GE(tcnt, 1, "should have at least 1 task");
	mach_port_deallocate(mach_task_self(), pset_priv);

	for (size_t i = 0; i < tcnt; i++) {
		kr = mach_port_kernel_object(mach_task_self(), taskList[i], &kotype, &kaddr);
		if (kr == KERN_INVALID_RIGHT) {
			/* task port is inactive */
			T_LOG("task port name 0x%x is inactive", taskList[i]);
			continue;
		} else if (kr) {
			T_FAIL("mach_port_kernel_object() failed with kr: 0x%x", kr);
		}
		switch (flavor) {
		case TASK_FLAVOR_CONTROL:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_TASK_CONTROL, "TASK_FLAVOR_CONTROL should yield control ports");
			break;
		case TASK_FLAVOR_READ:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_TASK_READ, "TASK_FLAVOR_READ should yield read ports");
			break;
		case TASK_FLAVOR_INSPECT:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_TASK_INSPECT, "TASK_FLAVOR_INSPECT should yield inspect ports");
			break;
		case TASK_FLAVOR_NAME:
			T_QUIET; T_EXPECT_EQ(kotype, IKOT_TASK_NAME, "TASK_FLAVOR_NAME should yield name ports");
			break;
		default:
			T_FAIL("strange flavor");
			break;
		}
	}

	for (size_t i = 0; i < tcnt; i++) {
		mach_port_deallocate(mach_task_self(), taskList[i]);
	}
}

static void
test_task_port_mig_intrans(
	task_t  tport,
	task_flavor_t   flavor)
{
	kern_return_t kr;

	T_LOG("Testing various MIG/manual intrans task interfaces with task flavor %d", flavor);

	{
		/* 1. Test some control port interfaces */
		int data = 0x41;
		int new_value = 0x42;
		kr = mach_vm_write(tport,
		    (mach_vm_address_t)&data,
		    (vm_offset_t)&new_value,
		    (mach_msg_type_number_t)sizeof(int));
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_CONTROL, "mach_vm_write");

		/* mach_vm_remap_new with max_protection VM_PROT_WRITE | VM_PROT_READ */
		int *localAddress = 0;
		mach_vm_address_t localMachVMAddress = 0;
		vm_prot_t cur_protection = VM_PROT_WRITE | VM_PROT_READ;
		vm_prot_t max_protection = VM_PROT_WRITE | VM_PROT_READ;
		/* rdar://67706101 (mach_vm_remap flag that allows restricting protection of remapped region) */
		kr = mach_vm_remap_new(mach_task_self(),
		    &localMachVMAddress,
		    sizeof(int),
		    0,
		    VM_FLAGS_ANYWHERE,
		    tport, /* remote task, use self task port */
		    (mach_vm_address_t)&data,
		    false,
		    &cur_protection,
		    &max_protection,
		    VM_INHERIT_NONE);
		localAddress = (int *)(uintptr_t)localMachVMAddress;

		RESULT_CHECK(kr, flavor, TASK_FLAVOR_CONTROL, "mach_vm_remap_new - VM_PROT_WRITE");
		if (KERN_SUCCESS == kr) {
			T_QUIET; T_EXPECT_EQ(max_protection, VM_PROT_READ | VM_PROT_WRITE, NULL);
			T_QUIET; T_EXPECT_EQ(cur_protection, VM_PROT_READ | VM_PROT_WRITE, NULL);
			T_QUIET; T_EXPECT_EQ(*localAddress, data, NULL); /* read */
			*localAddress = 0; /* write */
		}

		exception_mask_t masks[EXC_TYPES_COUNT] = {};
		mach_msg_type_number_t nmasks = 0;
		exception_port_t ports[EXC_TYPES_COUNT] = {};
		exception_behavior_t behaviors[EXC_TYPES_COUNT] = {};
		thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {};
		kr = task_get_exception_ports(tport, EXC_MASK_ALL,
		    masks, &nmasks, ports, behaviors, flavors);
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_CONTROL, "task_get_exception_ports");
		for (size_t i = 0; i < EXC_TYPES_COUNT; i++) {
			mach_port_deallocate(mach_task_self(), ports[i]);
		}
	}

	{
		/* 2. Test some read port interfaces */
		vm_offset_t read_value = 0;
		mach_msg_type_number_t read_cnt = 0;
		int data = 0x41;
		kr = mach_vm_read(tport,
		    (mach_vm_address_t)&data,
		    (mach_msg_type_number_t)sizeof(int),
		    &read_value,
		    &read_cnt);
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_READ, "mach_vm_read");

		/* mach_vm_remap_new with max_protection VM_PROT_READ */
		int *localAddress = 0;
		mach_vm_address_t localMachVMAddress = 0;
		vm_prot_t cur_protection = VM_PROT_READ;
		vm_prot_t max_protection = VM_PROT_READ;
		/* rdar://67706101 (mach_vm_remap flag that allows restricting protection of remapped region) */
		kr = mach_vm_remap_new(mach_task_self(),
		    &localMachVMAddress,
		    sizeof(int),
		    0,
		    VM_FLAGS_ANYWHERE,
		    tport, /* remote task, use self task port */
		    (mach_vm_address_t)&data,
		    false,
		    &cur_protection,
		    &max_protection,
		    VM_INHERIT_NONE);
		localAddress = (int *)(uintptr_t)localMachVMAddress;

		RESULT_CHECK(kr, flavor, TASK_FLAVOR_READ, "mach_vm_remap_new - VM_PROT_READ");
		if (KERN_SUCCESS == kr) {
			T_QUIET; T_EXPECT_EQ(max_protection, VM_PROT_READ, NULL);
			T_QUIET; T_EXPECT_EQ(cur_protection, VM_PROT_READ, NULL);
			T_QUIET; T_EXPECT_EQ(*localAddress, data, NULL); /* read */
		}

		/* mach_vm_remap_new with copy == TRUE */
		int data2 = 0x42;
		localAddress = 0;
		localMachVMAddress = 0;
		cur_protection = VM_PROT_WRITE | VM_PROT_READ;
		max_protection = VM_PROT_WRITE | VM_PROT_READ;

		kr = mach_vm_remap_new(mach_task_self(),
		    &localMachVMAddress,
		    sizeof(int),
		    0,
		    VM_FLAGS_ANYWHERE,
		    tport, /* remote task, use self task port */
		    (mach_vm_address_t)&data2,
		    true,
		    &cur_protection,
		    &max_protection,
		    VM_INHERIT_NONE);
		localAddress = (int *)(uintptr_t)localMachVMAddress;

		RESULT_CHECK(kr, flavor, TASK_FLAVOR_READ, "mach_vm_remap_new - copy==TRUE");
		if (KERN_SUCCESS == kr) {
			T_QUIET; T_EXPECT_EQ(max_protection, VM_PROT_READ | VM_PROT_WRITE, NULL);
			T_QUIET; T_EXPECT_EQ(cur_protection, VM_PROT_READ | VM_PROT_WRITE, NULL);
			/* Following is causing bus error tracked by rdar://71616700 (Unexpected BUS ERROR in mach_vm_remap_new()) */
			// T_QUIET; T_EXPECT_EQ(*localAddress, data2, NULL); /* read */
			// *localAddress = 0; /* write */
		}

		/* */
		mach_port_t voucher = MACH_PORT_NULL;
		kr = task_get_mach_voucher(tport, 0, &voucher);
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_READ, "task_get_mach_voucher");
		mach_port_deallocate(mach_task_self(), voucher);

		/* */
		ipc_info_space_t space_info;
		ipc_info_name_array_t table;
		mach_msg_type_number_t tableCount;
		ipc_info_tree_name_array_t tree; /* unused */
		mach_msg_type_number_t treeCount; /* unused */
		kr = mach_port_space_info(tport, &space_info, &table, &tableCount, &tree, &treeCount);
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_READ, "mach_port_space_info");
	}

	{
		/* 3. Test some inspect port interfaces */
		task_exc_guard_behavior_t exc_behavior;
		kr = task_get_exc_guard_behavior(tport, &exc_behavior);
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_INSPECT, "task_get_exc_guard_behavior");
	}

	{
		/* 4. Test some name port interfaces */
		struct task_basic_info info;
		mach_msg_type_number_t size = sizeof(info);
		kr = task_info(tport,
		    TASK_BASIC_INFO,
		    (task_info_t)&info,
		    &size);
		RESULT_CHECK(kr, flavor, TASK_FLAVOR_NAME, "task_info");
	}
}

static void
test_thread_port_mig_intrans(
	thread_t  tport,
	thread_flavor_t   flavor)
{
	kern_return_t kr;

	T_LOG("Testing various MIG/manual intrans thread interfaces with thread flavor %d", flavor);

	{
		/* 1. Test some control port interfaces */
		exception_mask_t masks[EXC_TYPES_COUNT] = {};
		mach_msg_type_number_t nmasks = 0;
		exception_port_t ports[EXC_TYPES_COUNT] = {};
		exception_behavior_t behaviors[EXC_TYPES_COUNT] = {};;
		thread_state_flavor_t flavors[EXC_TYPES_COUNT] = {};;
		kr = thread_get_exception_ports(tport, EXC_MASK_ALL,
		    masks, &nmasks, ports, behaviors, flavors);
		RESULT_CHECK(kr, flavor, THREAD_FLAVOR_CONTROL, "thread_get_exception_ports");
		for (size_t i = 0; i < EXC_TYPES_COUNT; i++) {
			mach_port_deallocate(mach_task_self(), ports[i]);
		}
	}

	{
		/* 2. Test some read port interfaces */
		mach_voucher_t voucher = MACH_PORT_NULL;
		kr = thread_get_mach_voucher(tport, 0, &voucher);
		RESULT_CHECK(kr, flavor, THREAD_FLAVOR_READ, "thread_get_mach_voucher");
		mach_port_deallocate(mach_task_self(), voucher);
	}

	{
		/* 3. Test some inspect port interfaces */
		processor_set_name_t name = MACH_PORT_NULL;
		kr = thread_get_assignment(tport, &name);
		RESULT_CHECK(kr, flavor, THREAD_FLAVOR_INSPECT, "thread_get_assignment");
		mach_port_deallocate(mach_task_self(), name);
	}
}

static void
test_get_child_task_port(void)
{
	pid_t child_pid;
	kern_return_t kr;
	mach_port_name_t tr, ti, tp, tn;

	child_pid = fork();

	T_LOG("Testing get child task ports");

	if (child_pid < 0) {
		T_FAIL("fork failed in test_get_child_port.");
	}

	if (child_pid == 0) {
		/* hang the child */
		while (1) {
			sleep(10);
		}
	}

	kr = task_for_pid(mach_task_self(), child_pid, &tp);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_for_pid for child %u", child_pid);

	kr = task_read_for_pid(mach_task_self(), child_pid, &tr);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_read_for_pid for child %u", child_pid);

	kr = task_inspect_for_pid(mach_task_self(), child_pid, &ti);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_inspect_for_pid for child %u", child_pid);

	kr = task_name_for_pid(mach_task_self(), child_pid, &tn);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_name_for_pid for child %u", child_pid);

	mach_port_deallocate(mach_task_self(), tp);
	mach_port_deallocate(mach_task_self(), tr);
	mach_port_deallocate(mach_task_self(), ti);
	mach_port_deallocate(mach_task_self(), tn);

	kill(child_pid, SIGKILL);
	int status;
	wait(&status);
}

T_DECL(read_inspect, "Test critical read and inspect port interfaces")
{
	mach_port_t control_port, movable_port, read_port, inspect_port, name_port;
	mach_port_t th_control_port, th_movable_port, th_read_port, th_inspect_port;
#define TASK_PORT_COUNT 5
#define THREAD_PORT_COUNT 4
	mach_port_t task_ports[TASK_PORT_COUNT];
	task_flavor_t task_flavors[TASK_PORT_COUNT];
	mach_port_t thread_ports[THREAD_PORT_COUNT];
	thread_flavor_t thread_flavors[THREAD_PORT_COUNT];
	kern_return_t kr;

	/* first, try getting all flavors of task port for self */
	kr = task_for_pid(mach_task_self(), getpid(), &control_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid()");
	task_ports[0] = control_port;
	task_flavors[0] = TASK_FLAVOR_CONTROL;

	kr = task_get_special_port(mach_task_self(), TASK_KERNEL_PORT, &movable_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_get_special_port(..TASK_KERNEL_PORT..)");
	task_ports[1] = movable_port;
	task_flavors[1] = TASK_FLAVOR_CONTROL;

	kr = task_read_for_pid(mach_task_self(), getpid(), &read_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_read_for_pid()");
	task_ports[2] = read_port;
	task_flavors[2] = TASK_FLAVOR_READ;

	kr = task_inspect_for_pid(mach_task_self(), getpid(), &inspect_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_inspect_for_pid()");
	task_ports[3] = inspect_port;
	task_flavors[3] = TASK_FLAVOR_INSPECT;

	kr = task_name_for_pid(mach_task_self(), getpid(), &name_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_name_for_pid()");
	task_ports[4] = name_port;
	task_flavors[4] = TASK_FLAVOR_NAME;


	for (size_t i = 0; i < TASK_PORT_COUNT; i++) {
		/*
		 * 1. Make sure can't get higher priv'ed ports from lower ones through
		 * task_get_special_port()
		 */
		test_task_get_special_port(task_ports[i], task_flavors[i]);

		/*
		 * 2. Make sure correct level of thread ports are returned from task_threads
		 */
		test_task_threads(task_ports[i], task_flavors[i]);

		/*
		 * 3. Make sure correct level of task ports are returned from processor_set_tasks
		 */
		if (i >= 1) {
			test_processor_set_tasks(task_flavors[i]);
		}

		/*
		 * 4. Make sure our MIG intrans enforcement for tasks does not break.
		 */
		test_task_port_mig_intrans(task_ports[i], task_flavors[i]);
	}


	for (size_t i = 0; i < TASK_PORT_COUNT; i++) {
		mach_port_deallocate(mach_task_self(), task_ports[i]);
	}

	/* 4. Try spawning a child an get its task ports */
	test_get_child_task_port();

	/* Now, test thread read/inspect ports */
	th_control_port = mach_thread_self();
	thread_ports[0] = th_control_port;
	thread_flavors[0] = THREAD_FLAVOR_CONTROL;

	kr = thread_get_special_port(th_control_port, THREAD_KERNEL_PORT, &th_movable_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_get_special_port(..THREAD_KERNEL_PORT..)");
	thread_ports[1] = th_movable_port;
	thread_flavors[1] = THREAD_FLAVOR_CONTROL;

	kr = thread_get_special_port(th_control_port, THREAD_READ_PORT, &th_read_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_get_special_port(..THREAD_READ_PORT..)");
	thread_ports[2] = th_read_port;
	thread_flavors[2] = THREAD_FLAVOR_READ;

	kr = thread_get_special_port(th_control_port, THREAD_INSPECT_PORT, &th_inspect_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_get_special_port(..THREAD_INSPECT_PORT..)");
	thread_ports[3] = th_inspect_port;
	thread_flavors[3] = THREAD_FLAVOR_INSPECT;


	for (size_t i = 0; i < THREAD_PORT_COUNT; i++) {
		/*
		 * 1. Make sure can't get higher priv'ed ports from lower ones through
		 * thread_get_special_port()
		 */
		test_thread_get_special_port(thread_ports[i], thread_flavors[i]);

		/*
		 * 2. Make sure our MIG intrans enforcement for threads does not break.
		 */
		test_thread_port_mig_intrans(thread_ports[i], thread_flavors[i]);
	}

	for (size_t i = 0; i < THREAD_PORT_COUNT; i++) {
		mach_port_deallocate(mach_task_self(), thread_ports[i]);
	}
}
