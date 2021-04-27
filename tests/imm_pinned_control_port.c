#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <excserver.h>
#include <sys/sysctl.h>
#include <spawn.h>
#include <signal.h>
#include <TargetConditionals.h>

#define MAX_ARGV 3
#define EXC_CODE_SHIFT 32
#define EXC_GUARD_TYPE_SHIFT 29
#define MAX_TEST_NUM 13

#define TASK_EXC_GUARD_MP_DELIVER 0x10

extern char **environ;
static uint64_t exception_code = 0;
static exception_type_t exception_taken = 0;

#define IKOT_TASK_CONTROL               2

/*
 * This test verifies behaviors of immovable/pinned task/thread ports.
 *
 * 1. Compare and verifies port names of mach_{task, thread}_self(),
 * {TASK, THREAD}_KERNEL_PORT, and ports returned from task_threads()
 * and processor_set_tasks().
 * 2. Make sure correct exceptions are raised resulting from moving immovable
 * task/thread control, read and inspect ports.
 * 3. Make sure correct exceptions are raised resulting from deallocating pinned
 * task/thread control ports.
 * 4. Make sure immovable ports cannot be stashed:
 * rdar://70585367 (Disallow immovable port stashing with *_set_special_port() and mach_port_register())
 */
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(TRUE));

static uint64_t test_exception_code[] = {
	/* Pinning tests. Currently delivered as soft crash */
	EXC_GUARD, // Soft crash delivered as EXC_CORPSE_NOTIFY
	EXC_GUARD,
	EXC_GUARD,
	EXC_GUARD,
	EXC_GUARD,

	/* Immovable tests. Currently delivered as hard crash */
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_IMMOVABLE,
};

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread, task, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, code_count)
	pid_t pid;
	kern_return_t kr = pid_for_task(task, &pid);
	T_EXPECT_MACH_SUCCESS(kr, "pid_for_task");
	T_LOG("Crashing child pid: %d, continuing...\n", pid);

	kr = mach_port_deallocate(mach_task_self(), thread);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), task);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	T_LOG("Caught exception type: %d code: 0x%llx", exception, *((uint64_t*)code));
	if (exception == EXC_GUARD || exception == EXC_CORPSE_NOTIFY) {
		exception_taken = exception;
		exception_code = *((uint64_t *)code);
	} else {
		T_FAIL("Unexpected exception");
	}
	return KERN_SUCCESS;
}

static void *
exception_server_thread(void *arg)
{
	kern_return_t kr;
	mach_port_t exc_port = *(mach_port_t *)arg;

	/* Handle exceptions on exc_port */
	kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_msg_server_once");

	return NULL;
}

static mach_port_t
alloc_exception_port(void)
{
	kern_return_t kret;
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	kret = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kret, "mach_port_allocate exc_port");

	kret = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kret, "mach_port_insert_right exc_port");

	return exc_port;
}

static void
test_immovable_port_stashing(void)
{
	kern_return_t kr;
	mach_port_t port;

	kr = task_set_special_port(mach_task_self(), TASK_BOOTSTRAP_PORT, mach_task_self());
	T_EXPECT_EQ(kr, KERN_INVALID_RIGHT, "should disallow task_set_special_port() with immovable port");

	kr = thread_set_special_port(mach_thread_self(), THREAD_KERNEL_PORT, mach_thread_self());
	T_EXPECT_EQ(kr, KERN_INVALID_RIGHT, "should disallow task_set_special_port() with immovable port");

	mach_port_t stash[1] = {mach_task_self()};
	kr = mach_ports_register(mach_task_self(), stash, 1);
	T_EXPECT_EQ(kr, KERN_INVALID_RIGHT, "should disallow mach_ports_register() with immovable port");

	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port), "mach_port_allocate");
	T_QUIET; T_ASSERT_MACH_SUCCESS(mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND), "mach_port_insert_right");

	stash[0] = port;
	kr = mach_ports_register(mach_task_self(), stash, 1);
	T_EXPECT_MACH_SUCCESS(kr, "mach_ports_register() should succeed with movable port");
}

static void
test_task_thread_port_values(void)
{
	T_LOG("Compare various task/thread control port values\n");
	kern_return_t kr;
	mach_port_t port, th_self;
	thread_array_t threadList;
	mach_msg_type_number_t threadCount = 0;
	boolean_t found_self = false;
	processor_set_name_array_t psets;
	processor_set_t        pset_priv;
	task_array_t taskList;
	mach_msg_type_number_t pcnt = 0, tcnt = 0;
	mach_port_t host = mach_host_self();

	/* Compare with task/thread_get_special_port() */
	kr = task_get_special_port(mach_task_self(), TASK_KERNEL_PORT, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_get_special_port() - TASK_KERNEL_PORT");
	T_EXPECT_NE(port, mach_task_self(), "TASK_KERNEL_PORT should not match mach_task_self()");
	mach_port_deallocate(mach_task_self(), port);

	kr = task_for_pid(mach_task_self(), getpid(), &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_for_pid()");
	T_EXPECT_EQ(port, mach_task_self(), "task_for_pid(self) should match mach_task_self()");
	mach_port_deallocate(mach_task_self(), port);

	th_self = mach_thread_self();
	kr = thread_get_special_port(th_self, THREAD_KERNEL_PORT, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_get_special_port() - THREAD_KERNEL_PORT");
	T_EXPECT_NE(port, th_self, "THREAD_KERNEL_PORT should not match mach_thread_self()");
	mach_port_deallocate(mach_task_self(), port);

	/* Make sure task_threads() return immovable thread ports */
	kr = task_threads(mach_task_self(), &threadList, &threadCount);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_threads()");
	T_QUIET; T_ASSERT_GE(threadCount, 1, "should have at least 1 thread");

	for (size_t i = 0; i < threadCount; i++) {
		if (th_self == threadList[i]) { /* th_self is immovable */
			found_self = true;
			break;
		}
	}

	T_EXPECT_TRUE(found_self, "task_threads() should return immovable thread self");

	for (size_t i = 0; i < threadCount; i++) {
		mach_port_deallocate(mach_task_self(), threadList[i]);
	}

	if (threadCount > 0) {
		mach_vm_deallocate(mach_task_self(),
		    (mach_vm_address_t)threadList,
		    threadCount * sizeof(mach_port_t));
	}

	mach_port_deallocate(mach_task_self(), th_self);

	/* Make sure processor_set_tasks() return immovable task self */
	kr = host_processor_sets(host, &psets, &pcnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_processor_sets");
	T_QUIET; T_ASSERT_GE(pcnt, 1, "should have at least 1 processor set");

	kr = host_processor_set_priv(host, psets[0], &pset_priv);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_processor_set_priv");
	for (size_t i = 0; i < pcnt; i++) {
		mach_port_deallocate(mach_task_self(), psets[i]);
	}
	mach_port_deallocate(mach_task_self(), host);
	vm_deallocate(mach_task_self(), (vm_address_t)psets, (vm_size_t)pcnt * sizeof(mach_port_t));

	kr = processor_set_tasks_with_flavor(pset_priv, TASK_FLAVOR_CONTROL, &taskList, &tcnt);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "processor_set_tasks_with_flavor");
	T_QUIET; T_ASSERT_GE(tcnt, 1, "should have at least 1 task");
	mach_port_deallocate(mach_task_self(), pset_priv);

	found_self = false;
	for (size_t i = 0; i < tcnt; i++) {
		if (taskList[i] == mach_task_self()) {
			found_self = true;
			break;
		}
	}

	T_EXPECT_TRUE(found_self, " processor_set_tasks() should return immovable task self");

	for (size_t i = 0; i < tcnt; i++) {
		mach_port_deallocate(mach_task_self(), taskList[i]);
	}

	if (tcnt > 0) {
		mach_vm_deallocate(mach_task_self(),
		    (mach_vm_address_t)taskList,
		    tcnt * sizeof(mach_port_t));
	}
}

T_DECL(imm_pinned_control_port, "Test pinned & immovable task and thread control ports",
    T_META_IGNORECRASHES(".*pinned_rights_child.*"),
    T_META_CHECK_LEAKS(false))
{
	uint32_t task_exc_guard = 0;
	size_t te_size = sizeof(&task_exc_guard);
	posix_spawnattr_t       attrs;
	char *test_prog_name = "./imm_pinned_control_port_crasher";
	char *child_args[MAX_ARGV];
	pid_t client_pid = 0;
	uint32_t opts = 0;
	size_t size = sizeof(&opts);
	mach_port_t exc_port;
	pthread_t s_exc_thread;
	uint64_t exc_id;

	T_LOG("Check if task_exc_guard exception has been enabled\n");
	int ret = sysctlbyname("kern.task_exc_guard_default", &task_exc_guard, &te_size, NULL, 0);
	T_ASSERT_EQ(ret, 0, "sysctlbyname");

	if (!(task_exc_guard & TASK_EXC_GUARD_MP_DELIVER)) {
		T_SKIP("task_exc_guard exception is not enabled");
	}

	T_LOG("Check if immovable control port has been enabled\n");
	ret = sysctlbyname("kern.ipc_control_port_options", &opts, &size, NULL, 0);

	if (!ret && (opts & 0x30) == 0) {
		T_SKIP("immovable control port isn't enabled");
	}

	/* first, try out comparing various task/thread ports */
	test_task_thread_port_values();

	/* try stashing immovable ports: rdar://70585367 */
	test_immovable_port_stashing();

	/* spawn a child and see if EXC_GUARD are correctly generated */
	for (int i = 0; i < MAX_TEST_NUM; i++) {
		/* Create the exception port for the child */
		exc_port = alloc_exception_port();
		T_QUIET; T_ASSERT_NE(exc_port, MACH_PORT_NULL, "Create a new exception port");

		/* Create exception serving thread */
		ret = pthread_create(&s_exc_thread, NULL, exception_server_thread, &exc_port);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create exception_server_thread");

		/* Initialize posix_spawn attributes */
		posix_spawnattr_init(&attrs);

		int err = posix_spawnattr_setexceptionports_np(&attrs, EXC_MASK_GUARD | EXC_MASK_CORPSE_NOTIFY, exc_port,
		    (exception_behavior_t) (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "posix_spawnattr_setflags");

		child_args[0] = test_prog_name;
		char test_num[10];
		sprintf(test_num, "%d", i);
		child_args[1] = test_num;
		child_args[2] = NULL;

		T_LOG("========== Spawning new child ==========");
		err = posix_spawn(&client_pid, child_args[0], NULL, &attrs, &child_args[0], environ);
		T_ASSERT_POSIX_SUCCESS(err, "posix_spawn control_port_options_client = %d test_num = %d", client_pid, i);

		/* try extracting child task port: rdar://71744817
		 * Moved to tests/extract_right_soft_fail.c
		 */
		// test_extract_immovable_task_port(client_pid);

		int child_status;
		/* Wait for child and check for exception */
		if (-1 == waitpid(-1, &child_status, 0)) {
			T_FAIL("waitpid: child mia");
		}

		if (WIFEXITED(child_status) && WEXITSTATUS(child_status)) {
			T_FAIL("Child exited with status = %x", child_status);
			T_END;
		}

		sleep(1);
		kill(1, SIGKILL);

		ret = pthread_join(s_exc_thread, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");

		if (exception_taken == EXC_GUARD) {
			exc_id = exception_code >> EXC_CODE_SHIFT;
		} else {
			exc_id = exception_code;
		}

		T_LOG("Exception code: Received code = 0x%llx Expected code = 0x%llx", exc_id, test_exception_code[i]);
		T_EXPECT_EQ(exc_id, test_exception_code[i], "Exception code: Received == Expected");
	}
}
