#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <darwintest.h>
#include <pthread.h>
#include <signal.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_error.h>
#include <System/sys/codesign.h>
#include <sys/proc.h>

int task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
int task_read_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
int task_inspect_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
int task_name_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
static int test_conversion_eval(pid_t current, pid_t victim, int translation);

static int g_tfpFail  = 0;
static int g_trfpFail = 0;
static int g_tifpFail = 0;
static int g_tnfpFail = 0;

static pthread_mutex_t g_lock;

#define NAME    0
#define INSPECT 1
#define READ    2
#define FULL    3
#define POLY    4

/*
 *  3. child still spawn as platform binary
 */

/* Mimic the behavior of task_conversion_eval in kernel.
 */
static int
test_conversion_eval(pid_t current, pid_t victim, int translation)
{
	uint32_t my_csflags = 0;
	uint32_t victim_csflags = 0;
	csops(victim, CS_OPS_STATUS, &victim_csflags, sizeof(victim_csflags));
	csops(current, CS_OPS_STATUS, &my_csflags, sizeof(my_csflags));

	switch (translation) {
	case FULL:
	case READ:
		if (victim == 0) {
			return false;
		}
		if (!(my_csflags & CS_PLATFORM_BINARY) && (victim_csflags & CS_PLATFORM_BINARY)) {
			return false;
		}
		break;
	default:
		break;
	}

	return true;
}

static void
check_result(kern_return_t kr, int port_type, int translation, int low, char *test_str, pid_t victim)
{
	char error[100];

	if (translation == POLY) {
		if (port_type == FULL) {
			translation = INSPECT;
		} else {
			translation = port_type;
		}
	}

	if (port_type < low) {
		goto fail;
	} else if (port_type < translation) {
		goto fail;
	} else if (!test_conversion_eval(getpid(), victim, translation)) {
		goto fail;
	} else {
		goto success;
	}

fail:
	snprintf(error, sizeof(error), "%s should fail with %d on %d.\n", test_str, port_type, victim);
	T_QUIET; T_EXPECT_NE(kr, 0, "check_result: %s", error);
	return;
success:
	snprintf(error, sizeof(error), "%s should succeed with %d on %d.\n", test_str, port_type, victim);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "check_result: %s", error);
	return;
}

static void
test_thread_port(mach_port_name_t thread, int type, pid_t victim)
{
	kern_return_t kr;
	mach_port_t name = MACH_PORT_NULL;
	thread_info_data_t th_info;
	mach_msg_type_number_t th_info_cnt = THREAD_INFO_MAX;

	kr = thread_info(thread, THREAD_BASIC_INFO, (thread_info_t)th_info, &th_info_cnt);
	check_result(kr, type, INSPECT, INSPECT, "thread_info", victim);

	kr = thread_get_special_port(thread, THREAD_KERNEL_PORT, &name);
	check_result(kr, type, POLY, FULL, "thread_get_special_port: THREAD_KERNEL_PORT", victim);
	kr = mach_port_deallocate(mach_task_self(), name);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	kr = thread_get_special_port(thread, THREAD_READ_PORT, &name);
	check_result(kr, type, POLY, READ, "thread_get_special_port: THREAD_READ_PORT", victim);
	kr = mach_port_deallocate(mach_task_self(), name);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	kr = thread_get_special_port(thread, THREAD_INSPECT_PORT, &name);
	check_result(kr, type, POLY, INSPECT, "thread_get_special_port: THREAD_INSPECT_PORT", victim);
	kr = mach_port_deallocate(mach_task_self(), name);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
}

static void
test_task_port(mach_port_name_t port, int type)
{
	kern_return_t kr;
	volatile int data = 0x4141;
	volatile int new_value = 0x4242;
	pid_t victim;
	if (port == MACH_PORT_NULL) {
		return;
	}
	kr = pid_for_task(port, &victim);
	if (victim == -1) {
		T_LOG("pid_for_task: port = 0x%x, type = %u is not valid anymore", port, type);
		return;
	}
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "pid_for_task, port = 0x%x, type = %u, pid = %u", port, type, victim);

	/************* TASK_INFO ************/
	struct task_basic_info info = {};
	mach_msg_type_number_t cnt = sizeof(info);
	kr = task_info(port, TASK_BASIC_INFO, (task_info_t)&info, &cnt);
	check_result(kr, type, NAME, NAME, "task_info", victim);

	/************ MACH_VM_* ************/

	if (victim == getpid()) {
		kr = mach_vm_write(port,
		    (mach_vm_address_t)&data,
		    (vm_offset_t)&new_value,
		    (mach_msg_type_number_t)sizeof(int));
		check_result(kr, type, FULL, FULL, "mach_vm_write", victim);

		vm_offset_t read_value = 0;
		mach_msg_type_number_t read_cnt = 0;
		kr = mach_vm_read(port,
		    (mach_vm_address_t)&data,
		    (mach_msg_type_number_t)sizeof(int),
		    &read_value,
		    &read_cnt);
		check_result(kr, type, READ, READ, "mach_vm_read", victim);
	}

	/************ TASK_GET_SPECIAL_PORT ************/

	mach_port_t name = MACH_PORT_NULL;
	kr = task_get_special_port(port, TASK_KERNEL_PORT, &name);
	check_result(kr, type, POLY, FULL, "task_get_special_port: TASK_KERNEL_PORT", victim);

	name = MACH_PORT_NULL;
	kr = task_get_special_port(port, TASK_READ_PORT, &name);
	check_result(kr, type, POLY, READ, "task_get_special_port: TASK_READ_PORT", victim);
	if (kr == KERN_SUCCESS) {
		kr = mach_port_deallocate(mach_task_self(), name);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	name = MACH_PORT_NULL;
	kr = task_get_special_port(port, TASK_INSPECT_PORT, &name);
	check_result(kr, type, POLY, INSPECT, "task_get_special_port: TASK_INSPECT_PORT", victim);
	if (kr == KERN_SUCCESS) {
		kr = mach_port_deallocate(mach_task_self(), name);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	name = MACH_PORT_NULL;
	kr = task_get_special_port(port, TASK_NAME_PORT, &name);
	check_result(kr, type, POLY, INSPECT, "task_get_special_port: TASK_NAME_PORT", victim);
	if (kr == KERN_SUCCESS) {
		kr = mach_port_deallocate(mach_task_self(), name);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	name = MACH_PORT_NULL;
	kr = task_get_special_port(port, TASK_HOST_PORT, &name);
	check_result(kr, type, POLY, FULL, "task_get_special_port: TASK_HOST_PORT", victim);
	if (kr == KERN_SUCCESS) {
		if (victim == getpid()) {
			mach_port_t host = mach_host_self();
			T_QUIET; T_EXPECT_EQ(host, name, "mach_host_self == task_get_special_port(.. TASK_HOST_PORT)");
		}
	}

	name = MACH_PORT_NULL;
	kr = task_get_special_port(port, TASK_BOOTSTRAP_PORT, &name);
	check_result(kr, type, POLY, FULL, "task_get_special_port: TASK_BOOTSTRAP_PORT", victim);

	/************ TEST IPC_SPACE_READ AND IPC_SPACE_INSPECT ************/
	if (victim == getpid()) {
		mach_port_status_t status;
		mach_msg_type_number_t statusCnt = MACH_PORT_LIMITS_INFO_COUNT;
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &name);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, 0, "mach_port_allocate should succeed");

		kr = mach_port_get_attributes(port, name, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&status, &statusCnt);
		check_result(kr, type, POLY, READ, "mach_port_get_attributes", victim);

		mach_port_context_t context;
		kr = mach_port_get_context(port, name, &context);
		check_result(kr, type, POLY, READ, "mach_port_get_context", victim);

		kr = mach_port_destruct(mach_task_self(), name, 0, 0);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct");
	}

	ipc_info_space_basic_t sinfo;
	kr = mach_port_space_basic_info(port, &sinfo);
	check_result(kr, type, INSPECT, INSPECT, "mach_port_space_basic_info", victim);

	/************ MACH_PORT_ALLOCATE ************/

	mach_port_t new_port = MACH_PORT_NULL;
	kr = mach_port_allocate(port, MACH_PORT_RIGHT_RECEIVE, &new_port);
	check_result(kr, type, FULL, FULL, "mach_port_allocate", victim);
	if (kr == KERN_SUCCESS) {
		kr = mach_port_destruct(port, new_port, 0, 0);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_destruct");
	}

	/************ INSPECT INTERFACES ************/
	int counts[2];
	mach_msg_type_number_t size = TASK_INSPECT_BASIC_COUNTS_COUNT;
	kr = task_inspect(port, TASK_INSPECT_BASIC_COUNTS, counts, &size);
	check_result(kr, type, INSPECT, INSPECT, "task_inspect", victim);

	/************ TASK_SET_SPECIAL_PORT ************/

	if (type == FULL) {
		new_port = MACH_PORT_NULL;
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &new_port);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_allocate");
		kr = mach_port_insert_right(mach_task_self(), new_port, new_port, MACH_MSG_TYPE_MAKE_SEND);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_insert_right");

		mach_port_t backup;
		kr = task_get_special_port(port, TASK_BOOTSTRAP_PORT, &backup);
		check_result(kr, type, POLY, FULL, "task_get_special_port", victim);
		kr = task_set_special_port(port, TASK_BOOTSTRAP_PORT, new_port);
		check_result(kr, type, FULL, FULL, "task_set_special_port", victim);
		kr = task_set_special_port(port, TASK_BOOTSTRAP_PORT, backup);
		check_result(kr, type, FULL, FULL, "task_set_special_port", victim);

		kr = mach_port_deallocate(mach_task_self(), new_port);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
		mach_port_mod_refs(mach_task_self(), new_port, MACH_PORT_RIGHT_RECEIVE, -1);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_mod_refs");
	}
	/************ TASK_THREADS ************/
	thread_array_t th_list;
	mach_msg_type_number_t th_cnt = 0;

	kr = task_threads(port, &th_list, &th_cnt);
	check_result(kr, type, POLY, INSPECT, "task_threads", victim);

	/* Skip thread ports tests if task_threads() fails */
	if (kr != KERN_SUCCESS) {
		return;
	}

	/************ THREAD_GET_SPECIAL_PORT ************/
	mach_port_t special = MACH_PORT_NULL;

	switch (type) {
	case FULL:
		kr = thread_get_special_port(th_list[0], THREAD_KERNEL_PORT, &special);
		break;
	case READ:
		kr = thread_get_special_port(th_list[0], THREAD_READ_PORT, &special);
		break;
	case INSPECT:
		kr = thread_get_special_port(th_list[0], THREAD_INSPECT_PORT, &special);
		break;
	default:
		break;
	}

	T_QUIET; T_EXPECT_EQ(special, th_list[0], "thread_get_special_port should match task_threads");

	kr = mach_port_deallocate(mach_task_self(), special);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	for (unsigned int i = 0; i < th_cnt; i++) {
		test_thread_port(th_list[i], type, victim); /* polymorphic */
		kr = mach_port_deallocate(mach_task_self(), th_list[i]);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}
}

static void
test_get_child_port(int with_sleep)
{
	pid_t child_pid;
	kern_return_t kr;
	mach_port_name_t tr, ti, tp, tn;

	child_pid = fork();

	if (child_pid < 0) {
		T_FAIL("fork failed in test_get_child_port.");
	}

	if (child_pid == 0) {
		while (1) {
			sleep(10);
		}
	}

	kr = task_for_pid(mach_task_self(), child_pid, &tp);
	if (with_sleep) {
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_for_pid for child %u", child_pid);
	} else if (kr != 0) {
		g_tfpFail++;
	}

	kr = task_read_for_pid(mach_task_self(), child_pid, &tr);
	if (with_sleep) {
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_read_for_pid for child %u", child_pid);
	} else if (kr != 0) {
		g_trfpFail++;
	}

	kr = task_inspect_for_pid(mach_task_self(), child_pid, &ti);
	if (with_sleep) {
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_inspect_for_pid for child %u", child_pid);
	} else if (kr != 0) {
		g_tifpFail++;
	}

	kr = task_name_for_pid(mach_task_self(), child_pid, &tn);
	if (with_sleep) {
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "task_name_for_pid for child %u", child_pid);
	} else if (kr != 0) {
		g_tnfpFail++;
	}

	kr = mach_port_deallocate(mach_task_self(), tp);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), tr);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), ti);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), tn);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	kill(child_pid, SIGKILL);
	int status;
	wait(&status);
}

static void
test_child_exec()
{
	pid_t child_pid;
	kern_return_t kr;
	mach_port_name_t tr2, ti2, tp2, tn2;

	child_pid = fork();

	if (child_pid < 0) {
		T_FAIL("fork failed in test_child_exec.");
	}

	if (child_pid == 0) {
		execve("/bin/bash", NULL, NULL);
	}

	sleep(10);

	kr = task_name_for_pid(mach_task_self(), child_pid, &tn2);
	test_task_port(tn2, NAME);

	kr = task_for_pid(mach_task_self(), child_pid, &tp2);
	test_task_port(tp2, FULL);

	kr = task_read_for_pid(mach_task_self(), child_pid, &tr2);
	test_task_port(tr2, READ);

	kr = task_inspect_for_pid(mach_task_self(), child_pid, &ti2);
	test_task_port(ti2, INSPECT);

	kr = mach_port_deallocate(mach_task_self(), tp2);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), tr2);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), ti2);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	kr = mach_port_deallocate(mach_task_self(), tn2);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	kill(child_pid, SIGKILL);
	int status;
	wait(&status);
}

static void *
thread_run()
{
	pthread_mutex_lock(&g_lock);
	pthread_mutex_unlock(&g_lock);

	pthread_exit(NULL);

	return NULL;
}

#ifdef T_NOCODESIGN
#define TEST_NAME inspect_read_port_nocodesign
#else
#define TEST_NAME inspect_read_port
#endif

T_DECL(TEST_NAME, "inspect and read port test", T_META_ASROOT(true))
{
	kern_return_t kr;
	pid_t pid = 0;
	mach_port_t port = MACH_PORT_NULL;

	kr = pid_for_task(mach_task_self(), &pid);
	T_EXPECT_MACH_SUCCESS(kr, "pid_for_task: My Pid = %d", pid);

#ifdef T_NOCODESIGN
	T_LOG("Running as non-platform binary...\n");
#else
	T_LOG("Running as platform binary...\n");
#endif

	kr = task_for_pid(mach_task_self(), pid, &port);
	T_EXPECT_EQ(kr, 0, "task_for_pid(mach_task_self..): %u", port);
	T_EXPECT_EQ(port, mach_task_self(), "task_for_pid == mach_task_self");
	test_task_port(port, FULL);

	port = MACH_PORT_NULL;
	kr = task_read_for_pid(mach_task_self(), pid, &port);
	T_EXPECT_EQ(kr, 0, "task_read_for_pid(mach_task_self..): read port = %u", port);
	test_task_port(port, READ);
	kr = mach_port_deallocate(mach_task_self(), port);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	port = MACH_PORT_NULL;
	kr = task_inspect_for_pid(mach_task_self(), pid, &port);
	T_EXPECT_EQ(kr, 0, "task_inspect_for_pid(mach_task_self..): inspect port = %u", port);
	test_task_port(port, INSPECT);
	kr = mach_port_deallocate(mach_task_self(), port);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	port = MACH_PORT_NULL;
	kr = task_name_for_pid(mach_task_self(), pid, &port);
	T_EXPECT_EQ(kr, 0, "task_name_for_pid(mach_task_self..): name port = %u", port);
	test_task_port(port, NAME);
	kr = mach_port_deallocate(mach_task_self(), port);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");

	port = MACH_PORT_NULL;
	kr = task_read_for_pid(mach_task_self(), 0, &port);
	T_EXPECT_NE(kr, 0, "task_read_for_pid for kernel should fail");

	/* task_read_for_pid loop, check for leaks */
	for (int i = 0; i < 0x1000; i++) {
		kr = task_read_for_pid(mach_task_self(), pid, &port);
		test_task_port(port, READ);
		kr = mach_port_deallocate(mach_task_self(), port);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	/* task_inspect_for_pid loop, check for leaks */
	for (int i = 0; i < 0x1000; i++) {
		kr = task_inspect_for_pid(mach_task_self(), pid, &port);
		test_task_port(port, INSPECT);
		kr = mach_port_deallocate(mach_task_self(), port);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	/* fork-exec a child process */
	test_child_exec();

	/* fork, get full/read/inspect/name port for the child then kill it */
	for (int i = 0; i < 10; i++) {
		test_get_child_port(TRUE);
	}

	T_LOG("tfp fail: %d, trfp fail: %d, tifp fail: %d, tnfp fail: %d, TOTAL: 10\n",
	    g_tfpFail, g_trfpFail, g_tifpFail, g_tnfpFail);


	/* task thread loop, check for leaks */
	thread_array_t th_list;
	mach_msg_type_number_t th_cnt;
	pthread_t thread;

	pthread_mutex_init(&g_lock, NULL);
	pthread_mutex_lock(&g_lock);

	for (unsigned i = 0; i < 0x100; i++) {
		pthread_create(&thread, NULL, thread_run, NULL);
	}

	for (unsigned i = 0; i < 0x1000; i++) {
		kr = task_threads(mach_task_self(), &th_list, &th_cnt);
		T_QUIET; T_ASSERT_EQ(th_cnt, 0x101, "257 threads");

		for (unsigned j = 0; j < th_cnt; j++) {
			kr = mach_port_deallocate(mach_task_self(), th_list[j]);
			T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
		}
	}
	pthread_mutex_unlock(&g_lock);

	/* processor_set_tasks_with_flavor */

	processor_set_name_array_t psets;
	processor_set_t        pset;
	task_array_t tasks;
	mach_msg_type_number_t pcnt, tcnt;
	mach_port_t host = mach_host_self();

	kr = host_processor_sets(host, &psets, &pcnt);
	kr = host_processor_set_priv(host, psets[0], &pset);

	kr = processor_set_tasks_with_flavor(pset, TASK_FLAVOR_CONTROL, &tasks, &tcnt);
	T_EXPECT_EQ(kr, 0, "processor_set_tasks_with_flavor: TASK_FLAVOR_CONTROL should succeed");
	for (unsigned int i = 0; i < tcnt; i++) {
		test_task_port(tasks[i], FULL);
		kr = mach_port_deallocate(mach_task_self(), tasks[i]);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	kr = processor_set_tasks_with_flavor(pset, TASK_FLAVOR_READ, &tasks, &tcnt);
	T_EXPECT_EQ(kr, 0, "processor_set_tasks_with_flavor: TASK_FLAVOR_READ should succeed");
	for (unsigned int i = 0; i < tcnt; i++) {
		test_task_port(tasks[i], READ);
		kr = mach_port_deallocate(mach_task_self(), tasks[i]);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	kr = processor_set_tasks_with_flavor(pset, TASK_FLAVOR_INSPECT, &tasks, &tcnt);
	T_EXPECT_EQ(kr, 0, "processor_set_tasks_with_flavor: TASK_FLAVOR_INSPECT should succeed");
	for (unsigned int i = 0; i < tcnt; i++) {
		test_task_port(tasks[i], INSPECT);
		kr = mach_port_deallocate(mach_task_self(), tasks[i]);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	kr = processor_set_tasks_with_flavor(pset, TASK_FLAVOR_NAME, &tasks, &tcnt);
	T_EXPECT_EQ(kr, 0, "processor_set_tasks_with_flavor: TASK_FLAVOR_NAME should succeed");
	for (unsigned int i = 0; i < tcnt; i++) {
		test_task_port(tasks[i], NAME);
		kr = mach_port_deallocate(mach_task_self(), tasks[i]);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	// Cleanup
	for (unsigned int i = 0; i < pcnt; i++) {
		kr = mach_port_deallocate(mach_task_self(), psets[i]);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
	}

	kr = mach_port_deallocate(mach_task_self(), pset);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_port_deallocate");
}
