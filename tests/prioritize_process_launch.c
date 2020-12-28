/*
 * prioritize process launch: Tests prioritized process launch across posix spawn and exec.
 */

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_multiprocess.h>

#include <dispatch/dispatch.h>
#include <pthread.h>
#include <launch.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mach_voucher.h>
#include <pthread/workqueue_private.h>
#include <voucher/ipc_pthread_priority_types.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>
#include <crt_externs.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <libkern/OSAtomic.h>
#include <sys/wait.h>
#include <spawn.h>
#include <spawn_private.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.prioritize_process_launch"),
    T_META_RUN_CONCURRENTLY(true));

#define HELPER_TIMEOUT_SECS (3000)
#define MACH_RCV_OPTIONS  (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY | \
	            MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_CTX) | \
	            MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0))

static pthread_t
thread_create_at_qos(qos_class_t qos, void * (*function)(void *), void *arg);
static mach_port_t sr_port;


#pragma mark Mach receive

static mach_voucher_t
create_pthpriority_voucher(mach_msg_priority_t qos)
{
	char voucher_buf[sizeof(mach_voucher_attr_recipe_data_t) + sizeof(ipc_pthread_priority_value_t)];

	mach_voucher_t voucher = MACH_PORT_NULL;
	kern_return_t ret;
	ipc_pthread_priority_value_t ipc_pthread_priority_value =
	    (ipc_pthread_priority_value_t)qos;

	mach_voucher_attr_raw_recipe_array_t recipes;
	mach_voucher_attr_raw_recipe_size_t recipe_size = 0;
	mach_voucher_attr_recipe_t recipe =
	    (mach_voucher_attr_recipe_t)&voucher_buf[recipe_size];

	recipe->key = MACH_VOUCHER_ATTR_KEY_PTHPRIORITY;
	recipe->command = MACH_VOUCHER_ATTR_PTHPRIORITY_CREATE;
	recipe->previous_voucher = MACH_VOUCHER_NULL;
	memcpy((char *)&recipe->content[0], &ipc_pthread_priority_value, sizeof(ipc_pthread_priority_value));
	recipe->content_size = sizeof(ipc_pthread_priority_value_t);
	recipe_size += sizeof(mach_voucher_attr_recipe_data_t) + recipe->content_size;

	recipes = (mach_voucher_attr_raw_recipe_array_t)&voucher_buf[0];

	ret = host_create_mach_voucher(mach_host_self(),
	    recipes,
	    recipe_size,
	    &voucher);

	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "client host_create_mach_voucher");
	return voucher;
}

static void
send(
	mach_port_t send_port,
	mach_port_t reply_port,
	mach_port_t msg_port,
	mach_msg_priority_t qos,
	mach_msg_option_t options,
	int send_disposition)
{
	kern_return_t ret = 0;

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	} send_msg = {
		.header = {
			.msgh_remote_port = send_port,
			.msgh_local_port  = reply_port,
			.msgh_bits        = MACH_MSGH_BITS_SET(send_disposition,
	    reply_port ? MACH_MSG_TYPE_MAKE_SEND_ONCE : 0,
	    MACH_MSG_TYPE_MOVE_SEND,
	    MACH_MSGH_BITS_COMPLEX),
			.msgh_id          = 0x100,
			.msgh_size        = sizeof(send_msg),
		},
		.body = {
			.msgh_descriptor_count = 1,
		},
		.port_descriptor = {
			.name        = msg_port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type        = MACH_MSG_PORT_DESCRIPTOR,
		},
	};

	if (options & MACH_SEND_SYNC_USE_THRPRI) {
		send_msg.header.msgh_voucher_port = create_pthpriority_voucher(qos);
	}

	if (msg_port == MACH_PORT_NULL) {
		send_msg.body.msgh_descriptor_count = 0;
	}

	ret = mach_msg(&(send_msg.header),
	    MACH_SEND_MSG |
	    MACH_SEND_TIMEOUT |
	    MACH_SEND_OVERRIDE |
	    ((reply_port ? MACH_SEND_SYNC_OVERRIDE : 0) | options),
	    send_msg.header.msgh_size,
	    0,
	    MACH_PORT_NULL,
	    10000,
	    0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "client mach_msg");
}

static void
receive(
	mach_port_t rcv_port,
	mach_port_t notify_port)
{
	kern_return_t ret = 0;

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
		mach_msg_trailer_t trailer;
	} rcv_msg = {
		.header =
		{
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = rcv_port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	T_LOG("Client: Starting sync receive\n");

	ret = mach_msg(&(rcv_msg.header),
	    MACH_RCV_MSG |
	    MACH_RCV_SYNC_WAIT,
	    0,
	    rcv_msg.header.msgh_size,
	    rcv_port,
	    0,
	    notify_port);
}

static int
get_pri(thread_t thread_port)
{
	kern_return_t kr;

	thread_extended_info_data_t extended_info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
	    (thread_info_t)&extended_info, &count);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

	return extended_info.pth_curpri;
}

static void
set_thread_name(const char *fn_name)
{
	char name[50] = "";

	thread_t thread_port = pthread_mach_thread_np(pthread_self());

	int pri = get_pri(thread_port);

	snprintf(name, sizeof(name), "%s at pri %2d", fn_name, pri);
	pthread_setname_np(name);
}

static void
thread_wait_to_block(mach_port_t thread_port)
{
	thread_extended_info_data_t extended_info;
	kern_return_t kr;

	while (1) {
		mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
		kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
		    (thread_info_t)&extended_info, &count);

		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

		if (extended_info.pth_run_state == TH_STATE_WAITING) {
			T_LOG("Target thread blocked\n");
			break;
		}
		thread_switch(thread_port, SWITCH_OPTION_DEPRESS, 0);
	}
}

static void *
thread_sync_rcv(void *arg)
{
	mach_port_t port = (mach_port_t)arg;
	mach_port_t special_reply_port;

	set_thread_name(__FUNCTION__);
	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	sr_port = special_reply_port;
	/* Do a sync rcv on special reply port and push on given arg port */
	receive(special_reply_port, port);
	return NULL;
}

static pthread_t
thread_create_at_qos(qos_class_t qos, void * (*function)(void *), void *arg)
{
	qos_class_t qos_thread;
	pthread_t pthread;
	pthread_attr_t attr;
	int ret;

	ret = setpriority(PRIO_DARWIN_ROLE, 0, PRIO_DARWIN_ROLE_UI_FOCAL);
	if (ret != 0) {
		T_LOG("set priority failed\n");
	}

	pthread_attr_init(&attr);
	pthread_attr_set_qos_class_np(&attr, qos, 0);
	pthread_create(&pthread, &attr, function, arg);

	T_LOG("pthread created\n");
	pthread_get_qos_class_np(pthread, &qos_thread, NULL);
	return pthread;
}

static mach_port_t
get_sync_push_port_at_qos(qos_class_t qos)
{
	mach_port_t port;
	kern_return_t kr;
	pthread_t pthread;
	thread_t thread;

	/* Create a rcv right to have a sync ipc push from a thread */
	kr = mach_port_allocate(mach_task_self(),
	    MACH_PORT_RIGHT_RECEIVE,
	    &port);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "sync push port  mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(),
	    port,
	    port,
	    MACH_MSG_TYPE_MAKE_SEND);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "sync push port mach_port_insert_right");

	/* Create a thread at given qos and start a sync push on given port */
	pthread = thread_create_at_qos(qos, thread_sync_rcv, (void *)(uintptr_t)port);
	thread = pthread_mach_thread_np(pthread);
	thread_wait_to_block(thread);

	return port;
}

static mach_port_t
create_port_and_copyin_a_port(mach_port_t port)
{
	mach_port_t new_port;
	kern_return_t kr;

	/* Create a rcv right */
	kr = mach_port_allocate(mach_task_self(),
	    MACH_PORT_RIGHT_RECEIVE,
	    &new_port);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "copyin  mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(),
	    new_port,
	    new_port,
	    MACH_MSG_TYPE_MAKE_SEND);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "copyin mach_port_insert_right");

	send(new_port, MACH_PORT_NULL, port, 0, 0, MACH_MSG_TYPE_COPY_SEND);
	return new_port;
}

static pid_t
posix_spawn_child_with_watch_ports(
	char *binary,
	char *arg,
	mach_port_t *port_array,
	int arrayCnt)
{
	pid_t child_pid = 0;
	char *new_argv[] = { binary, arg, NULL};
	errno_t ret;
	posix_spawnattr_t attr;

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_set_importancewatch_port_np(&attr, arrayCnt, port_array);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_set_importancewatch_port_np");

	ret = posix_spawn(&child_pid, binary, NULL, &attr, new_argv, NULL);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawn");

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "posix_spawnattr_destroy");

	return child_pid;
}

static void
worker_cb(pthread_priority_t __unused priority)
{
	T_FAIL("a worker thread was created");
}

static void
event_cb(void ** __unused events, int * __unused nevents)
{
	T_FAIL("a kevent routine was called instead of workloop");
}

static void
workloop_cb_test_intransit(uint64_t *workloop_id __unused, void **eventslist, int *events)
{
	pid_t pid;
	int stat;
	int priority;
	mach_port_t port;
	struct kevent_qos_s *kev = *eventslist;
	mach_msg_header_t *hdr = (mach_msg_header_t *)kev->ext[0];
	port = hdr->msgh_local_port;

	T_LOG("Workloop handler workloop_cb_test_intransit called. ");
	T_LOG("The total events returned is %d", *events);

	priority = get_pri(mach_thread_self());
	T_EXPECT_EQ(priority, 47, "Priority of servicer is %d", priority);

	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "WAIT", &port, 1);

	/* Make sure our priority has dropped */
	priority = get_pri(mach_thread_self());
	T_EXPECT_EQ(priority, 31, "Priority of servicer is %d", priority);

	sleep(2);

	/*enqueue the port to sever the temp onwer boost */
	create_port_and_copyin_a_port(port);

	waitpid(pid, &stat, 0);

	*events = 0;

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 31, "Temp owner boost did not work correctly with knotes");
	T_END;
}

static void
workloop_cb_test_knote_kill(uint64_t *workloop_id __unused, void **eventslist, int *events)
{
	pid_t pid;
	int stat;
	int priority;
	mach_port_t port;
	struct kevent_qos_s *kev = *eventslist;
	mach_msg_header_t *hdr = (mach_msg_header_t *)kev->ext[0];
	port = hdr->msgh_local_port;

	T_LOG("Workloop handler workloop_cb_test_knote_kill called. ");
	T_LOG("The total events returned is %d", *events);

	priority = get_pri(mach_thread_self());
	T_EXPECT_EQ(priority, 47, "Priority of servicer is %d", priority);

	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "EXIT", &port, 1);

	sleep(2);

	/* Make sure our priority is boosted again */
	priority = get_pri(mach_thread_self());
	T_EXPECT_EQ(priority, 47, "Priority of servicer is %d", priority);

	waitpid(pid, &stat, 0);

	*events = 0;

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 47, "Temp owner boost did not work correctly with knotes");
	T_END;
}

static void
workloop_cb_test_sync_bootstrap(uint64_t *workloop_id __unused, void **eventslist, int *events)
{
	static pid_t pid = 0;
	int stat;
	int priority;
	static mach_port_t port = MACH_PORT_NULL;
	struct kevent_qos_s *kev = *eventslist;
	mach_msg_header_t *hdr = (mach_msg_header_t *)kev->ext[0];

	T_LOG("Workloop handler workloop_cb_test_knote_kill called. ");
	T_LOG("The total events returned is %d", *events);

	/* Check if called for peek */
	if (hdr == NULL) {
		priority = get_pri(mach_thread_self());
		T_EXPECT_EQ(priority, 47, "Priority of servicer is %d", priority);

		port = (mach_port_t)kev->ident;
		pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "MSGSYNC", &port, 1);
	} else {
		/* Wait till the priority of servicer is 47 */
		T_LOG("Waiting for the servicer to be boosted");
		do {
			sleep(1);
			priority = get_pri(mach_thread_self());
		} while (priority != 47);

		T_EXPECT_EQ(priority, 47, "Priority of servicer is %d", priority);

		/* Get the reply port and send the receive right in it */
		mach_port_t reply_port = hdr->msgh_remote_port;
		T_LOG("The rcv right to send is %d", port);
		send(reply_port, MACH_PORT_NULL, port, 0, 0, MACH_MSG_TYPE_MOVE_SEND_ONCE);

		waitpid(pid, &stat, 0);

		/* The handler priority should not be boosted anymore */
		priority = get_pri(mach_thread_self());
		T_EXPECT_EQ(priority, 31, "Priority of servicer is %d", priority);

		T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
		T_EXPECT_EQ(WEXITSTATUS(stat), 31, "Temp owner boost did not work correctly with knotes");
		T_END;
	}
	*events = 0;
}

static void
register_workloop_for_port(
	mach_port_t port,
	pthread_workqueue_function_workloop_t func,
	unsigned int options)
{
	int r;

	/* register workloop handler with pthread */
	if (func != NULL) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)func, 0, 0), NULL);
	}

	/* attach port to workloop */
	struct kevent_qos_s kev[] = {{
					     .ident = port,
					     .filter = EVFILT_MACHPORT,
					     .flags = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
					     .fflags = options,
					     .data = 1,
					     .qos = (int32_t)_pthread_qos_class_encode(QOS_CLASS_DEFAULT, 0, 0)
				     }};

	struct kevent_qos_s kev_err[] = {{ 0 }};

	/* Setup workloop for mach msg rcv */
	r = kevent_id(25, kev, 1, kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "kevent_id");
	T_QUIET; T_ASSERT_EQ(r, 0, "no errors returned from kevent_id");
}

/*
 * Test 1: Test turnstile boosting for temp owner ports for posix_spawn.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port.
 */
T_DECL(posix_spawn_basic_priority, "Basic posix spawn temp owner priority test", T_META_ASROOT(YES))
{
	mach_port_t port;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "EXIT", &port, 1);

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 47, "spawn did not properly boost main thread");
	T_END;
}

/*
 * Test 2: Test turnstile boosting for temp owner ports for posix_spawn and exec.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port. The spawned binary will exec
 * and verify that it still has the push.
 */
T_DECL(posix_spawn_exec_basic_priority, "Basic posix spawn/exec temp owner priority test", T_META_ASROOT(YES))
{
	mach_port_t port;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "EXEC", &port, 1);

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 47, "spawn/exec did not properly boost main thread");
	T_END;
}

/*
 * Test 3: Test turnstile boosting for temp owner ports for posix_spawn and set exec.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port. The spawned binary will
 * posix_spawn set exec and verify that it still has the push.
 */
T_DECL(posix_spawn_set_exec_basic_priority, "Basic posix spawn set exec temp owner priority test", T_META_ASROOT(YES))
{
	mach_port_t port;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "SETEXEC", &port, 1);

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 47, "spawn set exec did not properly boost main thread");
	T_END;
}

/*
 * Test 4: Test turnstile boosting for temp owner ports for posix_spawn and set exec.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port. The spawned binary already
 * having the temp owner push will try to do set exec with watchports which should fail.
 */
T_DECL(posix_spawn_set_exec_with_more_ports, "posix spawn set exec with more watch ports", T_META_ASROOT(YES))
{
	mach_port_t port;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "SETEXEC_PORTS", &port, 1);

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), EINVAL, "spawn set exec did not error out when watchports were passed to already boosted process");
	T_END;
}

/*
 * Test 5: Test turnstile boosting for temp owner ports for multiple posix_spawns.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port, then
 * pass the same port as a watchport to another posix_spawn and verify that the boost was
 * transferred to the new process.
 */
T_DECL(posix_spawn_multiple, "multiple posix_spawn with same watchport", T_META_ASROOT(YES))
{
	mach_port_t port;
	pid_t pid1, pid2;
	int stat1, stat2;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid1 = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "WAIT", &port, 1);

	/* Let the child 1 execute a little, the sleep here is optional */
	sleep(2);

	pid2 = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "EXIT", &port, 1);

	waitpid(pid2, &stat2, 0);
	waitpid(pid1, &stat1, 0);

	T_QUIET; T_LOG("The return stat for child 1 is is %d", WEXITSTATUS(stat1));
	T_QUIET; T_LOG("The return stat for child 2 is is %d", WEXITSTATUS(stat2));
	T_EXPECT_EQ(WEXITSTATUS(stat2), 47, "spawn of multiple processes with same watchport did not transfer the boost correctly");
	T_EXPECT_EQ(WEXITSTATUS(stat1), 31, "spawn of multiple processes with same watchport did not transfer the boost correctly");
	T_END;
}

/*
 * Test 6: Test turnstile boosting for temp owner ports for posix_spawn for dead port.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port. Destroy the port and verify
 * the temp owner push has gone away.
 */
T_DECL(posix_spawn_dead_reply_port, "posix spawn with reply port destory", T_META_ASROOT(YES))
{
	mach_port_t port;
	kern_return_t kr;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "WAIT", &port, 1);

	/* Let the child execute a little, the sleep here is optional */
	sleep(2);

	/* Destory the special reply port */
	kr = mach_port_mod_refs(mach_task_self(), sr_port, MACH_PORT_RIGHT_RECEIVE, -1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "posix_spaw_dead_port  mach_port_mod_refs");

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 31, "Temp owner boost was not removed on port death");
	T_END;
}

/*
 * Test 7: Test turnstile boosting for temp owner ports for posix_spawn for dead port.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port. Destroy the port and verify
 * the temp owner push has gone.
 */
T_DECL(posix_spawn_dead_port, "posix spawn with port destory", T_META_ASROOT(YES))
{
	mach_port_t port;
	kern_return_t kr;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "WAIT", &port, 1);

	/* Destory the port */
	kr = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "posix_spaw_dead_port  mach_port_mod_refs");

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 31, "Temp owner boost was not removed on port death");
	T_END;
}

/*
 * Test 8: Test turnstile boosting for temp owner ports for posix_spawn when port is copied in.
 *
 * Create a port with sync IPC push and then pass the port to posix_spawn as a watch port and
 * test that spawned binary has the temp owner push of the port. Copyin the port and verify
 * the temp owner push has gone.
 */
T_DECL(posix_spawn_copyin_port, "posix spawn with copyin port", T_META_ASROOT(YES))
{
	mach_port_t port;
	pid_t pid;
	int stat;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "WAIT", &port, 1);

	/* Let the child execute a little, the sleep here is optional */
	sleep(2);

	/* Copyin the port in another port */
	create_port_and_copyin_a_port(port);

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 31, "Temp owner boost was not removed on port copyin");
	T_END;
}

/*
 * Test 9: Test turnstile boosting for temp owner ports for posix_spawn with multiple ports.
 *
 * Create multiple ports with sync IPC push and then pass the port to posix_spawn as watch ports and
 * test that spawned binary has the temp owner push of the ports. Copyin ports one by one and verify
 * the push has gone.
 */
T_DECL(posix_spawn_multiple_port, "posix spawn with multiple ports", T_META_ASROOT(YES))
{
	mach_port_t port[2];
	pid_t pid;
	int stat;

	port[0] = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);
	port[1] = get_sync_push_port_at_qos(QOS_CLASS_USER_INITIATED);
	pid = posix_spawn_child_with_watch_ports("prioritize_process_launch_helper", "MULTIWAIT", port, 2);

	/* Let the child execute a little, the sleep here is optional */
	sleep(2);

	/* Copyin the port in another port */
	create_port_and_copyin_a_port(port[0]);

	/* Let the child execute a little, the sleep here is optional */
	sleep(2);

	/* Copyin the port in another port */
	create_port_and_copyin_a_port(port[1]);

	waitpid(pid, &stat, 0);

	T_QUIET; T_LOG("The return stat is %d", WEXITSTATUS(stat));
	T_EXPECT_EQ(WEXITSTATUS(stat), 31, "Temp owner boost did not work correctly with multiple ports");
	T_END;
}

/*
 * Test 10: Test turnstile boosting for temp owner ports for posix_spawn when port attached to a knote.
 *
 * Create a port with sync IPC push attach a workloop knote to it, send a message on the port, then in the
 * servicer pass the port to posix_spawn as a watch port and test that spawned binary has the temp owner
 * push of the port and the servicer looses the boost.
 */
T_DECL(posix_spawn_knote, "posix spawn with temp owner port attached to knote", T_META_ASROOT(YES))
{
	mach_port_t port;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);

	/* attach port to a workloop */
	register_workloop_for_port(port, workloop_cb_test_intransit, MACH_RCV_OPTIONS);

	/* send a message on port to activate workloop handler */
	send(port, MACH_PORT_NULL, MACH_PORT_NULL, QOS_CLASS_DEFAULT, 0, MACH_MSG_TYPE_COPY_SEND);
	sigsuspend(0);
}

/*
 * Test 11: Test turnstile boosting for temp owner ports for posix_spawn when port attached to a knote.
 *
 * Create a port with sync IPC push attach a workloop knote to it, send a message on the port, then in the
 * servicer pass the port to posix_spawn as a watch port and test that spawned binary has the temp owner
 * push of the port and the servicer looses the boost, verify that once the spawned binary dies, the servicer
 * gets the push.
 */
T_DECL(posix_spawn_knote_ret, "posix spawn with temp owner port attached to knote with spawned binary dead", T_META_ASROOT(YES))
{
	mach_port_t port;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);

	register_workloop_for_port(port, workloop_cb_test_knote_kill, MACH_RCV_OPTIONS);

	/* send a message on port to activate workloop handler */
	send(port, MACH_PORT_NULL, MACH_PORT_NULL, QOS_CLASS_DEFAULT, 0, MACH_MSG_TYPE_COPY_SEND);
	sigsuspend(0);
}

/*
 * Test 12: Test turnstile boosting for temp owner ports and mach msg option for sync bootstrap_checkin.
 *
 * Create a port with sync IPC push attach a workloop knote to it, send a message on the port, then in the
 * servicer pass the port to posix_spawn as a watch port and test that spawned binary has the temp owner
 * push of the port and the servicer looses the boost, the spawn binary then does a sync bootstrap_checkin
 * with test binary to get the receive right and verify that is still has the boost.
 */
T_DECL(mach_msg_sync_boostrap_checkin, "test mach msg option for sync bootstrap_checkin", T_META_ASROOT(YES))
{
	mach_port_t port;
	mach_port_t sync_port;
	kern_return_t kr;

	port = get_sync_push_port_at_qos(QOS_CLASS_USER_INTERACTIVE);

	register_workloop_for_port(port, workloop_cb_test_sync_bootstrap, MACH_RCV_SYNC_PEEK);

	/* Create a mach port for spawned binary to do bootstrap checkin */
	kr = mach_port_allocate(mach_task_self(),
	    MACH_PORT_RIGHT_RECEIVE,
	    &sync_port);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg_sync_boostrap_checkin mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(),
	    sync_port,
	    sync_port,
	    MACH_MSG_TYPE_MAKE_SEND);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg_sync_boostrap_checkin mach_port_insert_right");

	kr = mach_port_mod_refs(mach_task_self(), sync_port, MACH_PORT_RIGHT_SEND, 1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg_sync_boostrap_checkin mach_port_mod_refs");

	register_workloop_for_port(sync_port, NULL, MACH_RCV_OPTIONS);

	/* Stash the port in task to make sure child also gets it */
	kr = mach_ports_register(mach_task_self(), &sync_port, 1);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_msg_sync_boostrap_checkin mach_ports_register");

	/* send a message on port to activate workloop handler */
	send(port, MACH_PORT_NULL, MACH_PORT_NULL, QOS_CLASS_DEFAULT, 0, MACH_MSG_TYPE_COPY_SEND);
	sigsuspend(0);
}
