#include <mach/mach.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>

/*
 * DO NOT run this test file by itself.
 * This test is meant to be invoked by control_port_options darwintest.
 *
 * If hard enforcement for pinned control port is on, pinned_test_main_thread_mod_ref-5 are
 * expected to generate fatal EXC_GUARD.
 *
 * If hard enforcement for immovable control port is on, immovable_test_move_send_task_self-13 are
 * expected to generate fatal EXC_GUARD.
 *
 * The type of exception raised (if any) is checked on control_port_options side.
 */
#define MAX_TEST_NUM 13

static int
attempt_send_immovable_port(mach_port_name_t port, mach_msg_type_name_t disp)
{
	mach_port_t server;
	kern_return_t kr;
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server);
	assert(kr == 0);

	kr = mach_port_insert_right(mach_task_self(), server, server, MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == 0);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	msg.header.msgh_remote_port = server;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.header.msgh_size = sizeof msg;

	msg.body.msgh_descriptor_count = 1;

	msg.desc.name = port;
	msg.desc.disposition = disp;
	msg.desc.type = MACH_MSG_PORT_DESCRIPTOR;

	return mach_msg_send(&msg.header);
}

static void
pinned_test_main_thread_mod_ref()
{
	printf("[Crasher]: Mod refs main thread's self port to 0\n");
	mach_port_t thread_self = mach_thread_self();
	kern_return_t kr = mach_port_mod_refs(mach_task_self(), thread_self, MACH_PORT_RIGHT_SEND, -2);

	printf("[Crasher pinned_test_main_thread_mod_ref] mach_port_mod_refs returned %s \n.", mach_error_string(kr));
}

static void*
pthread_run()
{
	printf("[Crasher]: Deallocate pthread_self\n");
	mach_port_t th_self = pthread_mach_thread_np(pthread_self());
	kern_return_t kr = mach_port_deallocate(mach_task_self(), th_self);

	printf("[Crasher pinned_test_pthread_dealloc] mach_port_deallocate returned %s \n.", mach_error_string(kr));
	return NULL;
}

static void
pinned_test_pthread_dealloc()
{
	printf("[Crasher]: Create a pthread and deallocate its self port\n");
	pthread_t thread;
	int ret = pthread_create(&thread, NULL, pthread_run, NULL);
	assert(ret == 0);
	ret = pthread_join(thread, NULL);
	assert(ret == 0);
}

static void
pinned_test_task_self_dealloc()
{
	printf("[Crasher]: Deallocate mach_task_self twice\n");
	mach_port_t task_self = mach_task_self();
	kern_return_t kr = mach_port_deallocate(task_self, task_self);
	assert(kr == 0);
	kr = mach_port_deallocate(task_self, task_self);

	printf("[Crasher pinned_test_task_self_dealloc] mach_port_deallocate returned %s \n.", mach_error_string(kr));
}

static void
pinned_test_task_self_mod_ref()
{
	printf("[Crasher]: Mod refs mach_task_self() to 0\n");
	kern_return_t kr = mach_port_mod_refs(mach_task_self(), mach_task_self(), MACH_PORT_RIGHT_SEND, -2);

	printf("[Crasher pinned_test_task_self_mod_ref] mach_port_mod_refs returned %s \n.", mach_error_string(kr));
}

static void
pinned_test_task_threads_mod_ref()
{
	printf("[Crasher]: task_threads should return pinned thread ports. Mod refs them to 0\n");
	thread_array_t th_list;
	mach_msg_type_number_t th_cnt;
	kern_return_t kr;
	mach_port_t th_kp = mach_thread_self();
	mach_port_deallocate(mach_task_self(), th_kp);

	kr = task_threads(mach_task_self(), &th_list, &th_cnt);
	mach_port_deallocate(mach_task_self(), th_list[0]);

	kr = mach_port_mod_refs(mach_task_self(), th_list[0], MACH_PORT_RIGHT_SEND, -1);

	printf("[Crasher pinned_test_task_threads_mod_ref] mach_port_mod_refs returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_task_self()
{
	kern_return_t kr;
	printf("[Crasher]: Move send mach_task_self_\n");
	kr = attempt_send_immovable_port(mach_task_self(), MACH_MSG_TYPE_MOVE_SEND);

	printf("[Crasher immovable_test_move_send_task_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_copy_send_task_self()
{
	kern_return_t kr;
	printf("[Crasher]: Copy send mach_task_self_\n");
	kr = attempt_send_immovable_port(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);

	printf("[Crasher immovable_test_copy_send_task_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_thread_self()
{
	kern_return_t kr;
	printf("[Crasher]: Move send main thread's self port\n");
	kr = attempt_send_immovable_port(mach_thread_self(), MACH_MSG_TYPE_MOVE_SEND);

	printf("[Crasher immovable_test_move_send_thread_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_copy_send_thread_self()
{
	kern_return_t kr;
	mach_port_t port;
	printf("[Crasher]: Copy send main thread's self port\n");
	port = mach_thread_self();
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_COPY_SEND);
	printf("[Crasher immovable_test_copy_send_thread_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), port);
}

static void
immovable_test_copy_send_task_read()
{
	kern_return_t kr;
	mach_port_t port;
	printf("[Crasher]: Copy send task read port\n");
	kr = task_get_special_port(mach_task_self(), TASK_READ_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_COPY_SEND);
	printf("[Crasher immovable_test_copy_send_task_read] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), port);
}

static void
immovable_test_copy_send_task_inspect()
{
	kern_return_t kr;
	mach_port_t port;
	printf("[Crasher]: Move send task inspect port\n");
	kr = task_get_special_port(mach_task_self(), TASK_INSPECT_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_MOVE_SEND);
	printf("[Crasher immovable_test_copy_send_task_inspect] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_thread_inspect()
{
	kern_return_t kr;
	mach_port_t port;
	mach_port_t th_port = mach_thread_self();

	printf("[Crasher]: Move send thread inspect port\n");
	kr = thread_get_special_port(th_port, THREAD_INSPECT_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_MOVE_SEND);
	printf("[Crasher immovable_test_move_send_thread_inspect] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), th_port);
}

static void
immovable_test_copy_send_thread_read()
{
	kern_return_t kr;
	mach_port_t port;
	mach_port_t th_port = mach_thread_self();

	printf("[Crasher]: Copy send thread read port\n");
	kr = thread_get_special_port(th_port, THREAD_READ_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_COPY_SEND);
	printf("[Crasher immovable_test_copy_send_thread_read] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), port);
	mach_port_deallocate(mach_task_self(), th_port);
}

int
main(int argc, char *argv[])
{
	void (*tests[MAX_TEST_NUM])(void) = {
		pinned_test_main_thread_mod_ref,
		pinned_test_pthread_dealloc,
		pinned_test_task_self_dealloc,
		pinned_test_task_self_mod_ref,
		pinned_test_task_threads_mod_ref,

		immovable_test_move_send_task_self,
		immovable_test_copy_send_task_self,
		immovable_test_move_send_thread_self,
		immovable_test_copy_send_thread_self,
		immovable_test_copy_send_task_read,
		immovable_test_copy_send_task_inspect,
		immovable_test_move_send_thread_inspect,
		immovable_test_copy_send_thread_read,
	};
	printf("[Crasher]: My Pid: %d\n", getpid());

	if (argc < 2) {
		printf("[Crasher]: Specify a test to run.");
		exit(-1);
	}

	int test_num = atoi(argv[1]);

	if (test_num >= 0 && test_num < MAX_TEST_NUM) {
		(*tests[test_num])();
	} else {
		printf("[Crasher]: Invalid test num. Exiting...\n");
		exit(-1);
	}

	exit(0);
}
