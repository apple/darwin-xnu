/*
 * prioritize process launch: Tests prioritized process launch across posix spawn and exec.
 */

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
#include <stdio.h>
#include <unistd.h>
#include <crt_externs.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <libkern/OSAtomic.h>
#include <sys/wait.h>
#include <spawn.h>
#include <spawn_private.h>
#include <string.h>


mach_port_t
receive(
	mach_port_t rcv_port,
	mach_port_t notify_port);

static int
get_pri(thread_t thread_port)
{
	kern_return_t kr;

	thread_extended_info_data_t extended_info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
	    (thread_info_t)&extended_info, &count);

	if (kr != KERN_SUCCESS) {
		printf("thread info failed to get current priority of the thread\n");
	}
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
send(
	mach_port_t send_port,
	mach_port_t reply_port,
	mach_port_t msg_port,
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

	if (ret != KERN_SUCCESS) {
		printf("mach_msg_send failed with error %d\n", ret);
	}
}

mach_port_t
receive(
	mach_port_t rcv_port,
	mach_port_t notify_port)
{
	kern_return_t ret = 0;
	mach_port_t service_port;

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

	printf("Client: Starting sync receive\n");

	ret = mach_msg(&(rcv_msg.header),
	    MACH_RCV_MSG | MACH_RCV_LARGE |
	    (notify_port ? MACH_RCV_SYNC_WAIT : 0),
	    0,
	    rcv_msg.header.msgh_size,
	    rcv_port,
	    0,
	    notify_port);

	printf("mach msg rcv returned %d\n", ret);


	if (rcv_msg.body.msgh_descriptor_count != 1) {
		if (notify_port) {
			printf("Did not receive a service port in mach msg %d\n", rcv_msg.body.msgh_descriptor_count);
		}
		return MACH_PORT_NULL;
	}

	service_port = rcv_msg.port_descriptor.name;
	return service_port;
}

int
main(int argc __attribute__((unused)), char *argv[])
{
	int priority;
	set_thread_name(__FUNCTION__);

	/* Check for priority */
	priority = get_pri(mach_thread_self());
	printf("The priority of child is %d\n", priority);

	if (strcmp(argv[1], "EXIT") == 0) {
		printf("Helper process exiting\n");
		exit(priority);
	} else if (strcmp(argv[1], "EXEC") == 0) {
		int ret;

		printf("Helper process execing\n");
		/* exec the same binary with EXIT arg */
		char *binary = "prioritize_process_launch_helper";
		char *new_argv[] = {binary, "EXIT", NULL};
		ret = execve(binary, new_argv, NULL);
		exit(ret);
	} else if (strcmp(argv[1], "SETEXEC") == 0) {
		int ret;
		int child_pid;
		posix_spawnattr_t attr;

		ret = posix_spawnattr_init(&attr);
		if (ret != 0) {
			printf("posix_spawnattr_init failed \n");
			exit(ret);
		}
		ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
		if (ret != 0) {
			printf("posix_spawnattr_setflags failed \n");
			exit(ret);
		}

		printf("Helper process doing posix_spawn set_exec\n");
		/* set exec the same binary with EXIT arg */
		char *binary = "prioritize_process_launch_helper";
		char *new_argv[] = {binary, "EXIT", NULL};

		ret = posix_spawn(&child_pid, binary, NULL, &attr, new_argv, NULL);
		exit(ret);
	} else if (strcmp(argv[1], "SETEXEC_PORTS") == 0) {
		int ret;
		int child_pid;
		posix_spawnattr_t attr;
		mach_port_t port;

		kern_return_t kr =  mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
		if (kr != KERN_SUCCESS) {
			printf("mach_port_allocate failed with error %d\n", kr);
			exit(kr);
		}

		kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
		if (kr != KERN_SUCCESS) {
			printf("mach_port_insert_right failed with error %d\n", kr);
			exit(kr);
		}

		ret = posix_spawnattr_init(&attr);
		if (ret != 0) {
			printf("posix_spawnattr_init failed \n");
			exit(ret);
		}

		ret = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
		if (ret != 0) {
			printf("posix_spawnattr_setflags failed \n");
			exit(ret);
		}

		ret = posix_spawnattr_set_importancewatch_port_np(&attr, 1, &port);
		if (ret != 0) {
			printf("posix_spawnattr_set_importance_port_np failed \n");
			exit(ret);
		}

		printf("Helper process doing posix_spawn set_exec\n");
		/* set exec the same binary with EXIT arg */
		char *binary = "prioritize_process_launch_helper";
		char *new_argv[] = {binary, "EXIT", NULL};

		ret = posix_spawn(&child_pid, binary, NULL, &attr, new_argv, NULL);
		printf("spawned failed with error %d\n", ret);
		exit(ret);
	} else if (strcmp(argv[1], "WAIT") == 0) {
		do {
			sleep(1);
			priority = get_pri(mach_thread_self());
		} while (priority == 47);
		exit(priority);
	} else if (strcmp(argv[1], "MULTIWAIT") == 0) {
		do {
			sleep(1);
			priority = get_pri(mach_thread_self());
		} while (priority == 47);
		printf("The priority came down to %d\n", priority);
		do {
			sleep(1);
			priority = get_pri(mach_thread_self());
		} while (priority == 37);
		printf("The priority came down to %d\n", priority);
		exit(priority);
	} else if (strcmp(argv[1], "MSGSYNC") == 0) {
		int ret_val = 31;
		mach_port_array_t port_array = NULL;
		unsigned int portCnt = 0;
		mach_port_t send_port;
		mach_port_t special_reply_port;
		mach_port_t service_port;
		kern_return_t kr;

		priority = get_pri(mach_thread_self());
		printf("The priority of spawned binary is  to %d\n", priority);
		if (priority != 47) {
			ret_val = 0;
		}

		/* Get the stashed send right using mach_ports_lookup */
		kr = mach_ports_lookup(mach_task_self(), &port_array, &portCnt);
		if (kr != KERN_SUCCESS) {
			printf("mach_ports_lookup failed with return value %d and port count %d\n", kr, portCnt);
			exit(0);
		}

		send_port = port_array[0];
		special_reply_port = thread_get_special_reply_port();
		if (!MACH_PORT_VALID(special_reply_port)) {
			printf("Failed to special reply port for thread\n");
			exit(0);
		}

		/* Perform a Sync bootstrap checkin */
		send(send_port, special_reply_port, MACH_PORT_NULL, MACH_SEND_SYNC_BOOTSTRAP_CHECKIN, MACH_MSG_TYPE_COPY_SEND);
		sleep(2);

		/* Make sure we are still boosted */
		priority = get_pri(mach_thread_self());
		printf("The priority of spawned binary is  to %d\n", priority);
		if (priority != 47) {
			ret_val = 0;
		}

		/* Receive the service port */
		service_port = receive(special_reply_port, send_port);

		/* Make sure we are still boosted */
		priority = get_pri(mach_thread_self());
		printf("The priority of spawned binary is  to %d\n", priority);
		if (priority != 47) {
			ret_val = 0;
		}

		/* Try to receive on service port */
		receive(service_port, MACH_PORT_NULL);

		/* Make sure we are no longer boosted */
		priority = get_pri(mach_thread_self());
		printf("The priority of spawned binary is  to %d\n", priority);
		if (priority != 31) {
			ret_val = 0;
		}
		exit(ret_val);
	}

	exit(0);
}
