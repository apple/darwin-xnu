
/*
 * File: sprace_test_11891562.c
 * Test Description: The test ensures that there are no race conditions when multiple threads
 * attempt to send messages to a mach port with a subset of threads waiting for a send possible 
 * notification.
 * Radar: <rdar://problem/11891562>
 */
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <mach/mach.h>

#define VERBOSE 1
#define COUNT 3000000

semaphore_t sender_sema = SEMAPHORE_NULL;
mach_port_t msg_port = MACH_PORT_NULL;
boolean_t msg_port_modref = FALSE;

void *
sender(void *arg)
{
	mach_msg_empty_send_t smsg;
	mach_port_t notify, old_notify;
	kern_return_t kr;
	boolean_t msg_inited;
	boolean_t use_sp = *(boolean_t *)arg;
	int send_possible_count = 0;

	fprintf(stderr, "starting a thread %susing send-possible notifications.\n", 
		(!use_sp) ? "not " : "");

	if (use_sp) {
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify);
		if (KERN_SUCCESS != kr) {
			mach_error("mach_port_allocate(notify)", kr);
			exit(1);
		}

	request:
		kr = mach_port_request_notification(mach_task_self(), msg_port,
						    MACH_NOTIFY_SEND_POSSIBLE, 0 /* delayed */,
						    notify, MACH_MSG_TYPE_MAKE_SEND_ONCE,
						    &old_notify);
		if (KERN_INVALID_ARGUMENT == kr && msg_port_modref)
			goto done;
				
		if (KERN_SUCCESS != kr) {
			mach_error("mach_port_request_notification(MACH_NOTIFY_SEND_POSSIBLE)", kr);
			exit(1);
		}
		if (MACH_PORT_NULL != old_notify) {
			fprintf(stderr, "unexecpted old notify port (0x%x)\n", old_notify);
			exit(1);
		}
	}

	msg_inited = FALSE;

	for (;;) {
		mach_send_possible_notification_t nmsg;
		mach_msg_option_t options;
		mach_msg_return_t mret;

		if (!msg_inited) {
			mach_msg_option_t options;

			smsg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
			smsg.header.msgh_remote_port = msg_port;
			smsg.header.msgh_local_port = MACH_PORT_NULL;
			smsg.header.msgh_size = sizeof(smsg);
			smsg.header.msgh_id = 0;
			msg_inited = TRUE;
		}

		options = MACH_SEND_MSG | MACH_SEND_TIMEOUT;
		if (use_sp)
			options |= MACH_SEND_NOTIFY;

		mret = mach_msg(&smsg.header, options,
				sizeof(smsg), 0,
				MACH_PORT_NULL,
				MACH_MSG_TIMEOUT_NONE /* immediate timeout */,
				MACH_PORT_NULL);

		if (MACH_MSG_SUCCESS == mret) {
			msg_inited = FALSE;
			continue;
		}

		if (MACH_SEND_INVALID_DEST == mret)
			break;

		if (MACH_SEND_TIMED_OUT != mret) {
			mach_error("mach_msg(send)", mret);
			exit(1);
		}

		if (use_sp) {

			/* Wait for the send-possible notification */
			mret = mach_msg(&nmsg.not_header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
					0, sizeof(nmsg),
					notify, 
					10000 /* 10 second timeout */,
					MACH_PORT_NULL);

			if (msg_port_modref)
				goto done;

			if (MACH_RCV_TIMED_OUT == mret) {
				fprintf(stderr, "FAILED! Didn't receive send-possible notification\n");
				exit(1);
			}

			if (MACH_MSG_SUCCESS != mret) {
				mach_error("mach_msg_receive(notify)\n", mret);
				exit(1);
			}

			switch (nmsg.not_header.msgh_id) {

			case MACH_NOTIFY_SEND_POSSIBLE:
				if (nmsg.not_port != msg_port) {
					fprintf(stderr, "send possible notification about wrong port (0x%x != 0x%x)\n", nmsg.not_port, msg_port);
					exit(1);
				}
				send_possible_count++;

				semaphore_signal_all(sender_sema);
				goto request;

			case MACH_NOTIFY_DEAD_NAME:
				if (nmsg.not_port != msg_port) {
					fprintf(stderr, "dead name notification about wrong port (0x%x != 0x%x)\n", nmsg.not_port, msg_port);
					exit(1);
				}
				goto done;
			default:
				fprintf(stderr, "unexected notify id (%d)\n", nmsg.not_header.msgh_id);
				exit(1);
			}
		} else {
			semaphore_wait(sender_sema);
		}
	}

 done:
	if (use_sp) {
		mach_port_destroy(mach_task_self(), notify);
		fprintf(stderr, "received %d send-possible notifications\n", send_possible_count);
	}
	return(NULL);
}

int
main(int argc, char **argv) {
	mach_msg_return_t mret;
	mach_port_limits_t limits;
	pthread_t thread1, thread2, thread3;
	boolean_t thread1_arg, thread2_arg, thread3_arg;
	kern_return_t kr;
	int i, res;

	/* allocate receive and send right for the message port */
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &msg_port);
	if (KERN_SUCCESS != kr) {
		mach_error("mach_port_allocate(msg_port)", kr);
		exit(1);
	}
	kr = mach_port_insert_right(mach_task_self(), msg_port, msg_port, MACH_MSG_TYPE_MAKE_SEND);
	if (KERN_SUCCESS != kr) {
		mach_error("mach_port_insert_right(msg_port)", kr);
		exit(1);
	}

	/* bump its qlimit up enough to allow races to develop between threads */
	limits.mpl_qlimit = 100;
	kr = mach_port_set_attributes(mach_task_self(), msg_port,
				      MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits, sizeof(limits)/sizeof(int));
	if (KERN_SUCCESS != kr) {
		mach_error("mach_port_allocate(msg_port)", kr);
		exit(1);
	}

	kr = semaphore_create(mach_task_self(), &sender_sema, SYNC_POLICY_FIFO, 0 /* initial value */);
	if (KERN_SUCCESS != kr) {
		mach_error("semaphore_create(sender_sema)\n", kr);
		exit(1);
	}

	thread1_arg = FALSE; /* don't use send-possible notifications */
	res = pthread_create(&thread1, (pthread_attr_t *)NULL, sender, &thread1_arg);
	if (res) {
		perror("pthread_create(non-send-possible_thread-1)");
		exit(1);
	}

	thread2_arg = FALSE; /* don't use send-possible notifications */
	res = pthread_create(&thread2, (pthread_attr_t *)NULL, sender, &thread2_arg);
	if (res) {
		perror("pthread_create(non-send-possible_thread-2)");
		exit(1);
	}

	thread3_arg = TRUE; /* use send-possible notifications */
	res = pthread_create(&thread3, (pthread_attr_t *)NULL, sender, &thread3_arg);
	if (res) {
		perror("pthread_create(send-possible-thread-3)");
		exit(1);
	}

	for (i=0; i < COUNT; i++) {
		mach_msg_empty_rcv_t rmsg;

		mret = mach_msg(&rmsg.header, MACH_RCV_MSG,
				0, sizeof(rmsg),
				msg_port, 
				MACH_MSG_TIMEOUT_NONE,
				MACH_PORT_NULL);
		if (MACH_MSG_SUCCESS != mret) {
			mach_error("mach_msg_receive(msg_port)\n", mret);
			exit(1);
		}
	}

	msg_port_modref = TRUE;
	kr = mach_port_mod_refs(mach_task_self(), msg_port, MACH_PORT_RIGHT_RECEIVE, -1);
	if (KERN_SUCCESS != kr) {
		mach_error("mach_port_mod_refs(msg_port)", kr);
		exit(1);
	}

	kr = semaphore_destroy(mach_task_self(), sender_sema);
	if (KERN_SUCCESS != kr) {
		mach_error("semaphore_destroy(sender_sema)", kr);
		exit(1);
	}

	res = pthread_join(thread1, NULL);
	if (res) {
		perror("pthread_join(thread1)");
		exit(1);
	}
	res = pthread_join(thread2, NULL);
	if (res) {
		perror("pthread_join(thread2)");
		exit(1);
	}
	res = pthread_join(thread3, NULL);
	if (res) {
		perror("pthread_join(thread3)");
		exit(1);
	}

        printf("[PASSED] Test sprace_test_11891562 passed. \n");
	exit(0);
}

