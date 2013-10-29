/* 
 * Testing Framework for EXC_GUARD exceptions 
 * 
 * The framework tests for exception conditions for guarded mach ports.
 * It creates a new exception port and an associated handling thread.
 * For each test case, the framework sets its own exception port to the 
 * newly allocated port, execs a new child (which inherits the new 
 * exception port) and restores the parent's exception port to the 
 * original handler. The child process is invoked with a different 
 * test case identifier and invokes the corresponding test case. 
 *
 */

#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/port.h>
#include <mach/mach_port.h>
#include <mach/mach_init.h>
#include <spawn_private.h>
#include <libproc_internal.h>
#include <mach_exc.h>

#define MAX_TEST_ID_LEN 16
#define MAX_ARGV 8
#define EXC_CODE_SHIFT 32
#define EXC_GUARD_TYPE_SHIFT 29

/*
 * To add a new test case to this framework:
 * - Increment the NUMTESTS value
 * - Add (Guard Type | flavor) to "test_exception_code" if the 
 *   test case generates an exception; 0 otherwise
 * - Add a new case and routine in guarded_test.c to 
 *   test the scenario
 */

#define NUMTESTS 10

uint64_t test_exception_code[] = {
	0,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_DESTROY,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_DESTROY,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_MOD_REFS,
	0,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_INCORRECT_GUARD,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_UNGUARDED,
	0,
	0,
	(GUARD_TYPE_MACH_PORT << EXC_GUARD_TYPE_SHIFT) | kGUARD_EXC_SET_CONTEXT
};

mach_port_t exc_port;
uint64_t exception_code;
extern char **environ;

boolean_t mach_exc_server(
		mach_msg_header_t *InHeadP,
		mach_msg_header_t *OutHeadP);

kern_return_t catch_mach_exception_raise
(
 mach_port_t exception_port,
 mach_port_t thread,
 mach_port_t task,
 exception_type_t exception,
 mach_exception_data_t code,
 mach_msg_type_number_t codeCnt,
 int *flavor,
 thread_state_t old_state,
 mach_msg_type_number_t old_stateCnt,
 thread_state_t new_state,
 mach_msg_type_number_t *new_stateCnt
 )
{
	if (exception == EXC_GUARD) {
		/* Set global variable to indicate exception received */	  
		exception_code = *((uint64_t *)code);
	} else {
		/* Terminate test on all other unexpected exceptions */
		fprintf(stderr, "received unexpected exception type %#x\n", exception);
		exit(1);
	}

	return (KERN_SUCCESS);
}

kern_return_t catch_mach_exception_raise_state
(
 mach_port_t exception_port,
 exception_type_t exception,
 const mach_exception_data_t code,
 mach_msg_type_number_t codeCnt,
 int *flavor,
 const thread_state_t old_state,
 mach_msg_type_number_t old_stateCnt,
 thread_state_t new_state,
 mach_msg_type_number_t *new_stateCnt
 )
{
	fprintf(stderr, "Unexpected exception handler called\n");
	exit(1);
	return (KERN_FAILURE);
}


kern_return_t catch_mach_exception_raise_state_identity
(
 mach_port_t exception_port,
 mach_port_t thread,
 mach_port_t task,
 exception_type_t exception,
 mach_exception_data_t code,
 mach_msg_type_number_t codeCnt
 )
{
	fprintf(stderr, "Unexpected exception handler called\n");
	exit(1);
	return (KERN_FAILURE);
}


void *server_thread(void *arg)
{
	kern_return_t kr;

	while(1) {
		/* Handle exceptions on exc_port */
		if ((kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0)) != KERN_SUCCESS) {
			fprintf(stderr, "mach_msg_server_once: error %#x\n", kr);
			exit(1);
		}
	}
	return (NULL);
}

int main(int argc, char *argv[])
{
	posix_spawnattr_t       attrs;
	kern_return_t           kr;
	mach_port_t             task = mach_task_self();

	mach_msg_type_number_t  maskCount = 1;
	exception_mask_t        mask;
	exception_handler_t     handler;
	exception_behavior_t    behavior;
	thread_state_flavor_t   flavor;
	pthread_t               exception_thread;
	uint64_t                exc_id;
	unsigned int            exc_fd;

	char *test_prog_name = "./guarded_mp_test";
	char *child_args[MAX_ARGV];
	char test_id[MAX_TEST_ID_LEN];
	int i, err;
	int child_status;
	int test_status = 0;

	/* Allocate and initialize new exception port */
	if ((kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port)) != KERN_SUCCESS) {
		fprintf(stderr, "mach_port_allocate: %#x\n", kr);
		exit(1);
	}

	if ((kr = mach_port_insert_right(task, exc_port, 
					exc_port, MACH_MSG_TYPE_MAKE_SEND)) != KERN_SUCCESS) {
		fprintf(stderr, "mach_port_allocate: %#x\n", kr);
		exit(1);
	}

	/* Get Current exception ports */
	if ((kr = task_get_exception_ports(task, EXC_MASK_GUARD, &mask,
					&maskCount, &handler, &behavior, &flavor)) != KERN_SUCCESS) {
		fprintf(stderr,"task_get_exception_ports: %#x\n", kr);
		exit(1);
	}

	/* Create exception serving thread */
	if ((err = pthread_create(&exception_thread, NULL, server_thread, 0)) != 0) {
		fprintf(stderr, "pthread_create server_thread: %s\n", strerror(err));
		exit(1);
	}

	pthread_detach(exception_thread);

	/* Initialize posix_spawn attributes */
	posix_spawnattr_init(&attrs);

	if ((err = posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETEXEC)) != 0) {
		fprintf(stderr, "posix_spawnattr_setflags: %s\n", strerror(err));
		exit(1);
	}

	/* Run Tests */
	for(i=0; i<NUMTESTS; i++) {

		exception_code = 0;
		/* Set Exception Ports for Current Task */
		if ((kr = task_set_exception_ports(task, EXC_MASK_GUARD, exc_port,
						EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, flavor)) != KERN_SUCCESS) {
			fprintf(stderr, "task_set_exception_ports: %#x\n", kr);
			exit(1);
		}

		child_args[0] = test_prog_name;
		sprintf(&test_id[0], "%d", i);
		child_args[1] = &test_id[0];
		child_args[2] = NULL;

		/* Fork and exec child */
		if (fork() == 0) {
			if ((err = posix_spawn(NULL, child_args[0], NULL, &attrs, &child_args[0], environ)) != 0) {
				fprintf(stderr, "posix_spawn: %s\n", strerror(err));
				exit(1);
			}
		}

		/* Restore exception ports for parent */
		if ((kr = task_set_exception_ports(task, EXC_MASK_GUARD, handler,
						EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, flavor)) != KERN_SUCCESS) {
			fprintf(stderr, "task_set_exception_ports: %#x\n", kr);
			exit(1);
		} 

		/* Wait for child and check for exception */
		if (-1 == wait4(-1, &child_status, 0, NULL)) {
			exit(1);
		}

		exc_id = (exception_code >> EXC_CODE_SHIFT);
		printf("EXC_GUARD Received: ");
		(exc_id != 0)?printf("Yes (Code 0x%llx)\n", exception_code):printf("No\n");
		printf("Expected Exception Code: 0x%llx\n", test_exception_code[i]);
		printf("Test Result: ");
		if((WIFEXITED(child_status) && WEXITSTATUS(child_status)) ||
			(exc_id != test_exception_code[i])) {
				test_status = 1;
				printf("FAILED\n");
		}
		else {
			printf("PASSED\n");
		}
		printf("-------------------\n");

	}

	exit(test_status);
}


