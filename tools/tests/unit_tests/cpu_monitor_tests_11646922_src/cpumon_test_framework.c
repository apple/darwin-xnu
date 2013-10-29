/*
 * Testing Framework for CPU Usage Monitor
 *
 * The framework tests for correctness of the CPU Usage Monitor.
 * It creates a new exception port and an associated handling thread.
 * For each test case, the framework sets its own exception port to the
 * newly allocated port, execs a new child (which inherits the new
 * exception port) and restores the parent's exception port to the
 * original handler. The child process is invoked with a different
 * parameters based on the scenario being tested.
 *
 * Usage: ./cpu_monitor_tests_11646922 [test case ID]
 * If no test case ID is supplied, the framework runs all test cases.
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
#include <spawn_private.h>
#include <libproc_internal.h>
#include <excserver.h>
#include <kern/exc_resource.h>

#define MAX_TEST_ID_LEN 16
#define MAX_ARGV 8

#define GENERATE_TEST_EXC_CODE(type, flavor) \
	((0) | ((type & 0x7ULL) << 61) | ((flavor & 0x7ULL) << 58))

/*
 * To add a new test case to this framework:
 * - Increment the NUMTESTS value
 * - Add exec args for cpu_hog/cpu_hog unentitled to test the
 *   scenario. Also add a case to the main loop child_args assignment.
 * - Add timeout for exception. If no timeout, specify 0.
 * - Add expected duration for exception. 0 if no exception expected.
 * - Add (Exception Type | flavor) to "test_exception_code" if the
 *   test case generates an exception; 0 otherwise
 */

#define NUMTESTS 7

const char *test_description[] = {
	"Basic test for EXC_RESOURCE.",
	"Test Program stays under limit.",
	"Test Program disables monitor.",
	"Unentitled Test Program attempts to disable monitor.",
	"Test Program resets monitor to default.",
	"Set high watermark, munch past it, and confirm EXC_RESOURCE received for FLAVOR_HIGH_WATERMARK.",
	"Set high watermark but don't munch past it. Confirm no EXC_RESOURCE received.",
};

/*
 * Exec arguments for cpu hogging programs
 * (NULL indicates test should not be run)
 */
char *test_argv_0[] = { "./cpu_hog-unentitled", "-c", "30", "-C", "10", "-p", "100", "-i", "1", NULL };
char *test_argv_1[] = { "./cpu_hog-unentitled", "-c", "50", "-C", "15", "-p", "25", "-i", "1", NULL };
#ifdef TARGET_SDK_iphoneos_internal
char *test_argv_2[] = { "./cpu_hog",            "-c", "20", "-C", "15", "-x", "0", "-p", "100", "-i", "1", NULL };
char *test_argv_3[] = { "./cpu_hog-unentitled", "-c", "20", "-C", "15", "-x", "1", "-p", "100", "-i", "1", NULL };
#else
char *test_argv_2[] = { "./cpu_hog-unentitled", "-c", "20", "-C", "15", "-x", "0", "-p", "100", "-i", "1", NULL };
char **test_argv_3 = NULL;
#endif
char *test_argv_4[] = { "./cpu_hog-unentitled", "-c", "20", "-C", "15", "-r", "1", "-p", "100", "-i", "1", NULL };
#ifdef TARGET_SDK_iphoneos_internal
char *test_argv_5[] = { "./mem_hog", "-e", "-w", "50", "-m", "150", "10", "200", NULL };
char *test_argv_6[] = { "./mem_hog", "-e", "-w", "190", "-m", "160", "10", "200", NULL };
#else
char **test_argv_5 = NULL;
char **test_argv_6 = NULL;
#endif

/*
 * Timeout in seconds for test scenario to complete
 * (0 indicates no timeout enabled)
 */
int timeout_secs[] = {
	15,
	20,
	20,
	110,
	110,
	20,
	20,
};

/*
 * Exception should be generated within the specified duration
 * (0 indicates no exception/time constraints for the exception
 * to occur)
 */
int exc_expected_at[] = {
	0,
	0,
	0,
	90,
	90,
	10,
	0,
};

/*
 * EXC_RESOURCE exception codes expected (0 indicates no
 * exception expected)
 */
uint64_t test_exception_code[] = {
	GENERATE_TEST_EXC_CODE(RESOURCE_TYPE_CPU, FLAVOR_CPU_MONITOR),
	0,
	0,
	GENERATE_TEST_EXC_CODE(RESOURCE_TYPE_CPU, FLAVOR_CPU_MONITOR),
	GENERATE_TEST_EXC_CODE(RESOURCE_TYPE_CPU, FLAVOR_CPU_MONITOR),
	GENERATE_TEST_EXC_CODE(RESOURCE_TYPE_MEMORY, FLAVOR_HIGH_WATERMARK),
	0,
};

#define DEFAULT_PERCENTAGE "50"
#define DEFAULT_INTERVAL   "180"

/* Global Variables used by parent/child */
mach_port_t	exc_port;	/* Exception port for child process */
uint64_t	exception_code; /* Exception code for the exception generated */
int		time_for_exc;	/* Time (in secs.) for the exception to be generated */
extern char	**environ;	/* Environment variables for the child process */
int		test_status;	/* Test Suite Status */
int		indiv_results[NUMTESTS]; /* Results of individual tests (-1=didn't run; 0=pass; 1=fail) */

/* Cond Var and Mutex to indicate timeout for child process */
pthread_cond_t	cv;
pthread_mutex_t lock;

/* Timer Routines to calculate elapsed time and run timer thread */
time_t		start_time;	/* Test case start time (in secs.) */

int elapsed(void)
{
	return (time(NULL) - start_time);
}

void *timeout_thread(void *arg)
{
	int err;
	int timeout = (int)arg;

	sleep(timeout);
	fprintf(stderr, "Test Program timed out... Terminating!\n");

	if ((err = pthread_cond_broadcast(&cv)) != 0) {
		fprintf(stderr, "pthread_cond_broadcast: %s\n", strerror(err));
		exit(1);
	}	

	return (NULL);	
}

/* Routine to wait for child to complete */
void *wait4_child_thread(void *arg)
{
	int err;
	int child_stat;

	wait4(-1, &child_stat, 0, NULL);

	if ((err = pthread_cond_broadcast(&cv)) != 0) {
		fprintf(stderr, "pthread_cond_broadcast: %s\n", strerror(err));
		exit(1);
	}

	return (NULL);
}

/* Mach Server Routines */
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
 mach_msg_type_number_t codeCnt
 )
{
	if (exception == EXC_RESOURCE) {
		/* Set global variable to indicate exception received */
		exception_code = *((uint64_t *)code);
		time_for_exc = elapsed();
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
 mach_msg_type_number_t codeCnt,
 int *flavor,
 thread_state_t old_state,
 mach_msg_type_number_t old_stateCnt,
 thread_state_t new_state,
 mach_msg_type_number_t *new_stateCnt
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
	posix_spawnattr_t	attrs;
	uint64_t		percent, interval;
	int			i, err, ret = 0;

	kern_return_t		kr;
	mach_port_t		task = mach_task_self();
	mach_port_t		child_task;
	char                    **child_args;

	pthread_t		exception_thread;
	pthread_t		timer_thread;
	pthread_t		wait_thread;

	mach_msg_type_number_t	maskCount = 1;
	exception_mask_t	mask;
	exception_handler_t	handler;
	exception_behavior_t	behavior;
	thread_state_flavor_t   flavor;

	pid_t			child_pid;
	int			test_case_id = -1;

	if (argc > 1)
		test_case_id = atoi(argv[1]);

	/* Initialize mutex and condition variable */
	if ((err = pthread_mutex_init(&lock, NULL)) != 0) {
		fprintf(stderr,"pthread_mutex_init: %s\n", strerror(err));
		exit(1);
	}

	if ((err = pthread_cond_init(&cv, NULL)) != 0) {
		fprintf(stderr, "pthread_cond_init: %s\n", strerror(err));
		exit(1);
	}

	/* Allocate and initialize new exception port */
	if ((kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port)) != KERN_SUCCESS) {
		fprintf(stderr, "mach_port_allocate: %s\n", mach_error_string(kr));
		exit(1);
	}

	if ((kr = mach_port_insert_right(task, exc_port,
					exc_port, MACH_MSG_TYPE_MAKE_SEND)) != KERN_SUCCESS) {
		fprintf(stderr, "mach_port_allocate: %s\n", mach_error_string(kr));
		exit(1);
	}

	/* Get Current exception ports */
	if ((kr = task_get_exception_ports(task, EXC_MASK_RESOURCE, &mask,
					&maskCount, &handler, &behavior, &flavor)) != KERN_SUCCESS) {
		fprintf(stderr,"task_get_exception_ports: %s\n", mach_error_string(kr));
		exit(1);
	}

	/* Create exception serving thread */
	if ((err = pthread_create(&exception_thread, NULL, server_thread, 0)) != 0) {
		fprintf(stderr, "pthread_create server_thread: %s\n", strerror(err));
		exit(1);
	}

	fprintf(stderr, "---------------System Configuration------------------------------------------\n");
	fprintf(stderr, "System Kernel Version: ");
	system("uname -a");
	fprintf(stderr, "System SDK Version: ");
	system("sw_vers");

	for (i = 0; i < NUMTESTS; i++) {
		indiv_results[i] = -1;
	}

	/* Run Tests */
	for(i=0; i<NUMTESTS; i++) {
		int j;

		if (test_case_id != -1 && test_case_id != i)
			continue;

		fprintf(stderr, "---------------Test [%d] Configuration------------------------------------------\n", i);
		fprintf(stderr, "Test Case ID: %d\n", i);
		fprintf(stderr, "Description: %s\n", test_description[i]);

		switch(i) {
		case 0:
			child_args = test_argv_0;
			break;
		case 1:
			child_args = test_argv_1;
			break;
		case 2:
			child_args = test_argv_2;
			break;
		case 3:
			child_args = test_argv_3;
			break;
		case 4:
			child_args = test_argv_4;
			break;
		case 5:
			child_args = test_argv_5;
			break;
		case 6:
			child_args = test_argv_6;
			break;
		default:
			fprintf(stderr, "no test argv found\n");
			exit(1);
		}

		/* Test cases which do not need to run for certain platforms */
		if (child_args == NULL) {
			fprintf(stderr, "Test case unimplemented for current platform.\n");
			fprintf(stderr, "[PASSED]\n");
			fprintf(stderr, "-------------------------------------------------------------------------------\n");
			continue;
		}

		fprintf(stderr, "Helper args: ");
		for (j = 0; child_args[j] != NULL; j++) {
			fprintf(stderr, "%s ", child_args[j]);
		}
		fprintf(stderr, "\n");

		/* Print Test Case Configuration */
		fprintf(stderr, "Test Case expects EXC_RESOURCE?: %s\n", test_exception_code[i] ? "Yes":"No");
		if (test_exception_code[i])
			fprintf(stderr, "Expected EXC_RESOURCE code: 0x%llx\n", test_exception_code[i]);
		if (timeout_secs[i])
			fprintf(stderr, "Timeout for Test Program: %d secs\n", timeout_secs[i]);
		if (exc_expected_at[i])
			fprintf(stderr, "Exception Expected After: %d secs\n", exc_expected_at[i]);

		/* Initialize posix_spawn attributes */
		posix_spawnattr_init(&attrs);

		if ((err = posix_spawnattr_setflags(&attrs, POSIX_SPAWN_SETEXEC)) != 0) {
			fprintf(stderr, "posix_spawnattr_setflags: %s\n", strerror(err));
			exit(1);
		}

		/* Use high values so the system defaults take effect (spawn attrs are capped) */
		percent = 100;
		interval = 10000;

		/* Enable CPU Monitor */
		if ((err = posix_spawnattr_setcpumonitor(&attrs, percent, interval)) != 0) {
				fprintf(stderr, "posix_spawnattr_setcpumonitor: %s\n", strerror(err));
				exit(1);
		}
		

		exception_code = 0;
		time_for_exc = -1;

		/* Set Exception Ports for Current Task */
		if ((kr = task_set_exception_ports(task, EXC_MASK_RESOURCE, exc_port,
						EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, flavor)) != KERN_SUCCESS) {
			fprintf(stderr, "task_set_exception_ports: %#x\n", kr);
			exit(1);
		}
	
		/*
		 * Note the time at start of test.
		 */
		start_time = time(NULL);

		fprintf(stderr, "---------------Test [%d] Runtime------------------------------------------------\n", i);

		/* Fork and exec child */
		if ((child_pid = fork()) == 0) {
			if ((err = posix_spawn(NULL, child_args[0], NULL, &attrs, &child_args[0], environ)) != 0) {
				fprintf(stderr, "posix_spawn: %s\n", strerror(err));
				exit(1);
			}
		}

		/* Restore exception ports for parent */
		if ((kr = task_set_exception_ports(task, EXC_MASK_RESOURCE, handler,
						EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, flavor)) != KERN_SUCCESS) {
			fprintf(stderr, "task_set_exception_ports: %#x\n", kr);
			exit(1);
		}

		/* Create Timer Thread if timeout specified */
		if (timeout_secs[i]) {
			if ((err = pthread_create(&timer_thread, NULL, timeout_thread, (void *)timeout_secs[i])) != 0) {
				fprintf(stderr, "pthread_create timeout_thread: %s\n", strerror(err));
				test_status = 1;
				goto cleanup;
			}
		}

		/* Create waiting for child thread */
		if ((err = pthread_create(&wait_thread, NULL, wait4_child_thread, NULL)) != 0) {
			fprintf(stderr, "pthread_create wait4_child_thread: %s\n", strerror(err));
			test_status = 1;
			goto cleanup;
		}

		pthread_mutex_lock(&lock);
		pthread_cond_wait(&cv, &lock);
		pthread_mutex_unlock(&lock);
		
		kill(child_pid, SIGKILL);
		pthread_join(timer_thread, NULL);
		pthread_join(wait_thread, NULL);

		int test_case_status = 0;
		indiv_results[i] = 0;

		fprintf(stderr, "---------------Test [%d] Results------------------------------------------------\n", i);

		if (exception_code)
			fprintf(stderr, "EXC_RESOURCE Received with Code: 0x%llx\n", exception_code);
		else
			fprintf(stderr, "No EXC_RESOURCE Received!\n");
			
		if (time_for_exc > 0)
			fprintf(stderr, "EXC_RESOURCE Received after %d secs\n", time_for_exc);

		if (!!exception_code != !!test_exception_code[i]) {
			test_status = 1;
			test_case_status = 1;
			indiv_results[i] = 1;
		}

		if (exception_code) {
			/* Validate test success by checking code and expected time */
			if ((exception_code & test_exception_code[i]) != test_exception_code[i]) {
				fprintf(stderr, "Test Failure Reason: EXC_RESOURCE code did not match expected exception code!\n");
				fprintf(stderr, "Expected: 0x%llx Found: 0x%llx\n", test_exception_code[i], exception_code);
				test_status = 1;
				test_case_status = 1;
				indiv_results[i] = 1;				
			}
			if(exc_expected_at[i] &&
				(time_for_exc < (exc_expected_at[i] - 10) ||
				time_for_exc > (exc_expected_at[i] + 10))) {
					fprintf(stderr, "Test Failure Reason: Test case did not receive EXC_RESOURCE within expected time!\n");
					test_status = 1;
					test_case_status = 1;
					indiv_results[i] = 1;					
			}
		}

		if(test_case_status)
			fprintf(stderr, "[FAILED]\n");
		else
			fprintf(stderr, "[PASSED]\n");
		fprintf(stderr, "-------------------------------------------------------------------------------\n");

	}

	if (test_case_id == -1) {
		fprintf(stderr, "--------------- Results Summary -----------------------------------------------\n");

		for (i = 0; i < NUMTESTS; i++) {
			fprintf(stderr, "%2d: %s\n", i, (indiv_results[i] < 0) ? "N/A" :
			        (indiv_results[i] == 0) ? "PASSED" : "FAILED");
		}
	}

cleanup:
	kill(child_pid, SIGKILL);
	exit(test_status);
}


