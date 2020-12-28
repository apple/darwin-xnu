#include <AvailabilityMacros.h>
#include <mach/thread_policy.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

int             verbosity = 1;

#define DBG(x...) do {                          \
	if (verbosity > 1) {                    \
	        printf(x);                      \
	}                                       \
} while (0)

#define mutter(x...) do {                       \
	if (verbosity > 0) {                    \
	        printf(x);                      \
	}                                       \
} while (0)

#define s_if_plural(x)  (((x) > 1) ? "s" : "")

static void
usage()
{
	fprintf(stderr,
	    "usage: tags [-i]   interactive/input\n"
	    "            [-v V] verbosity level 0..2 (1)\n"
	    "            [-h]   help info\n"
	    "            pid    process id of target task\n"
	    );
	exit(1);
}

void
thread_tag_set(thread_t thread, int tag)
{
	kern_return_t                   ret;
	thread_affinity_policy_data_t   policy;

	policy.affinity_tag = tag;
	ret = thread_policy_set(
		thread, THREAD_AFFINITY_POLICY,
		(thread_policy_t) &policy,
		THREAD_AFFINITY_POLICY_COUNT);
	if (ret != KERN_SUCCESS) {
		printf("thread_policy_set(1) returned %d\n", ret);
		exit(1);
	}
}

int
thread_tag_get(thread_t thread)
{
	kern_return_t                   ret;
	boolean_t                       get_default = FALSE;
	thread_affinity_policy_data_t   policy;
	mach_msg_type_number_t          count = THREAD_AFFINITY_POLICY_COUNT;

	ret = thread_policy_get(
		thread, THREAD_AFFINITY_POLICY,
		(thread_policy_t) &policy, &count, &get_default);
	if (ret != KERN_SUCCESS) {
		printf("thread_policy_set(1) returned %d\n", ret);
		exit(1);
	}

	return policy.affinity_tag;
}

char                    input[81];
int
main(int argc, char *argv[])
{
	kern_return_t           ret;
	mach_port_name_t        port;
	int                     pid;
	int                     c;
	thread_act_t            *thread_array;
	mach_msg_type_number_t  num_threads;
	int                     i;
	boolean_t               interactive = FALSE;
	int                     tag;

	if (geteuid() != 0) {
		printf("Must be run as root\n");
		exit(1);
	}

	/* Do switch parsing: */
	while ((c = getopt(argc, argv, "hiv:")) != -1) {
		switch (c) {
		case 'i':
			interactive = TRUE;
			break;
		case 'v':
			verbosity = atoi(optarg);
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	argc -= optind; argv += optind;
	if (argc > 0) {
		pid = atoi(*argv);
	}

	ret = task_for_pid(mach_task_self(), pid, &port);
	if (ret != KERN_SUCCESS) {
		err(1, "task_for_pid(,%d,) returned %d", pid, ret);
	}

	mutter("task %p\n", port);
	ret = task_threads(port, &thread_array, &num_threads);
	if (ret != KERN_SUCCESS) {
		err(1, "task_threads() returned %d", pid, ret);
	}

	for (i = 0; i < num_threads; i++) {
		printf(" %d: thread 0x%08x tag %d\n",
		    i, thread_array[i], thread_tag_get(thread_array[i]));
	}

	while (interactive) {
		printf("Enter new tag or <return> to skip or ^D to quit\n");
		for (i = 0; i < num_threads; i++) {
			tag =  thread_tag_get(thread_array[i]);
			printf(" %d: thread 0x%08x tag %d: ",
			    i, thread_array[i], tag);
			fflush(stdout);
			(void) fgets(input, 20, stdin);
			if (feof(stdin)) {
				printf("\n");
				interactive = FALSE;
				break;
			}
			if (strlen(input) > 1) {
				tag = atoi(input);
				thread_tag_set(thread_array[i], tag);
			}
		}
	}

	return 0;
}
