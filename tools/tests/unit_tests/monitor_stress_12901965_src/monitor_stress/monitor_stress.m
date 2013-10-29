#define TARGET_OS_EMBEDDED 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#import <Foundation/Foundation.h>

#include <mach/message.h>
#include <libproc_internal.h>

#define MAX_THREADS 100

char *pname;

int pid;

int exit_after = -1;

int percentage = 95, interval = 600;

int wakemon_rate = 150;

int limit = 0; // Worker thread should apply per-thread limit to self?
int limit_period = 5000;

void usage(void) {
	printf("usage: monitor_stress [ -c nthreads ] [ -w nthreads ] \n");
	printf("\t-c: number of CPU usage monitor stress threads to use (default: 2\n");
	printf("\t-w: number of wakeups monitor stress threads to use (default: 0\n");
	printf("\t-e: exit after this many seconds (default: run forever)\n");
	printf("\t-p: act on this pid (default: self)\n");
}

void *perthr_limit_thread(void *arg)
{
	int percent = 90, refill_period = 30; // time unit is milliseconds
	int err;
	int cpupercent;

top:
	cpupercent = percent | (refill_period << 8);
    
    	if ((err = sysctlbyname("kern.setthread_cpupercent", 0, 0,
    		&cpupercent, sizeof (int))) != 0) {
		printf("kern.setthread_cpupercent: error %d\n", err);
		exit(1);
	}
	goto top;
}

void *cpumon_stress_thread(void *arg)
{
top:
	if (proc_set_cpumon_params(pid, percentage, interval) != 0) {
		perror("proc_set_cpumon_params");
		exit(1);
	}
	if (proc_disable_cpumon(pid) != 0) {
		perror("proc_disable_cpumon");
		exit(1);
	}
	goto top;
}

void *wakemon_stress_thread(void *arg)
{
top:
	if (proc_set_wakemon_params(pid, wakemon_rate, 0) != 0) {
		perror("proc_set_wakemon_params");
		exit(1);
	}
	if (proc_disable_wakemon(pid) != 0) {
		perror("proc_disable_wakemon");
		exit(1);
	}
	goto top;
}

void *exit_thread(void *arg) 
{
	sleep(exit_after);
	printf("...exiting.\n");
	exit(0);

	return (NULL);
}

int main(int argc, char *argv[])
{
	int ch;
	int i = 0;
	int cpumon_threads = 2;
	int wakemon_threads = 0;
    
	pthread_t thr_id;
	
	pname = basename(argv[0]);
	pid = getpid();
    
	while ((ch = getopt(argc, argv, "c:w:e:p:h?")) != -1) {
		switch (ch) {
		case 'c':
			cpumon_threads = atoi(optarg);
			break;
		case 'w':
			wakemon_threads = atoi(optarg);
			break;
		case 'e':
			exit_after = atoi(optarg);
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
			exit(1);

		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0) {
		usage();
		exit(1);
	}

	if ((cpumon_threads <= 0) || (cpumon_threads > MAX_THREADS) ||
	    (wakemon_threads < 0) || (wakemon_threads > MAX_THREADS)) {
		printf("%s: %d/%d threads too many (max is %d)\n", pname,
			cpumon_threads, wakemon_threads, MAX_THREADS);
		exit(1);
	}

	printf("%s: creating %d CPU usage monitor stress threads (1 will be main thread), ", pname, cpumon_threads);
	if (wakemon_threads > 0) {
		printf( "%d wakeups monitor stress threads, ", wakemon_threads);
	}
	printf("and 1 per-thread CPU limit stress thread.\n");

	if (pthread_create(&thr_id, NULL, perthr_limit_thread, NULL) != 0) {
     		perror("pthread_create");
     		exit(1);
	}

	for (i = 0; i < wakemon_threads; i++) {
		if (pthread_create(&thr_id, NULL, wakemon_stress_thread, NULL) != 0) {
	     		perror("pthread_create");
	     		exit(1);
		}
	}

	// main thread will be used as stress thread too, so start count at 1
	for (i = 1; i < cpumon_threads; i++) {
		if (pthread_create(&thr_id, NULL, cpumon_stress_thread, NULL) != 0) {
	     		perror("pthread_create");
	     		exit(1);
		}
	}

	if (exit_after >= 0) {
		printf("%s: will exit after %d seconds\n", pname, exit_after);
		if (pthread_create(&thr_id, NULL, exit_thread, NULL) != 0) {
			perror("pthread_create");
			exit(1);
		}
	}

	cpumon_stress_thread(NULL);

	return (0);
}
