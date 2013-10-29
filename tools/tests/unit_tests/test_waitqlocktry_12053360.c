/*
 * File: test_waitqlocktry_12053360.c
 * Test Description: This is a load test for wait queues in the kernel. It is designed to excercise the locking of threads and
 * wait queues in the face of timer expirations. The overall runtime is limited to 90 secs. 
 * In case of inconsistency we have found to be panic'ing within the first 15 secs.
 * Radar: <rdar://problem/12053360> <rdar://problem/12323652>
 */

#include <unistd.h>
#include <stdio.h>
#include <mach/semaphore.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>

#define MAX_TEST_RUN_TIME  90
uint32_t test_usleep_max;

void*
test_thread(void *arg __unused)
{
	while (1) {
		usleep(random() % test_usleep_max);
	}

	return NULL;
}


int
main(int argc, const char **argv)
{
	pthread_t *threads;
	uint32_t nthreads, i;
	int tmp, result;

	if (argc != 3) {
		printf("Usage: %s <max sleep in usecs> <nthreads>\n", argv[0]);
		printf("Currently defaulting to 100us and 100 threads\n");
		test_usleep_max = 100;
		nthreads = 100;
	}else {
	
		tmp = atoi(argv[1]);
		if (tmp < 0) {
			printf("Sleep time must be > 0.\n");
			exit(1);
		}
	
		test_usleep_max = (uint32_t)tmp;
	
		tmp = atoi(argv[2]);
		if (tmp < 0) {
			printf("Num threads must be > 0.\n");
			exit(1);
		}
		nthreads = (uint32_t)tmp;
	}
	threads = (pthread_t*)malloc(nthreads * sizeof(pthread_t));
	if (threads == NULL) {
		printf("Failed to allocate thread array.\n");
		exit(1);
	}

	printf("Creating %u threads with a max sleep time of %uusec.\n", nthreads, test_usleep_max);
	srand(time(NULL));
	for (i = 0; i < nthreads; i++) {
		result = pthread_create(&threads[i], NULL, test_thread, NULL);
		if (result != 0) {
			printf("Failed to allocate thread.\n");
			exit(1);
		}
	}

	printf("Main thread sleeping for %d secs\n", MAX_TEST_RUN_TIME);
	sleep(MAX_TEST_RUN_TIME);
	printf("Success. Exiting..\n");
	return 0;
}
