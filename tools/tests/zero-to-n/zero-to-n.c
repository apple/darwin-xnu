/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#include <unistd.h>
#include <stdio.h>
#include <math.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <semaphore.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <libkern/OSAtomic.h>

#include <mach/mach_time.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/semaphore.h>

typedef enum wake_type { WAKE_BROADCAST_ONESEM, WAKE_BROADCAST_PERTHREAD, WAKE_CHAIN } wake_type_t;
typedef enum my_policy_type { MY_POLICY_REALTIME, MY_POLICY_TIMESHARE, MY_POLICY_FIXEDPRI } my_policy_type_t;

#define assert(truth, label) do { if(!(truth)) { printf("Thread %p: failure on line %d\n", pthread_self(), __LINE__); goto label; } } while (0)

#define CONSTRAINT_NANOS	(20000000ll)	/* 20 ms */
#define COMPUTATION_NANOS	(10000000ll)	/* 10 ms */
#define TRACEWORTHY_NANOS	(10000000ll)	/* 10 ms */

#if DEBUG
#define debug_log(args...) printf(args)
#else
#define debug_log(args...) do { } while(0)
#endif

/* Declarations */
void* 			child_thread_func(void *arg);
void			print_usage();
int			thread_setup(int my_id);
my_policy_type_t	parse_thread_policy(const char *str);
int			thread_finish_iteration();

/* Global variables (general) */
int			g_numthreads;
wake_type_t 		g_waketype;
policy_t		g_policy;
int			g_iterations;
struct mach_timebase_info g_mti;
semaphore_t		g_main_sem;
uint64_t 		*g_thread_endtimes_abs;
volatile int32_t 	g_done_threads;
boolean_t		g_do_spin = FALSE;
boolean_t		g_verbose = FALSE;
boolean_t		g_do_affinity = FALSE;
uint64_t	 	g_starttime_abs;
#if MIMIC_DIGI_LEAD_TIME
int			g_long_spinid;
uint64_t		g_spinlength_abs;
#endif /* MIMIC_DIGI_LEAD_TIME */

/* Global variables (broadcast) */
semaphore_t 		g_machsem;
semaphore_t 		g_leadersem;

/* Global variables (chain) */
semaphore_t		*g_semarr;

uint64_t
abs_to_nanos(uint64_t abstime)
{
	return (uint64_t)(abstime * (((double)g_mti.numer) / ((double)g_mti.denom)));
}

uint64_t
nanos_to_abs(uint64_t ns)
{
	return (uint64_t)(ns * (((double)g_mti.denom) / ((double)g_mti.numer)));
}

/*
 * Figure out what thread policy to use 
 */
my_policy_type_t
parse_thread_policy(const char *str)
{
	if (strcmp(str, "timeshare") == 0) {
		return MY_POLICY_TIMESHARE;
	} else if (strcmp(str, "realtime") == 0) {
		return MY_POLICY_REALTIME;
	} else if (strcmp(str, "fixed") == 0) {
		return MY_POLICY_FIXEDPRI;
	} else {
		printf("Invalid thread policy %s\n", str);
		exit(1);
	}
}

/*
 * Figure out what wakeup pattern to use
 */
wake_type_t 
parse_wakeup_pattern(const char *str) 
{
	if (strcmp(str, "chain") == 0) {
		return WAKE_CHAIN;
	} else if (strcmp(str, "broadcast-single-sem") == 0) {
		return WAKE_BROADCAST_ONESEM;
	} else if (strcmp(str, "broadcast-per-thread") == 0) {
		return WAKE_BROADCAST_PERTHREAD;
	} else {
		print_usage();
		exit(1);
	}
}

/*
 * Set policy
 */
int
thread_setup(int my_id)
{
	int res;

	switch (g_policy) {
		case MY_POLICY_TIMESHARE:
		{
			return 0;
		}
		case MY_POLICY_REALTIME: 
		{
			thread_time_constraint_policy_data_t pol;

			/* Hard-coded realtime parameters (similar to what Digi uses) */
			pol.period = 100000;
			pol.constraint =  nanos_to_abs(CONSTRAINT_NANOS);
			pol.computation = nanos_to_abs(COMPUTATION_NANOS);
			pol.preemptible = 0; /* Ignored by OS */

			res = thread_policy_set(mach_thread_self(), THREAD_TIME_CONSTRAINT_POLICY, (thread_policy_t) &pol, THREAD_TIME_CONSTRAINT_POLICY_COUNT);
			assert(res == 0, fail);
			break;
		}
		case MY_POLICY_FIXEDPRI: 
		{
			thread_extended_policy_data_t pol;
			pol.timeshare = 0;

			res = thread_policy_set(mach_thread_self(), THREAD_EXTENDED_POLICY, (thread_policy_t) &pol, THREAD_EXTENDED_POLICY_COUNT);
			assert(res == 0, fail);
			break;
		}
		default:
		{
			printf("invalid policy type\n");
			return 1;
		}
	}

	if (g_do_affinity) {
		thread_affinity_policy_data_t affinity;

		affinity.affinity_tag = my_id % 2;

		res = thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY, (thread_policy_t)&affinity, THREAD_AFFINITY_POLICY_COUNT);
		assert(res == 0, fail);
	}

	return 0;
fail:
	return 1;
}

/*
 * Wake up main thread if everyone's done
 */
int
thread_finish_iteration(int id)
{
	int32_t new;
	int res = 0;
	volatile float x = 0.0;
	volatile float y = 0.0;

	debug_log("Thread %p finished iteration.\n", pthread_self());
	
#if MIMIC_DIGI_LEAD_TIME
	/*
	 * One randomly chosen thread determines when everybody gets to stop.
	 */
	if (g_do_spin) {
		if (g_long_spinid == id) {
			uint64_t endspin;

			/* This thread took up fully half of his computation */
			endspin = g_starttime_abs + g_spinlength_abs;
			while (mach_absolute_time() < endspin) {
				y = y + 1.5 + x;
				x = sqrt(y);
			}
		}
	}
#endif /* MIMIC_DIGI_LEAD_TIME */
	
	new = OSAtomicIncrement32(&g_done_threads);

	debug_log("New value is %d\n", new);

	/*
	 * When the last thread finishes, everyone gets to go back to sleep.
	 */
	if (new == g_numthreads) {
		debug_log("Thread %p signalling main thread.\n", pthread_self());
		res = semaphore_signal(g_main_sem);
	} else {
#ifndef MIMIC_DIGI_LEAD_TIME
		if (g_do_spin) {
			while (g_done_threads < g_numthreads) {
				y = y + 1.5 + x;
				x = sqrt(y);
			}
		}
#endif
	}

	return res;
}

/*
 * Wait for a wakeup, potentially wake up another of the "0-N" threads,
 * and notify the main thread when done.
 */
void*
child_thread_func(void *arg)
{
	int my_id = (int)(uintptr_t)arg;
	int res;
	int i, j;
	int32_t new;

	/* Set policy and so forth */
	thread_setup(my_id);

	/* Tell main thread when everyone has set up */
	new = OSAtomicIncrement32(&g_done_threads);
	if (new == g_numthreads) {
		semaphore_signal(g_main_sem);
	}

	/* For each iteration */
	for (i = 0; i < g_iterations; i++) {
		/*
		 * Leader thread either wakes everyone up or starts the chain going.
		 */
		if (my_id == 0) { 
			res = semaphore_wait(g_leadersem);
			assert(res == 0, fail);
			
			g_thread_endtimes_abs[my_id] = mach_absolute_time();

#if MIMIC_DIGI_LEAD_TIME
			g_long_spinid = rand() % g_numthreads;
#endif /* MIMIC_DIGI_LEAD_TIME */

			switch (g_waketype) {
			case WAKE_CHAIN:
				semaphore_signal(g_semarr[my_id + 1]);
				break;
			case WAKE_BROADCAST_ONESEM: 
				semaphore_signal_all(g_machsem);
				break;
			case WAKE_BROADCAST_PERTHREAD:
				for (j = 1; j < g_numthreads; j++) {
					semaphore_signal(g_semarr[j]);
				}
				break;
			default:
				printf("Invalid wakeup type?!\n");
				exit(1);
			}
		} else {
			/*
			 * Everyone else waits to be woken up,
			 * records when she wake up, and possibly
			 * wakes up a friend.
			 */
			switch(g_waketype)  {
			case WAKE_BROADCAST_ONESEM:
				res = semaphore_wait(g_machsem);
				assert(res == KERN_SUCCESS, fail);

				g_thread_endtimes_abs[my_id] = mach_absolute_time();

				break;
				/*
				 * For the chain wakeup case:
				 * wait, record time, signal next thread if appropriate
				 */
			case WAKE_BROADCAST_PERTHREAD:
				res = semaphore_wait(g_semarr[my_id]);
				assert(res == 0, fail);

				g_thread_endtimes_abs[my_id] = mach_absolute_time();
				break;

			case WAKE_CHAIN:
				res = semaphore_wait(g_semarr[my_id]);
				assert(res == 0, fail);

				g_thread_endtimes_abs[my_id] = mach_absolute_time();

				if (my_id < (g_numthreads - 1)) {
					res = semaphore_signal(g_semarr[my_id + 1]);
					assert(res == 0, fail);
				}

				break;
			default:
				printf("Invalid wake type.\n");
				goto fail;
			}
		}

		res = thread_finish_iteration(my_id);
		assert(res == 0, fail);
	}

	return 0;
fail:
	exit(1);
}

/*
 * Admittedly not very attractive.
 */
void
print_usage()
{
	printf("Usage: zn <num threads> <chain | broadcast-single-sem | broadcast-per-thread> <realtime | timeshare | fixed> <num iterations> [-trace  <traceworthy latency in ns>] [-spin] [-affinity] [-verbose]\n");
}

/*
 * Given an array of uint64_t values, compute average, max, min, and standard deviation
 */
void 
compute_stats(uint64_t *values, uint64_t count, float *averagep, uint64_t *maxp, uint64_t *minp, float *stddevp)
{
	int i;
	uint64_t _sum = 0;
	uint64_t _max = 0;
	uint64_t _min = UINT64_MAX;
	float	 _avg = 0;
	float 	 _dev = 0;

	for (i = 0; i < count; i++) {
		_sum += values[i];
		_max = values[i] > _max ? values[i] : _max;
		_min = values[i] < _min ? values[i] : _min;
	}

	_avg = ((float)_sum) / ((float)count);
	
	_dev = 0;
	for (i = 0; i < count; i++) {
		_dev += powf((((float)values[i]) - _avg), 2);
	}
	
	_dev /= count;
	_dev = sqrtf(_dev);

	*averagep = _avg;
	*maxp = _max;
	*minp = _min;
	*stddevp = _dev;
}

int
main(int argc, char **argv)
{
	int		i;
	int 		res;
	pthread_t	*threads;
	uint64_t	*worst_latencies_ns;
	uint64_t	*worst_latencies_from_first_ns;
	uint64_t 	last_end;
	uint64_t	max, min;
	uint64_t	traceworthy_latency_ns = TRACEWORTHY_NANOS;
	float		avg, stddev;

	srand(time(NULL));

	if (argc < 5 || argc > 9) {
		print_usage();
		goto fail;
	}

	/* How many threads? */
	g_numthreads = atoi(argv[1]);

	/* What wakeup pattern? */
	g_waketype = parse_wakeup_pattern(argv[2]);

	/* Policy */
	g_policy = parse_thread_policy(argv[3]);

	/* Iterations */
	g_iterations = atoi(argv[4]);

	/* Optional args */
	for (i = 5; i < argc; i++) {
		if (strcmp(argv[i], "-spin") == 0) {
			g_do_spin = TRUE;
		} else if (strcmp(argv[i], "-verbose") == 0) {
			g_verbose = TRUE;
		} else if ((strcmp(argv[i], "-trace") == 0) && 
				(i < (argc - 1))) {
			traceworthy_latency_ns = strtoull(argv[++i], NULL, 10);
		} else if (strcmp(argv[i], "-affinity") == 0) {
			g_do_affinity = TRUE;
		} else {
			print_usage();
			goto fail;
		}
	}

	mach_timebase_info(&g_mti);

#if MIMIC_DIGI_LEAD_TIME
	g_spinlength_abs = nanos_to_abs(COMPUTATION_NANOS) / 2;
#endif /* MIMIC_DIGI_LEAD_TIME */

	/* Arrays for threads and their wakeup times */
	threads = (pthread_t*) malloc(sizeof(pthread_t) * g_numthreads);
	assert(threads, fail);

	g_thread_endtimes_abs = (uint64_t*) malloc(sizeof(uint64_t) * g_numthreads);
	assert(g_thread_endtimes_abs, fail);

	worst_latencies_ns = (uint64_t*) malloc(sizeof(uint64_t) * g_iterations);
	assert(worst_latencies_ns, fail);

	worst_latencies_from_first_ns = (uint64_t*) malloc(sizeof(uint64_t) * g_iterations);
	assert(worst_latencies_from_first_ns, fail);
	res = semaphore_create(mach_task_self(), &g_main_sem, SYNC_POLICY_FIFO, 0);
	assert(res == KERN_SUCCESS, fail);

	/* Either one big semaphore or one per thread */
	if (g_waketype == WAKE_CHAIN || g_waketype == WAKE_BROADCAST_PERTHREAD) {
		g_semarr = malloc(sizeof(semaphore_t) * g_numthreads);
		assert(g_semarr != NULL, fail);

		for (i = 0; i < g_numthreads; i++) {
			res = semaphore_create(mach_task_self(), &g_semarr[i], SYNC_POLICY_FIFO, 0);
			assert(res == KERN_SUCCESS, fail);
		}
		
		g_leadersem = g_semarr[0];
	} else {
		res = semaphore_create(mach_task_self(), &g_machsem, SYNC_POLICY_FIFO, 0);
		assert(res == KERN_SUCCESS, fail);
		res = semaphore_create(mach_task_self(), &g_leadersem, SYNC_POLICY_FIFO, 0);
		assert(res == KERN_SUCCESS, fail);
	}

	/* Create the threads */
	g_done_threads = 0;
	for (i = 0; i < g_numthreads; i++) {
		res = pthread_create(&threads[i], NULL, child_thread_func, (void*)(uintptr_t)i);
		assert(res == 0, fail);
	}

	/* Let everyone get settled */
	semaphore_wait(g_main_sem);
	sleep(1);

	/* Go! */
	for (i = 0; i < g_iterations; i++) {
		int j;
		uint64_t worst_abs = 0, best_abs = UINT64_MAX;

		g_done_threads = 0;
		OSMemoryBarrier();

		g_starttime_abs = mach_absolute_time();

		/* Fire them off */
		semaphore_signal(g_leadersem);

		/* Wait for worker threads to finish */
		semaphore_wait(g_main_sem);
		assert(res == KERN_SUCCESS, fail);

		/* 
		 * We report the worst latencies relative to start time
		 * and relative to the lead worker thread.
		 */
		for (j = 0; j < g_numthreads; j++) {
			uint64_t latency_abs;
		
			latency_abs = g_thread_endtimes_abs[j] - g_starttime_abs;
			worst_abs = worst_abs < latency_abs ? latency_abs : worst_abs;
		}
	
		worst_latencies_ns[i] = abs_to_nanos(worst_abs);

		worst_abs = 0;
		for (j = 1; j < g_numthreads; j++) {
			uint64_t latency_abs;
		
			latency_abs = g_thread_endtimes_abs[j] - g_thread_endtimes_abs[0];
			worst_abs = worst_abs < latency_abs ? latency_abs : worst_abs;
			best_abs = best_abs > latency_abs ? latency_abs : best_abs;
		}

		worst_latencies_from_first_ns[i] = abs_to_nanos(worst_abs);

		/*
		 * In the event of a bad run, cut a trace point.
		 */
		if (worst_latencies_from_first_ns[i] > traceworthy_latency_ns) {
			int _tmp;

			if (g_verbose) {
				printf("Worst on this round was %.2f us.\n", ((float)worst_latencies_from_first_ns[i]) / 1000.0);
			}

			_tmp = syscall(SYS_kdebug_trace, 0xEEEEEEEE, 0, 0, 0, 0);
		}

		/* Let worker threads get back to sleep... */
		usleep(g_numthreads * 10);
	}

	/* Rejoin threads */
	last_end = 0;
	for (i = 0; i < g_numthreads; i++) {
		res = pthread_join(threads[i], NULL);
		assert(res == 0, fail);
	}

	compute_stats(worst_latencies_ns, g_iterations, &avg, &max, &min, &stddev);
	printf("Results (from a stop):\n");
	printf("Max:\t\t%.2f us\n", ((float)max) / 1000.0);
	printf("Min:\t\t%.2f us\n", ((float)min) / 1000.0);
	printf("Avg:\t\t%.2f us\n", avg / 1000.0);
	printf("Stddev:\t\t%.2f us\n", stddev / 1000.0);

	putchar('\n');

	compute_stats(worst_latencies_from_first_ns, g_iterations, &avg, &max, &min, &stddev);
	printf("Results (relative to first thread):\n");
	printf("Max:\t\t%.2f us\n", ((float)max) / 1000.0);
	printf("Min:\t\t%.2f us\n", ((float)min) / 1000.0);
	printf("Avg:\t\t%.2f us\n", avg / 1000.0);
	printf("Stddev:\t\t%.2f us\n", stddev / 1000.0);

#if 0
	for (i = 0; i < g_iterations; i++) {
		printf("Iteration %d: %f us\n", i, worst_latencies_ns[i] / 1000.0);
	}
#endif 

	return 0;
fail:
	return 1;
}
