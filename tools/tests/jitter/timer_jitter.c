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
#include <sys/kdebug.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <semaphore.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <string.h>

#include <libkern/OSAtomic.h>

#include <mach/mach_time.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/semaphore.h>

typedef enum my_policy_type { MY_POLICY_REALTIME, MY_POLICY_TIMESHARE, MY_POLICY_FIXEDPRI } my_policy_type_t;

#define DEFAULT_MAX_SLEEP_NS	2000000000ll /* Two seconds */
#define CONSTRAINT_NANOS	(20000000ll)	/* 20 ms */
#define COMPUTATION_NANOS	(10000000ll)	/* 10 ms */

struct mach_timebase_info g_mti;

#define assert(truth, label) do { if(!(truth)) { printf("Thread %p: failure on line %d\n", pthread_self(), __LINE__); goto label; } } while (0)

struct second_thread_args {
	semaphore_t wakeup_semaphore;
	semaphore_t return_semaphore;
	uint64_t iterations;
	my_policy_type_t pol;
	double *wakeup_second_jitter_arr;
	uint64_t woke_on_same_cpu;
	uint64_t too_much;
	volatile uint64_t last_poke_time;
	volatile int cpuno;
};

extern int cpu_number(void);

void *
second_thread(void *args);

void
print_usage()
{
	printf("Usage: jitter [-w] [-s <random seed>] [-n <min sleep, ns>] [-m <max sleep, ns>] <realtime | timeshare | fixed> <num iterations> <traceworthy jitter, ns>\n");
}

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

int
thread_setup(my_policy_type_t pol)
{
	int res;

	switch (pol) {
		case MY_POLICY_TIMESHARE:
		{
			return 0;
		}
		case MY_POLICY_REALTIME: 
		{
			thread_time_constraint_policy_data_t pol;

			/* Hard-coded realtime parameters (similar to what Digi uses) */
			pol.period = 100000;
			pol.constraint =  CONSTRAINT_NANOS * g_mti.denom / g_mti.numer;
			pol.computation = COMPUTATION_NANOS * g_mti.denom / g_mti.numer;
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

	return 0;
fail:
	return 1;
}

uint64_t 
get_random_sleep_length_abs_ns(uint64_t min_sleep_ns, uint64_t max_sleep_ns)
{
	uint64_t tmp;

	tmp = (uint32_t)random();
	tmp <<= 32;
	tmp |= (uint32_t)random();

	/* Now use the random number to sleep amount within the window */
	tmp %= (max_sleep_ns - min_sleep_ns);

	return min_sleep_ns + tmp;
}

void 
compute_stats(double *values, uint64_t count, double *average_magnitudep, double *maxp, double *minp, double *stddevp)
{
	uint64_t i;
	double _sum = 0;
	double _max = 0;
	double _min = (double)INT64_MAX;
	double _avg = 0;
	double _dev = 0;

	for (i = 0; i < count; i++) {
		_sum += fabs(values[i]);
		_max = values[i] > _max ? values[i] : _max;
		_min = values[i] < _min ? values[i] : _min;
	}

	_avg = _sum / (double)count;
	
	_dev = 0;
	for (i = 0; i < count; i++) {
		_dev += pow((values[i] - _avg), 2);
	}
	
	_dev /= count;
	_dev = sqrt(_dev);

	*average_magnitudep = _avg;
	*maxp = _max;
	*minp = _min;
	*stddevp = _dev;
}

void
print_stats_us(const char *label, double avg, double max, double min, double stddev)
{
	printf("Max %s: %.1lfus\n", label, max / 1000.0 * (((double)g_mti.numer) / ((double)g_mti.denom)));
	printf("Min %s: %.1lfus\n", label, min / 1000.0 * (((double)g_mti.numer) / ((double)g_mti.denom)));
	printf("Avg magnitude of %s: %.1lfus\n", label, avg / 1000.0 * (((double)g_mti.numer) / ((double)g_mti.denom)));
	printf("Stddev: %.1lfus\n", stddev / 1000.0 * (((double)g_mti.numer) / ((double)g_mti.denom)));
	putchar('\n');
}

void
print_stats_fract(const char *label, double avg, double max, double min, double stddev)
{
	printf("Max %s jitter: %.1lf%%\n", label, max * 100);
	printf("Min %s jitter: %.1lf%%\n", label, min * 100);
	printf("Avg %s jitter: %.1lf%%\n", label, avg * 100);
	printf("Stddev: %.1lf%%\n", stddev * 100);
	putchar('\n');	
}

int
main(int argc, char **argv)
{
	uint64_t iterations, i;
	double *jitter_arr, *fraction_arr;
	double *wakeup_second_jitter_arr;
	uint64_t target_time;
	uint64_t sleep_length_abs;
	uint64_t min_sleep_ns = 0;
	uint64_t max_sleep_ns = DEFAULT_MAX_SLEEP_NS;
	uint64_t wake_time;
	unsigned random_seed;
	boolean_t need_seed = TRUE;
	char ch;
	int res;
	kern_return_t kret;
	my_policy_type_t pol;
	boolean_t wakeup_second_thread = FALSE;
	semaphore_t wakeup_semaphore, return_semaphore;

	double avg, stddev, max, min;
	double avg_fract, stddev_fract, max_fract, min_fract;
	uint64_t too_much;

	struct second_thread_args secargs;
	pthread_t secthread;

	mach_timebase_info(&g_mti);

	/* Seed random */
	opterr = 0;
	while ((ch = getopt(argc, argv, "m:n:hs:w")) != -1 && ch != '?') {
		switch (ch) {
			case 's':
				/* Specified seed for random)() */
				random_seed = (unsigned)atoi(optarg);
				srandom(random_seed);
				need_seed = FALSE;
				break;
			case 'm':
				/* How long per timer? */
				max_sleep_ns = strtoull(optarg, NULL, 10);	
				break;
			case 'n':
				/* How long per timer? */
				min_sleep_ns = strtoull(optarg, NULL, 10);	
				break;
			case 'w':
				/* After each timed wait, wakeup another thread */
				wakeup_second_thread = TRUE;
				break;
			case 'h':
				print_usage();
				exit(0);
				break;
			default:
				fprintf(stderr, "Got unexpected result from getopt().\n");
				exit(1);
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 3) {
		print_usage();
		exit(1);
	}

	if (min_sleep_ns >= max_sleep_ns) {
		print_usage();
		exit(1);
	}

	if (need_seed) {
		srandom(time(NULL));
	}

	/* What scheduling policy? */
	pol = parse_thread_policy(argv[0]);

	/* How many timers? */
	iterations = strtoull(argv[1], NULL, 10);

	/* How much jitter is so extreme that we should cut a trace point */
	too_much = strtoull(argv[2], NULL, 10);
	
	/* Array for data */
	jitter_arr = (double*)malloc(sizeof(*jitter_arr) * iterations);
	if (jitter_arr == NULL) {
		printf("Couldn't allocate array to store results.\n");
		exit(1);
	}

	fraction_arr = (double*)malloc(sizeof(*fraction_arr) * iterations);
	if (fraction_arr == NULL) {
		printf("Couldn't allocate array to store results.\n");
		exit(1);
	}

	if (wakeup_second_thread) {
		/* Array for data */
		wakeup_second_jitter_arr = (double*)malloc(sizeof(*jitter_arr) * iterations);
		if (wakeup_second_jitter_arr == NULL) {
			printf("Couldn't allocate array to store results.\n");
			exit(1);
		}

		kret = semaphore_create(mach_task_self(), &wakeup_semaphore, SYNC_POLICY_FIFO, 0);
		if (kret != KERN_SUCCESS) {
			printf("Couldn't allocate semaphore %d\n", kret);
			exit(1);
		}

		kret = semaphore_create(mach_task_self(), &return_semaphore, SYNC_POLICY_FIFO, 0);
		if (kret != KERN_SUCCESS) {
			printf("Couldn't allocate semaphore %d\n", kret);
			exit(1);
		}


		secargs.wakeup_semaphore = wakeup_semaphore;
		secargs.return_semaphore = return_semaphore;
		secargs.iterations = iterations;
		secargs.pol = pol;
		secargs.wakeup_second_jitter_arr = wakeup_second_jitter_arr;
		secargs.woke_on_same_cpu = 0;
		secargs.too_much = too_much;
		secargs.last_poke_time = 0ULL;
		secargs.cpuno = 0;

		res = pthread_create(&secthread, NULL, second_thread, &secargs);
		if (res) {
			err(1, "pthread_create");
		}

		sleep(1); /* Time for other thread to start up */
	}

	/* Set scheduling policy */
	res = thread_setup(pol);
	if (res != 0) {
		printf("Couldn't set thread policy.\n");
		exit(1);
	}

	/* 
	 * Repeatedly pick a random timer length and 
	 * try to sleep exactly that long 
	 */
	for (i = 0; i < iterations; i++) {
		sleep_length_abs = (uint64_t) (get_random_sleep_length_abs_ns(min_sleep_ns, max_sleep_ns) * (((double)g_mti.denom) / ((double)g_mti.numer)));
		target_time = mach_absolute_time() + sleep_length_abs;
		
		/* Sleep */
		kret = mach_wait_until(target_time);
		wake_time = mach_absolute_time();
	
		jitter_arr[i] = (double)(wake_time - target_time);
		fraction_arr[i] = jitter_arr[i] / ((double)sleep_length_abs);
		
		/* Too much: cut a tracepoint for a debugger */
		if (jitter_arr[i] >= too_much) {
			kdebug_trace(0xeeeee0 | DBG_FUNC_NONE, 0, 0, 0, 0);
		}

		if (wakeup_second_thread) {
			secargs.last_poke_time = mach_absolute_time();
			secargs.cpuno = cpu_number();
			OSMemoryBarrier();
			kret = semaphore_signal(wakeup_semaphore);
			if (kret != KERN_SUCCESS) {
				errx(1, "semaphore_signal");
			}

			kret = semaphore_wait(return_semaphore);
			if (kret != KERN_SUCCESS) {
				errx(1, "semaphore_wait");
			}

		}
	}

	/*
	 * Compute statistics and output results. 
	 */
	compute_stats(jitter_arr, iterations, &avg, &max, &min, &stddev);
	compute_stats(fraction_arr, iterations, &avg_fract, &max_fract, &min_fract, &stddev_fract);

	putchar('\n');
	print_stats_us("jitter", avg, max, min, stddev);
	print_stats_fract("%", avg_fract, max_fract, min_fract, stddev_fract);

	if (wakeup_second_thread) {

		res = pthread_join(secthread, NULL);
		if (res) {
			err(1, "pthread_join");
		}

		compute_stats(wakeup_second_jitter_arr, iterations, &avg, &max, &min, &stddev);
		
		putchar('\n');
		print_stats_us("second jitter", avg, max, min, stddev);

		putchar('\n');
		printf("%llu/%llu (%.1f%%) wakeups on same CPU\n", secargs.woke_on_same_cpu, iterations,
			   100.0*((double)secargs.woke_on_same_cpu)/iterations);
	}

	return 0;
}

void *
second_thread(void *args)
{
	struct second_thread_args *secargs = (struct second_thread_args *)args;
	int res;
	uint64_t i;
	kern_return_t kret;
	uint64_t wake_time;
	int cpuno;

	/* Set scheduling policy */
	res = thread_setup(secargs->pol);
	if (res != 0) {
		printf("Couldn't set thread policy.\n");
		exit(1);
	}

	/* 
	 * Repeatedly pick a random timer length and 
	 * try to sleep exactly that long 
	 */
	for (i = 0; i < secargs->iterations; i++) {

		/* Wake up when poked by main thread */
		kret = semaphore_wait(secargs->wakeup_semaphore);
		if (kret != KERN_SUCCESS) {
			errx(1, "semaphore_wait %d", kret);
		}

		wake_time = mach_absolute_time();
		cpuno = cpu_number();
		if (wake_time < secargs->last_poke_time) {
			/* Woke in past, unsynchronized mach_absolute_time()? */
			
			errx(1, "woke in past %llu (%d) < %llu (%d)", wake_time, cpuno, secargs->last_poke_time, secargs->cpuno);
		}

		if (cpuno == secargs->cpuno) {
			secargs->woke_on_same_cpu++;
		}

		secargs->wakeup_second_jitter_arr[i] = (double)(wake_time - secargs->last_poke_time);
		
		/* Too much: cut a tracepoint for a debugger */
		if (secargs->wakeup_second_jitter_arr[i] >= secargs->too_much) {
			kdebug_trace(0xeeeee4 | DBG_FUNC_NONE, 0, 0, 0, 0);
		}

		kret = semaphore_signal(secargs->return_semaphore);
		if (kret != KERN_SUCCESS) {
			errx(1, "semaphore_signal %d", kret);
		}

	}

	return NULL;
}
