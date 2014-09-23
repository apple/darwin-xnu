#define TARGET_OS_EMBEDDED 1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#import <Foundation/Foundation.h>

#include <mach/message.h>
#include <libproc_internal.h>

#define	MAX_THREADS 1000

char *pname;

volatile int spin = 0;
pthread_mutex_t lock;
pthread_cond_t cv;
volatile int ready = 0;

int exit_after = 600;

int limit = 0; // Worker thread should apply per-thread limit to self?
int limit_period = 5000;

boolean_t reset_to_defaults = FALSE;

boolean_t stress_test = FALSE;

void usage(void) {
	printf("usage: cpu_hog [-l percentage] [-s msecs] [-n nthreads] [-p percentage] [-i secs] [-e secs] [-t num]\n");
	printf("\t-l: worker thread should apply per-thread limit to self (default: no limit)\n");
	printf("\t-s: worker thread's per-thread limit refill period (msecs) (default: 5000)\n");
	printf("\t-n: create nthreads and choose 1 to be worker. (default: 2)\n");
	printf("\t-p: worker thread should consume this percent CPU over -i seconds (default: 1)\n");
	printf("\t-i: interval for CPU consumption given with -p (DEFAULT: 1 second)\n");
	printf("\t-x: disable CPU usage monitor after this many seconds (0 == upon launch)\n");
	printf("\t-r: reset CPU usage monitor to default params after this many seconds (0 == upon launch)\n");
	printf("\t-c: change this process's CPU monitor percentage to this value upon launch\n");
	printf("\t-C: change this process's CPU monitor interval to this value upon launch (requires -c)\n");
	printf("\t-d: change this process's CPU monitor percentage to this value (with -D interval) -- after -w seconds\n");
	printf("\t-D: change this process's CPU monitor interval to this value (with -d percentage) -- after -w seconds\n");
	printf("\t-w: wait this number of seconds until changing CPU monitor percentage to -d percent\n");
	printf("\t-e: exit after this many seconds (default: 10 mins)\n");
    printf("\t-P: confirm that this process's CPU monitor parameters match this percentage (requires -I)\n");
    printf("\t-I: interval to match (with -P)\n");
    printf("\t-t: spin up additional CPU burner threads (each will consume 100%% CPU)\n");
}

void set_my_limit(int percent, int refill_period)
{
	int err;
	int cpupercent = percent | (refill_period << 8);
    
    	if ((err = sysctlbyname("kern.setthread_cpupercent", 0, 0,
    		&cpupercent, sizeof (int))) != 0) {
	printf("sysctl: error %d\n", err);
    }
}

static void print_cpumon_params(void) {
	int new_percentage = -1, new_interval = -1;
    
	proc_get_cpumon_params(getpid(), &new_percentage, &new_interval);
    
	printf("CPU monitor params: percentage = %d interval = %d\n", new_percentage, new_interval);
}

void *burner_thread(void *arg)
{
	int x = 1, y = 2;

	while (1) {
		x = rand();
		y = x * rand();
	}
}

void *spinner_thread(void *arg)
{
	int am_i_the_one = (arg != NULL) ? 1 : 0;
	int j = 0;
	int err;

	if (am_i_the_one) {
		if ((err = pthread_mutex_lock(&lock)) != 0) {
			printf("spinner: pthread_mutex_lock: %d", err);
			exit(1);
		}

		/*
		 * Apply per-thread limit to self?
		 */
		if (limit != 0) {
			set_my_limit(limit, limit_period);
		}

		/*
		 * Tell the main thread we're ready to get to work.
		 */
		ready = 1;
		pthread_mutex_unlock(&lock);
		pthread_cond_signal(&cv);

		while (1) {
			/*
			 * Go to sleep until the main thread wakes us.
			 */
			pthread_cond_wait(&cv, &lock);

			/*
			 * Do useless work until the main thread tells us to 
			 * stop.
			 */
			while (spin) {
				j += rand();
                if (reset_to_defaults) {
                    reset_to_defaults = FALSE;
                    printf("%s: resetting CPU usage monitor to default params.\n", pname);
                    proc_set_cpumon_defaults(getpid());
                    print_cpumon_params();
                }
                
                if (stress_test) {
//                    printf("%s: resetting CPU usage monitor to default params.\n", pname);
                    proc_set_cpumon_defaults(getpid());
//                    print_cpumon_params();
//                    printf("%s: disabling CPU usage monitor\n", pname);
                    proc_disable_cpumon(getpid());
//                    print_cpumon_params();
                }
                
            }
		}
	}

	while(1) {
		sleep(6000);
	}
}

void *disable_thread(void *arg)
{
    sleep((int)arg);
    
    printf("%s: disabling CPU usage monitor.\n", pname);
    proc_disable_cpumon(getpid());
    print_cpumon_params();
    
    return (NULL);
}

void *reset_thread(void *arg)
{
    sleep((int)arg);
    
    reset_to_defaults = TRUE;
    
    return (NULL);
}

void *exit_thread(void *arg) 
{
	sleep(exit_after);
	printf("...exiting.\n");
	exit(0);

	return (NULL);
}

int delayed_cpumon_percentage = -1;
int delayed_cpumon_interval = -1;
int delayed_cpumon_percentage_wait = -1;

void *change_cpumon_thread(void *arg)
{
	sleep(delayed_cpumon_percentage_wait);
	printf("changing CPU monitor params to %d %% over %d seconds\n", delayed_cpumon_percentage, delayed_cpumon_interval);
	proc_set_cpumon_params(getpid(), delayed_cpumon_percentage, delayed_cpumon_interval);

	print_cpumon_params();

	return (NULL);
}

int main(int argc, char *argv[])
{
	int ch;
	int i = 0;
	int nthreads = 1;
	int chosen_thr;
	pthread_t chosen_thr_id;
	int percent = 100;

	int interval = 2 * 1000000; // Default period for cycle is 2 seconds. Units are usecs.
	int on_time, off_time;

	int new_cpumon_percentage = -1;
	int new_cpumon_interval = -1;
	
	int disable_delay = -1;
    int reset_params_delay = -1;

    int confirm_cpumon_percentage = -1;
    int confirm_cpumon_interval = -1;

    int num_burner_threads = 0;
    
	pthread_t thr_id;
	
	printf("In CPU hogging test program...\n");

    pname = argv[0];
    
	while ((ch = getopt(argc, argv, "r:x:l:s:n:p:i:c:C:d:D:w:e:P:I:St:")) != -1) {
		switch (ch) {
		case 'l':
			limit = atoi(optarg);
			break;
		case 's':
			limit_period = atoi(optarg);
			break;
		case 'n':
			nthreads = atoi(optarg);
			break;
		case 'p':
			percent = atoi(optarg);
			break;
		case 'i':
			interval = atoi(optarg) * 1000000; // using usleep
			break;
        case 'x':
            disable_delay = atoi(optarg);
            break;
        case 'r':
            reset_params_delay = atoi(optarg);
            break;
		case 'c':
			new_cpumon_percentage = atoi(optarg);
			break;
		case 'C':
			new_cpumon_interval = atoi(optarg);
			break;
		case 'd':
			delayed_cpumon_percentage = atoi(optarg);
			break;
		case 'D':
			delayed_cpumon_interval = atoi(optarg);
			break;
		case 'w':
			delayed_cpumon_percentage_wait = atoi(optarg);
			break;
		case 'e':
			exit_after = atoi(optarg);
			break;
        case 'P':
            confirm_cpumon_percentage = atoi(optarg);
            break;
        case 'I':
            confirm_cpumon_interval = atoi(optarg);
            break;
        case 'S':
            stress_test = TRUE;
            break;
        case 't':
        	num_burner_threads = atoi(optarg);
        	break;
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

	if (((delayed_cpumon_percentage != -1) && (delayed_cpumon_percentage_wait == -1)) ||
	    ((delayed_cpumon_percentage == -1) && (delayed_cpumon_percentage_wait != -1))) {
		printf("must specify -d and -w together\n");
		usage();
		exit(1);
	}

	if ((nthreads <= 0) || (nthreads > MAX_THREADS)) {
		printf("%s: %d threads too many (max is %d)\n", argv[0],
			nthreads ,MAX_THREADS);
		exit(1);
	}

	if ((percent <= 0) || (percent > 100)) {
		printf("%s: invalid percentage %d\n", argv[0], percent);
		exit(1);
	}

	if (interval <= 0) {
		printf("%s: invalid interval %d\n", argv[0], interval);
		exit(1);
	}

	if ((new_cpumon_interval != -1) && (new_cpumon_percentage == -1)) {
		printf("%s: -C requires that you also specify -c\n", argv[0]);
		exit(1);
	}

	print_cpumon_params();

    if (confirm_cpumon_percentage != -1) {
        int my_percentage, my_interval;
        proc_get_cpumon_params(getpid(), &my_percentage, &my_interval);
        if ((my_percentage != confirm_cpumon_percentage) ||
            (my_interval != confirm_cpumon_interval)) {
            printf("parameters don't match values given with -P and -I\n");
            exit(1);
        }
        
        printf("parameters match values given with -P and -I.\n");
        exit(0);
    }
    
	on_time = (percent * interval) / 100;
	off_time = interval - on_time;

	/*
	 * Randomly choose a thread to be the naughty one.
	 */
	srand(MAX_THREADS); // Want this to be repeatable, for now
	chosen_thr = rand() % nthreads;

	if (pthread_mutex_init(&lock, NULL) != 0) {
		perror("pthread_mutex_init");
		exit(1);
	}

	if (pthread_cond_init(&cv, NULL) != 0) {
		perror("pthread_cond_init");
		exit(1);
	}

	if (pthread_mutex_lock(&lock) != 0) {
		perror("pthread_mutex_lock");
		exit(1);
	}

	if (pthread_create(&thr_id, NULL, exit_thread, NULL) != 0) {
     		perror("pthread_create");
     		exit(1);
	}

	if (delayed_cpumon_percentage != -1) {
		if (pthread_create(&thr_id, NULL, change_cpumon_thread, NULL) != 0) {
	     		perror("pthread_create");
	     		exit(1);
		}
	}

	printf("Creating %d threads. Thread %d will try to consume "
		"%d%% of a CPU over %d seconds.\n", nthreads, chosen_thr,
		percent, interval / 1000000);
	if (limit != 0) {
		printf("Worker thread %d will first self-apply a per-thread"
			" CPU limit of %d percent over %d seconds\n",
			chosen_thr, limit, limit_period);
	}
	
	for (i = 0; i < nthreads; i++) {
		if (pthread_create(&thr_id, NULL, spinner_thread,
	     	    (void *)((i == chosen_thr) ? (void *)1 : NULL)) != 0) {
	     		perror("pthread_create");
	     		exit(1);
     		}
     		if (i == chosen_thr) {
     			chosen_thr_id = thr_id;
     		}
	}

	/*
	 * Try to adjust the CPU usage monitor limit.
	 */
	if (new_cpumon_percentage != -1) {
		proc_set_cpumon_params(getpid(), new_cpumon_percentage, new_cpumon_interval);
		print_cpumon_params();		
	}

    if (disable_delay != -1) {
        if (pthread_create(&thr_id, NULL, disable_thread, (void *)disable_delay) != 0) {
            perror("pthread_create");
            exit(1);
        }
	}

    if (reset_params_delay != -1) {
        if (pthread_create(&thr_id, NULL, reset_thread, (void *)reset_params_delay) != 0) {
            perror("pthread_create");
            exit(1);
        }
	}

	if (num_burner_threads > 0) {
		for (i = 0; i < num_burner_threads; i++) {
	        if (pthread_create(&thr_id, NULL, burner_thread, NULL) != 0) {
	            perror("pthread_create");
	            exit(1);
	        }
		}
	}
    
	// Wait for the worker thread to come alive and get ready to work.
	while (ready == 0) {
		pthread_cond_wait(&cv, &lock);
	}

	if (pthread_mutex_unlock(&lock) != 0) {
		perror("spinner: pthread_mutex_unlock");
		exit(1);
	}

	/*
	 * Control the worker thread's CPU consumption.
	 */
	while (1) {
		/*
		 * Worker thread is waiting for us to awaken him, with the
		 * lock dropped.
		 */
		if (pthread_mutex_lock(&lock) != 0) {
			perror("pthread_mutex_lock");
			exit(1);
		}

		/*
		 * Go to sleep until we are ready to awaken the worker.
		 */
		usleep(off_time);

		/*
		 * Tell the worker to get to work.
		 */
		spin = 1;

		if (pthread_mutex_unlock(&lock) != 0) {
			perror("spinner: pthread_mutex_unlock");
			exit(1);
		}

		pthread_cond_signal(&cv);

		/*
		 * Go to sleep until we're ready to stop the worker.
		 */
		usleep(on_time);

		/*
		 * Stop the worker. He will drop the lock and wait
		 * for us to wake him again.
		 */
		spin = 0;
	}

	return (1);
}
