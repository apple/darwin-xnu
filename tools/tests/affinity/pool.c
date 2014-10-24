#include <AvailabilityMacros.h>
#include <mach/thread_policy.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

/*
 * Pool is another multithreaded test/benchmarking program to evaluate
 * affinity set placement in Leopard.
 *
 * The basic picture is:
 *
 *                  -> producer --                 -> consumer --
 *       free     /                \    work     /                \
 *    -> queue --      ...          --> queue --                   --
 *   |            \                /             \                /  |
 *   |              -> producer --                 -> consumer --    |
 *    ---------------------------------------------------------------
 *
 *       <---------- "stage" ---------> <---------- "stage" --------->
 *
 * There are a series of work stages. Each stage has an input and an output
 * queue and multiple threads. The first stage is the producer and subsequent
 * stages are consumers. By defuaut there are 2 stages. There are N producer
 * and M consumer threads. The are B buffers per producer threads circulating
 * through the system.
 *
 * When affinity is enabled, each producer thread is tagged with an affinity tag
 * 1 .. N - so each runs on a different L2 cache. When a buffer is queued to
 * the work queue it is tagged with this affinity. When a consumer dequeues a
 * work item, it sets its affinity to this tag. Hence consumer threads migrate
 * to the same affinity set where the data was produced.
 *
 * Buffer management uses pthread mutex/condition variables. A thread blocks
 * when no buffer is available on a queue and it is signaled when a buffer
 * is placed on an empty queue. Queues are tailq'a a la <sys/queue.h>.
 * The queue management is centralized in a single routine: what queues to
 * use as input and output and what function to call for processing is
 * data-driven.
 */
  
pthread_mutex_t funnel;
pthread_cond_t	barrier;

uint64_t	timer;
int		threads;
int		threads_ready = 0;

int		iterations = 10000;
boolean_t	affinity = FALSE;
boolean_t	halting = FALSE;
int		verbosity = 1;

typedef struct work {
	TAILQ_ENTRY(work)	link;
	int			*data;
	int			isize;
	int			tag;
	int			number;
} work_t;

/*
 * A work queue, complete with pthread objects for its management
 */
typedef struct work_queue {
	pthread_mutex_t		mtx;
	pthread_cond_t		cnd;
	TAILQ_HEAD(, work)	queue;
	unsigned int		waiters;
} work_queue_t;

/* Worker functions take a integer array and size */
typedef void (worker_fn_t)(int *, int); 

/* This struct controls the function of a stage */
#define WORKERS_MAX 10
typedef struct {
	int			stagenum;
	char			*name;
	worker_fn_t		*fn;
	work_queue_t		*input;		
	work_queue_t		*output;		
	work_queue_t		bufq;
	int			work_todo;
} stage_info_t;

/* This defines a worker thread */
typedef struct worker_info {
	int			setnum;
	stage_info_t		*stage;
	pthread_t		thread;
} worker_info_t;

#define DBG(x...) do {				\
	if (verbosity > 1) {			\
		pthread_mutex_lock(&funnel);	\
		printf(x);			\
		pthread_mutex_unlock(&funnel);	\
	}					\
} while (0)

#define mutter(x...) do {			\
	if (verbosity > 0) {			\
		printf(x);			\
	}					\
} while (0)

#define s_if_plural(x)	(((x) > 1) ? "s" : "")

static void
usage()
{
	fprintf(stderr,
		"usage: pool [-a]    Turn affinity on (off)\n"
		"            [-b B]  Number of buffers per producer (2)\n"
		"            [-i I]  Number of buffers to produce (10000)\n"
		"            [-s S]  Number of stages (2)\n"
		"            [-p P]  Number of pages per buffer (256=1MB)]\n"
		"            [-w]    Consumer writes data\n"
		"            [-v V]  Verbosity level 0..2 (1)\n"
		"            [N [M]] Number of producer and consumers (2)\n"
	);
	exit(1);
}

/* Trivial producer: write to each byte */
void
writer_fn(int *data, int isize)
{
	int 	i;

	for (i = 0; i < isize; i++) {
		data[i] = i;
	}
}

/* Trivial consumer: read each byte */
void
reader_fn(int *data, int isize)
{
	int 	i;
	int	datum;

	for (i = 0; i < isize; i++) {
		datum = data[i];
	}
}

/* Consumer reading and writing the buffer */
void
reader_writer_fn(int *data, int isize)
{
	int 	i;

	for (i = 0; i < isize; i++) {
		data[i] += 1;
	}
}

void
affinity_set(int tag)
{
	kern_return_t			ret;
	thread_affinity_policy_data_t	policy;
	if (affinity) {
		policy.affinity_tag = tag;
		ret = thread_policy_set(
				mach_thread_self(), THREAD_AFFINITY_POLICY,
				(thread_policy_t) &policy,
				THREAD_AFFINITY_POLICY_COUNT);
		if (ret != KERN_SUCCESS)
			printf("thread_policy_set(THREAD_AFFINITY_POLICY) returned %d\n", ret);
	}
}

/*
 * This is the central function for every thread.
 * For each invocation, its role is ets by (a pointer to) a stage_info_t.
 */
void *
manager_fn(void *arg)
{
	worker_info_t	*wp = (worker_info_t *) arg;
	stage_info_t	*sp = wp->stage;
	boolean_t	is_producer = (sp->stagenum == 0);
	long		iteration = 0;
	int		current_tag = 0;

	kern_return_t			ret;
	thread_extended_policy_data_t	epolicy;
	epolicy.timeshare = FALSE;
	ret = thread_policy_set(
			mach_thread_self(), THREAD_EXTENDED_POLICY,
			(thread_policy_t) &epolicy,
			THREAD_EXTENDED_POLICY_COUNT);
	if (ret != KERN_SUCCESS)
		printf("thread_policy_set(THREAD_EXTENDED_POLICY) returned %d\n", ret);
	
	/*
	 * If we're using affinity sets and we're a producer
	 * set our tag to by our thread set number.
	 */
	if (affinity && is_producer) {
		affinity_set(wp->setnum);
		current_tag = wp->setnum;
	}

	DBG("Starting %s %d, stage: %d\n", sp->name, wp->setnum, sp->stagenum);

	/*
	 * Start barrier.
	 * The tets thread to get here releases everyone and starts the timer.
	 */
	pthread_mutex_lock(&funnel);
	threads_ready++;
	if (threads_ready == threads) {
		pthread_mutex_unlock(&funnel);
		if (halting) {
			printf("  all threads ready for process %d, "
				"hit any key to start", getpid());
			fflush(stdout);
			(void) getchar();
		}
		pthread_cond_broadcast(&barrier);
		timer = mach_absolute_time();
	} else {
		pthread_cond_wait(&barrier, &funnel);
		pthread_mutex_unlock(&funnel);
	}

	do {
		work_t		*workp;

		/*
		 * Get a buffer from the input queue.
		 * Block if none.
		 * Quit if all work done.
		 */
		pthread_mutex_lock(&sp->input->mtx);
		while (1) {
			if (sp->work_todo == 0) {
				pthread_mutex_unlock(&sp->input->mtx);
				goto out;
			}
			workp = TAILQ_FIRST(&(sp->input->queue));
			if (workp != NULL)
				break;
			DBG("    %s[%d,%d] todo %d waiting for buffer\n",
				sp->name, wp->setnum, sp->stagenum, sp->work_todo);
			sp->input->waiters++;
			pthread_cond_wait(&sp->input->cnd, &sp->input->mtx);
			sp->input->waiters--;
		}
		TAILQ_REMOVE(&(sp->input->queue), workp, link);
		iteration = sp->work_todo--;
		pthread_mutex_unlock(&sp->input->mtx);

		if (is_producer) {
			workp->number = iteration;
			workp->tag = wp->setnum;
		} else {
			if (affinity && current_tag != workp->tag) {
				affinity_set(workp->tag);
				current_tag = workp->tag;
			}
		}

		DBG("  %s[%d,%d] todo %d work %p data %p\n",
			sp->name, wp->setnum, sp->stagenum, iteration, workp, workp->data);

		/* Do our stuff with the buffer */
		(void) sp->fn(workp->data, workp->isize);

		/*
		 * Place the buffer on the input queue of the next stage.
		 * Signal waiters if required.
		 */
		pthread_mutex_lock(&sp->output->mtx);
		TAILQ_INSERT_TAIL(&(sp->output->queue), workp, link);
		if (sp->output->waiters) {
			DBG("    %s[%d,%d] todo %d signaling work\n",
				sp->name, wp->setnum, sp->stagenum, iteration);
			pthread_cond_signal(&sp->output->cnd);
		}
		pthread_mutex_unlock(&sp->output->mtx);

	} while (1);

out:
	pthread_cond_broadcast(&sp->output->cnd);

	DBG("Ending %s[%d,%d]\n", sp->name, wp->setnum, sp->stagenum);

	return (void *) iteration;
}

void (*producer_fnp)(int *data, int isize) = &writer_fn;
void (*consumer_fnp)(int *data, int isize) = &reader_fn;

int
main(int argc, char *argv[])
{
	int			i;
	int			j;
	int			k;
	int			pages = 256; /* 1MB */
	int			buffers = 2;
	int			producers = 2;
	int			consumers = 2;
	int			stages = 2;
	int			*status;
	stage_info_t		*stage_info;
	stage_info_t		*sp;
	worker_info_t		*worker_info;
	worker_info_t		*wp;
	kern_return_t		ret;
	int			c;

	/* Do switch parsing: */
	while ((c = getopt (argc, argv, "ab:i:p:s:twv:")) != -1) {
		switch (c) {
		case 'a':
			affinity = !affinity;
			break;
		case 'b':
			buffers = atoi(optarg);
			break;
		case 'i':
			iterations = atoi(optarg);
			break;
		case 'p':
			pages = atoi(optarg);
			break;
		case 's':
			stages = atoi(optarg);
			if (stages >= WORKERS_MAX)
				usage();
			break;
		case 't':
			halting = TRUE;
			break;
		case 'w':
			consumer_fnp = &reader_writer_fn;
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
	if (argc > 0)
		producers = atoi(*argv);
	argc--; argv++;
	if (argc > 0)
		consumers = atoi(*argv);
	
	pthread_mutex_init(&funnel, NULL);
	pthread_cond_init(&barrier, NULL);

	/*
 	 * Fire up the worker threads.
	 */
	threads = consumers * (stages - 1) + producers;
	mutter("Launching %d producer%s with %d stage%s of %d consumer%s\n"
		"  with %saffinity, consumer reads%s data\n",
		producers, s_if_plural(producers),
		stages - 1, s_if_plural(stages - 1),
		consumers, s_if_plural(consumers),
		affinity? "": "no ",
		(consumer_fnp == &reader_writer_fn)? " and writes" : "");
	if (pages < 256)
		mutter("  %dkB bytes per buffer, ", pages * 4);
	else
		mutter("  %dMB bytes per buffer, ", pages / 256);
	mutter("%d buffer%s per producer ",
		buffers, s_if_plural(buffers));
	if (buffers * pages < 256)
		mutter("(total %dkB)\n", buffers * pages * 4);
	else
		mutter("(total %dMB)\n", buffers * pages / 256);
	mutter("  processing %d buffer%s...\n",
		iterations, s_if_plural(iterations));

	stage_info = (stage_info_t *) malloc(stages * sizeof(stage_info_t));
	worker_info = (worker_info_t *) malloc(threads * sizeof(worker_info_t));

	/* Set up the queue for the workers of this thread set: */
	for (i = 0; i < stages; i++) {
		sp = &stage_info[i];
		sp->stagenum = i;
		pthread_mutex_init(&sp->bufq.mtx, NULL);
		pthread_cond_init(&sp->bufq.cnd, NULL);
		TAILQ_INIT(&sp->bufq.queue);
		sp->bufq.waiters = 0;
		if (i == 0) {
			sp->fn = producer_fnp;
			sp->name = "producer";
		} else {
			sp->fn = consumer_fnp;
			sp->name = "consumer";
		}
		sp->input = &sp->bufq;
		sp->output = &stage_info[(i + 1) % stages].bufq;
		stage_info[i].work_todo = iterations;
	}
 
	/* Create the producers */
	for (i = 0; i < producers; i++) {
		work_t	*work_array;
		int	*data;
		int	isize;

		isize = pages * 4096 / sizeof(int);
		data = (int *) malloc(buffers * pages * 4096);

		/* Set up the empty work buffers */
		work_array = (work_t *)  malloc(buffers * sizeof(work_t));
		for (j = 0; j < buffers; j++) {
			work_array[j].data = data + (isize * j);	
			work_array[j].isize = isize;
			work_array[j].tag = 0;
			TAILQ_INSERT_TAIL(&stage_info[0].bufq.queue, &work_array[j], link);
			DBG("  empty work item %p for data %p\n",
				&work_array[j], work_array[j].data);
		}
		wp = &worker_info[i];
		wp->setnum = i + 1;
		wp->stage = &stage_info[0];
		if (ret = pthread_create(&wp->thread,
					 NULL,
					 &manager_fn,
					 (void *) wp))
			err(1, "pthread_create %d,%d", 0, i);
	}

	/* Create consumers */
	for (i = 1; i < stages; i++) {
		for (j = 0; j < consumers; j++) {
			wp = &worker_info[producers + (consumers*(i-1)) + j];
			wp->setnum = j + 1;
			wp->stage = &stage_info[i];
			if (ret = pthread_create(&wp->thread,
						NULL,
						&manager_fn,
						(void *) wp))
				err(1, "pthread_create %d,%d", i, j);
		}
	}

	/*
	 * We sit back anf wait for the slaves to finish.
	 */
	for (k = 0; k < threads; k++) {
		int	i;
		int	j;

		wp = &worker_info[k];
		if (k < producers) {
			i = 0;
			j = k;
		} else {
			i = (k - producers) / consumers;
			j = (k - producers) % consumers;
		}
		if(ret = pthread_join(wp->thread, (void **)&status))
		    err(1, "pthread_join %d,%d", i, j);
		DBG("Thread %d,%d status %d\n", i, j, status);
	}

	/*
	 * See how long the work took.
	 */
	timer = mach_absolute_time() - timer;
	timer = timer / 1000000ULL;
	printf("%d.%03d seconds elapsed.\n",
		(int) (timer/1000ULL), (int) (timer % 1000ULL));

	return 0;
}
